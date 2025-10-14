#!/usr/bin/env python3
import re
import ast
import os
import sys
import json
import csv
import argparse
import shutil
from collections import defaultdict
from dotenv import load_dotenv
import requests
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def call_ollama_api(api_key, system_msg, prompt, max_tokens=1000, temperature=0.0):
    """Call the Ollama API with the given prompt (replaces OpenAI)."""

    api_url = "http://172.24.16.155:11434/api/generate"
    headers = {"Content-Type": "application/json"}
    data = {
        "model": "llama3.2:latest",
        "prompt": f"{system_msg}\n\n{prompt}",
        "stream": False
    }

    try:
        response = requests.post(api_url, headers=headers, json=data)
        response.raise_for_status()
        response_data = response.json()

        if "response" in response_data:
            return response_data["response"]

        logger.error(f"Unexpected API response format: {response_data}")
        return None

    except requests.exceptions.RequestException as e:
        logger.error(f"Ollama API request failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response content: {e.response.text}")
        return None
    except KeyError as e:
        logger.error(f"Unexpected API response format: {e}")
        return None

def call_openai_api(api_key, system_msg, prompt, max_tokens=1000, temperature=0.1):
    """Call the OpenAI API with the given prompt."""
    
    if not api_key:
        raise ValueError("OpenAI API key not provided. Set OPENAI_API_KEY environment variable or pass --api-key.")

    api_url = f"https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}"
    }
    data = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": max_tokens,
        "temperature": temperature
    }

    try:
        response = requests.post(api_url, headers=headers, json=data)
        response.raise_for_status()
        response_data = response.json()

        if "choices" in response_data and len(response_data["choices"]) > 0:
            return response_data["choices"][0]["message"]["content"]

        logger.error(f"Unexpected API response format: {response_data}")
        return None

    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response content: {e.response.text}")
        return None
    except KeyError as e:
        logger.error(f"Unexpected API response format: {e}")
        return None

def load_cwe_data(config_path="data/cwe_top25_2024.json"):
    """Load CWE Top 25 2024 data."""
    with open(config_path, 'r', encoding='utf-8') as f:
        cwe_data = json.load(f)
    return cwe_data

def load_sample_filename(language_folder, samples_dir="data/source_files"):
    """Load metadata about extracted samples."""
    directory = os.path.join(samples_dir, language_folder)
    lang_map_extension = {
        "Python": "py",
        "python": "py",
        "Java": "java",
        "java": "java",
        "JavaScript": "js",
        "javascript": "js",
        "JS": "js",
        "C++": "cpp",
        "CPP": "cpp",
        "cpp": "cpp",
        "GO": "go",
        "go": "go",
        "C": "c",
        "c": "c",
    }
    lang = lang_map_extension.get(language_folder)
    if not os.path.isdir(directory):
        logger.error(f"Samples directory does not exist: {directory}")
        return []
    filenames = [f for f in os.listdir(directory) if f.endswith(f'.{lang}')]
    samples = [{'filename': f} for f in filenames]
    return samples

def read_code_from_file(file_path):
    """Read code from a file."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading {file_path}: {e}")
        return None

# def generate_vulnerability_implementations():
#     """Generate implementation suggestions for each CWE."""
#     implementations = {
#         "CWE-79": "Add user input directly to HTML output without escaping (e.g., in a web template or HTML generation)",
#         "CWE-89": "Concatenate user input directly into SQL queries without parameterization",
#         "CWE-352": "Remove CSRF token validation from form processing endpoints",
#         "CWE-22": "Allow user input to construct file paths without validation (e.g., '../../../etc/passwd')",
#         "CWE-78": "Pass user input directly to os.system() or subprocess without sanitization",
#         "CWE-862": "Remove authentication checks from sensitive functions or endpoints",
#         "CWE-434": "Allow file uploads without validating file type or extension",
#         "CWE-287": "Use weak authentication (e.g., hardcoded passwords, no password verification)",
#         "CWE-190": "Perform arithmetic operations without checking for integer overflow",
#         "CWE-502": "Use pickle.loads() or eval() on untrusted user data",
#         "CWE-77": "Execute user input as shell commands without validation",
#         "CWE-798": "Embed credentials directly in source code (API keys, passwords)",
#         "CWE-918": "Make HTTP requests to user-provided URLs without validation",
#         "CWE-306": "Access critical functions without requiring authentication",
#         "CWE-362": "Modify shared resources without proper locking mechanisms",
#         "CWE-269": "Grant excessive privileges or fail to drop privileges appropriately",
#         "CWE-94": "Execute dynamically generated code from user input (eval, exec)",
#         "CWE-863": "Implement insufficient permission checks for resource access",
#         "CWE-276": "Set overly permissive file permissions (777, etc.)",
#         "CWE-20": "Accept and process input without validation or sanitization"
#     }
#     return implementations

def extract_cwe_ids_from_response(response: str):
    """
    Robustly extract CWE IDs from model response:
    - Try JSON parse or ast.literal_eval first
    - Fallback to regex
    - Normalize to uppercase, preserve order, remove duplicates
    """
    if not response or not isinstance(response, str):
        return []

    text = response.strip()

    # Remove simple code-fence wrappers if present
    fence_pattern = r"^```(?:json|python)?\s*([\s\S]*?)\s*```$"
    m = re.match(fence_pattern, text, re.MULTILINE)
    if m:
        text = m.group(1).strip()

    # Try JSON
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list) and all(isinstance(x, str) for x in parsed):
            seen = set()
            out = []
            for s in parsed:
                s2 = s.strip().upper()
                if s2 not in seen:
                    seen.add(s2)
                    out.append(s2)
            return out
    except Exception:
        pass

    # Try Python literal eval
    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, list) and all(isinstance(x, str) for x in parsed):
            seen = set()
            out = []
            for s in parsed:
                s2 = s.strip().upper()
                if s2 not in seen:
                    seen.add(s2)
                    out.append(s2)
            return out
    except Exception:
        pass

    # Regex fallback
    cwe_pattern = r"(CWE-\d+)"
    matches = re.findall(cwe_pattern, text, flags=re.IGNORECASE)
    normalized = []
    seen = set()
    for m in matches:
        m_up = m.upper()
        if m_up not in seen:
            seen.add(m_up)
            normalized.append(m_up)
    return normalized

def distribute_vulnerabilities(api_key, samples, language, cwes, samples_dir="data/source_files", vuln_counts=[1, 3, 5, 9], move_processed=True, processed_folder_name=None):
    """Distribute vulnerabilities across samples for different datasets.

    For each sample we request TOP 9 CWEs in a single API call.
    """
    mappings = {v: {'mapping': [], 'cwe_usage': defaultdict(int)} for v in vuln_counts}
    # implementations = generate_vulnerability_implementations()
    cwe_lookup = {cwe['cwe_id']: cwe for cwe in cwes}

    samples_base = os.path.join(samples_dir, language)
    processed_dir = processed_folder_name or f"Processed_{language}"
    processed_full = os.path.join(samples_dir, processed_dir)
    if move_processed:
        os.makedirs(processed_full, exist_ok=True)

    total = len(samples)
    processed_count = 0

    for sample in samples:
        sample_filename = sample['filename']
        file_path = os.path.join(samples_base, sample_filename)
        code = read_code_from_file(file_path)
        if code is None:
            print(f"Skipping {sample_filename} due to read error", file=sys.stderr)
            continue

        # Single call: ask for top 9 CWEs from the provided list
        top_k = 9
        system_msg = (
            "You are a cybersecurity expert specializing in code vulnerabilities. NEVER include any explanation in your response. "
            "Return ONLY a List exactly matching the schema: "
            '["CWE-ID1", "CWE-ID2", ...] '
            f"Choose from this list only: {cwes}. "
            f"Return exactly {top_k} items and do not include duplicates. "
            "If you are unsure, return an empty list: []. "
            "Do not include markdown, backticks, or extraneous text."
        )

        prompt = f"""I have the following {language} code:

        ```{language.lower()}
        {code}
        ```
        Please suggest the top {top_k} vulnerabilities that are feasible to be induced in the given code from the following list of CWEs

        {cwes}
        Return ONLY the cwe_ids as a list.
        For example, if you suggest CWE-79 and CWE-89, return: ["CWE-79", "CWE-89"] and nothing else.
        """

        response = call_openai_api(api_key, system_msg, prompt, max_tokens=1000, temperature=0.1)
        if not response:
            logger.error(f"No response from API when requesting top {top_k} for {sample_filename}")
            continue

        suggested_top = extract_cwe_ids_from_response(response)

        if not suggested_top:
            logger.error(f"Failed to extract CWE IDs from API response for {sample_filename}")
            continue

        if len(suggested_top) > top_k:
            logger.warning(f"AI returned {len(suggested_top)} CWE(s) for {sample_filename}; trimming to {top_k}.")
            suggested_top = suggested_top[:top_k]

        for vuln_count in vuln_counts:
            if len(suggested_top) < vuln_count:
                logger.warning(f"Model returned only {len(suggested_top)} CWE(s) for {sample_filename}; expected {vuln_count} for mapping {vuln_count}.")
            chosen = suggested_top[:vuln_count]
            for i, cwe_id in enumerate(chosen):
                cwe_info = cwe_lookup.get(cwe_id, {})
                mappings[vuln_count]['cwe_usage'][cwe_id] += 1
                name = cwe_info.get('name', 'Unknown')
                description = cwe_info.get('description', 'No description available')
                mappings[vuln_count]['mapping'].append({
                    'filename': sample_filename,
                    'vulnerability_index': i + 1,
                    'cwe_id': cwe_id,
                    'name': name,
                    'description': description,
                    # 'implementation': implementations.get(cwe_id, "Implement this vulnerability type")
                })

        # Move processed file to processed_<language> folder
        if move_processed:
            try:
                dest = os.path.join(processed_full, sample_filename)
                shutil.move(file_path, dest)
            except Exception as e:
                logger.error(f"Failed to move {file_path} to {processed_full}: {e}")

        processed_count += 1
        # Print progress after every 5 files (or at end)
        if processed_count % 5 == 0 or processed_count == total:
            print(f"[{processed_count}/{total}] files processed for language: {language}")

    # Print distributions
    for vuln_count in vuln_counts:
        cwe_usage = mappings[vuln_count]['cwe_usage']
        print(f"\nCWE distribution for {vuln_count} vuln(s):")
        total_vulns = sum(cwe_usage.values())
        if total_vulns == 0:
            print("  No vulnerabilities recorded.")
            continue
        for cwe_id, count in sorted(cwe_usage.items()):
            percentage = (count / total_vulns) * 100
            print(f"  {cwe_id}: {count} instances ({percentage:.1f}%)")

    # Convert defaultdicts to normal dicts for JSON serialization compatibility
    for v in vuln_counts:
        mappings[v]['cwe_usage'] = dict(mappings[v]['cwe_usage'])

    return mappings

def _ensure_csv_header_and_open(filepath, fieldnames):
    """Helper: open CSV in append mode, write header if file not exists or empty."""
    write_header = True
    if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
        write_header = False

    f = open(filepath, 'a', newline='', encoding='utf-8')
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    if write_header:
        writer.writeheader()
    return f, writer

def merge_distribution_stats(existing_path, new_counts):
    """Merge distribution stats: sum counts from new_counts into existing JSON at existing_path."""
    merged = {}
    if os.path.exists(existing_path):
        try:
            with open(existing_path, 'r', encoding='utf-8') as ef:
                merged = json.load(ef)
        except Exception as e:
            logger.error(f"Failed to read existing distribution file {existing_path}: {e}")
            merged = {}

    # merged may have string keys and int values
    for k, v in new_counts.items():
        merged[k] = merged.get(k, 0) + v

    try:
        with open(existing_path, 'w', encoding='utf-8') as wf:
            json.dump(merged, wf, indent=2)
    except Exception as e:
        logger.error(f"Failed to write merged distribution file {existing_path}: {e}")

    return existing_path

def save_mappings(mappings, language, output_dir="data/cwe_mapping/"):
    """Save vulnerability mappings to CSV files and append/merge if exist."""
    output_dir = os.path.join(output_dir, language)
    os.makedirs(output_dir, exist_ok=True)
    
    saved_files = []
    # fieldnames = ['filename', 'vulnerability_index', 'cwe_id', 'name', 'description', 'implementation']
    fieldnames = ['filename', 'vulnerability_index', 'cwe_id', 'name', 'description']
    
    for vuln_count, data in mappings.items():
        filename = f"cwe_mapping_{vuln_count}vulns.csv"
        filepath = os.path.join(output_dir, filename)

        # Append rows to CSV, writing header only if file is new/empty
        try:
            f, writer = _ensure_csv_header_and_open(filepath, fieldnames)
            for row in data['mapping']:
                writer.writerow(row)
            f.close()
            saved_files.append(filepath)
            print(f"Saved/Appended: {filepath}")
        except Exception as e:
            logger.error(f"Failed to write CSV {filepath}: {e}")

        # Save/merge distribution statistics as JSON (append semantics -> merge counts)
        stats_filename = f"distribution_stats_{vuln_count}vulns.json"
        stats_filepath = os.path.join(output_dir, stats_filename)
        try:
            merge_distribution_stats(stats_filepath, data['cwe_usage'])
            saved_files.append(stats_filepath)
            print(f"Merged stats: {stats_filepath}")
        except Exception as e:
            logger.error(f"Failed to merge stats {stats_filepath}: {e}")

    return saved_files

def main():
    parser = argparse.ArgumentParser(description='Generate CWE mapping files')
    parser.add_argument('--samples-dir', type=str, 
                       default='data/source_files',
                       help='Directory containing extracted raw samples language wise')
    parser.add_argument('--language', type=str, required=True,
                       help='Programming language of the samples (e.g., Python)')
    parser.add_argument('--config-path', type=str,
                       default='data/cwe_top25_2024.json',
                       help='Path to CWE configuration file')
    parser.add_argument('--output-dir', type=str,
                       default='data/cwe_mapping',
                       help='Output directory for mapping files')
    parser.add_argument('--vuln-counts', nargs='+', type=int, default=[1, 3, 5, 9],
                       help='Vulnerability counts per sample')
    parser.add_argument('--api-key', type=str, help='OPENAI API key (or set OPENAI_API_KEY env var)')
    parser.add_argument('--limit', type=int, default=None,
                       help='If set, process only this many files (e.g., 20)')
    parser.add_argument('--no-move', action='store_true',
                       help='If set, do not move processed files to processed_<language> folder')
    args = parser.parse_args()

    load_dotenv()
    api_key = args.api_key or os.getenv('OPENAI_API_KEY')
    
    # Load data
    print("Loading CWE data...")
    cwes = load_cwe_data(args.config_path)
    print(f"Loaded {len(cwes)} CWEs")

    print("Loading sample filenames...")
    lang_map = {
        "Python": "Python",
        "python": "Python",
        "Java": "Java",
        "java": "Java",
        "JavaScript": "JavaScript",
        "javascript": "JavaScript",
        "JS": "JavaScript",
        "js": "JavaScript",
        "C++": "C++",
        "CPP": "C++",
        "cpp": "C++",
        "GO": "GO",
        "go": "GO",
        "C": "C",
        "c": "C",
    }
    language_folder = lang_map.get(args.language)
    if not language_folder:
        print(f"Unsupported language: {args.language}", file=sys.stderr)
        sys.exit(1)

    samples = load_sample_filename(language_folder, args.samples_dir)
    if args.limit is not None:
        samples = samples[:args.limit]
    print(f"Loaded {len(samples)} samples (processing limit: {args.limit})")
    
    # Generate mappings
    print("Generating vulnerability distributions...")
    mappings = distribute_vulnerabilities(
        api_key,
        samples,
        language_folder,
        cwes,
        samples_dir=args.samples_dir,
        vuln_counts=args.vuln_counts,
        move_processed=not args.no_move,
        processed_folder_name=f"Processed_{language_folder}"
    )
    
    # Save mappings
    print("Saving mapping files...")
    saved_files = save_mappings(mappings, language_folder, args.output_dir)
    
    print(f"\n Successfully generated/updated {len(saved_files)} mapping files")
    print("Files created/updated:")
    for file_path in saved_files:
        print(f"  {file_path}")

if __name__ == "__main__":
    main()
