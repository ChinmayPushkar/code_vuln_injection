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
# keep requests import for compatibility if other parts still need it
import requests
import logging

# NEW async/network imports
import asyncio
import aiohttp
from more_itertools import chunked  # pip install more-itertools if not present
import time
import random

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()  # load env vars if present

# -----------------------
# (unchanged) helper functions & utilities
# -----------------------

def list_samples_from_directory(directory, language_folder):
    lang_map_extension = {
        "python": "py",
        "Python": "py",
        "py": "py",
        "java": "java",
        "Java": "java",
        "Javascript": "js",
        "js": "js",
        "javascript": "js",
        "cpp": "cpp",
        "c++": "cpp",
        "C++": "cpp",
        "CPP": "cpp",
        "GO": "go",
        "go": "go",
        "C": "c",
        "c": "c",
    }
    lang = lang_map_extension.get(language_folder)
    directory = os.path.join(directory, language_folder)
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

def chunk_text(text, max_chars=8000):
    """
    Split a long text into chunks of roughly max_chars length.
    Used to avoid exceeding model token/context limits.
    """
    chunks = []
    for i in range(0, len(text), max_chars):
        chunks.append(text[i:i + max_chars])
    return chunks


def extract_cwe_ids_from_text(text):
    """
    Given a model response text, attempt to extract CWE IDs (like CWE-79).
    Uses a couple heuristics and a regex fallback.
    """
    if not text:
        return []
    # heuristic: JSON-like
    try:
        # attempt to parse any JSON inside text
        json_start = text.find('{')
        json_end = text.rfind('}')
        if json_start != -1 and json_end != -1 and json_end > json_start:
            snippet = text[json_start:json_end+1]
            parsed = json.loads(snippet)
            if isinstance(parsed, list):
                # attempt to normalize items like "CWE-79"
                res = []
                for item in parsed:
                    if isinstance(item, str):
                        m = re.search(r"(CWE-\d+)", item, flags=re.IGNORECASE)
                        if m:
                            res.append(m.group(1).upper())
                if res:
                    return res
            elif isinstance(parsed, dict):
                # look for values containing CWE ids
                s = json.dumps(parsed)
                matches = re.findall(r"(CWE-\d+)", s, flags=re.IGNORECASE)
                return [m.upper() for m in matches]
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

# -----------------------
# Replace blocking API calls with async aiohttp versions
# -----------------------

async def _async_post_json(session: aiohttp.ClientSession, url: str, json_data: dict, max_retries=2, backoff_base=0.5):
    """Helper to POST JSON with retries and exponential backoff (async)."""
    attempt = 0
    while True:
        attempt += 1
        try:
            timeout = aiohttp.ClientTimeout(total=300)
            async with session.post(url, json=json_data, timeout=timeout) as resp:
                resp.raise_for_status()
                try:
                    return await resp.json()
                except aiohttp.ContentTypeError:
                    # fallback: try text
                    txt = await resp.text()
                    try:
                        return json.loads(txt)
                    except Exception:
                        return {"response_text": txt}
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            if attempt >= max_retries:
                logger.exception(f"HTTP POST to {url} failed after {attempt} attempts: {e!r}")
                raise
            sleep_time = backoff_base * (2 ** (attempt - 1)) + random.random() * 0.1
            logger.warning(f"Retry {attempt}/{max_retries} for {url} after {sleep_time:.2f}s due to {e!r}")
            await asyncio.sleep(sleep_time)


async def call_ollama_api_async(api_url, system_msg, prompt, max_tokens=512, temperature=0.0):
    """
    Async version of call_ollama_api.
    Expects an Ollama-like endpoint that returns JSON with 'choices' and 'message' structure.
    """
    headers = {"Content-Type": "application/json"}
    data = {
        "model": "qwen2.5-32b-instruct",  # keep same default as before (was hard-coded earlier)
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": False
    }
    async with aiohttp.ClientSession(headers=headers) as session:
        response_data = await _async_post_json(session, api_url, data)
        # Check if the response contains 'choices' and extract the content
        if isinstance(response_data, dict) and "choices" in response_data:
            try:
                return response_data["choices"][0]["message"]["content"]
            except (KeyError, IndexError):
                return "Error: Unexpected response format."
        return response_data

# -----------------------
# Async version of distribute_vulnerabilities
# -----------------------

async def distribute_vulnerabilities_async(api_key, samples, language, cwes, samples_dir="data/source_files",
                                           vuln_counts=[1, 3, 5, 9], move_processed=True,
                                           processed_folder_name=None, batch_size=20, concurrency=6, ollama_api_url=None):
    """
    Async variant of the original distribute_vulnerabilities function.
    Processes samples in batches and issues concurrent API requests with a semaphore.
    Minimal changes to logic and mapping formats to keep output identical.
    """
    mappings = {v: {'mapping': [], 'cwe_usage': defaultdict(int)} for v in vuln_counts}
    cwe_lookup = {cwe['cwe_id']: cwe for cwe in cwes}

    samples_base = os.path.join(samples_dir, language)
    processed_dir = processed_folder_name or f"Processed_{language}"
    processed_full = os.path.join(samples_dir, processed_dir)
    if move_processed:
        os.makedirs(processed_full, exist_ok=True)

    total = len(samples)
    processed_count = 0

    semaphore = asyncio.Semaphore(concurrency)

    # We'll reuse a single aiohttp ClientSession for efficiency (if using external endpoints)
    # If use_ollama is True we will call ollama endpoint; otherwise use openai-like endpoint
    # Provide endpoint URLs via arguments or environment variables as before
    ollama_api_url = ollama_api_url or os.getenv("OLLAMA_API_URL")

    async def process_one_sample(sample):
        nonlocal processed_count
        sample_filename = sample['filename']
        file_path = os.path.join(samples_base, sample_filename)

        # read file off-thread to avoid blocking event loop
        code = await asyncio.to_thread(read_code_from_file, file_path)
        if code is None:
            logger.error(f"Skipping {sample_filename} due to read error.")
            return

        # NEW: Chunking logic for long files
        max_chars = 8000  # safe approximate limit (~6K tokens)
        code_chunks = chunk_text(code, max_chars) if len(code) > max_chars else [code]
        full_response = ""

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

        # Process each chunk sequentially
        for idx, chunk in enumerate(code_chunks):
            user_prompt = f"""I have the following {language} code (part {idx + 1}/{len(code_chunks)}):
            ```{language.lower()}
            {chunk}
            Please suggest the top {top_k} vulnerabilities that are feasible to be induced in the given code from the following list of CWEs:

            {cwes}
            Return ONLY the cwe_ids as a list.
            For example, if you suggest CWE-79 and CWE-89, return: ["CWE-79", "CWE-89"] and nothing else.
            """
            async with semaphore:
                try:
                    if not ollama_api_url:
                        raise RuntimeError("OLLAMA API URL not provided.")
                    resp_part = await call_ollama_api_async(ollama_api_url, system_msg, user_prompt)
                    full_response += f"\n{resp_part}"
                except Exception as e:
                    logger.exception(f"API error for chunk {idx+1} of {sample_filename}: {e!r}")
                    continue

        # extract CWE IDs from combined responses
        cwe_ids = extract_cwe_ids_from_text(full_response if isinstance(full_response, str) else json.dumps(full_response))
        
        # For each vuln_count, pick top N CWEs
        for v in vuln_counts:
            top_n = cwe_ids[:v]
            for i, cwe_id in enumerate(top_n):
                cwe_info = cwe_lookup.get(cwe_id, {})
                name = cwe_info.get('name', 'Unknown')
                description = cwe_info.get('description', 'No description available')
                mappings[v]['mapping'].append({
                    'filename': sample_filename,
                    'vulnerability_index': i + 1,
                    'cwe_id': cwe_id,
                    'name': name,
                    'description': description,
                })
                mappings[v]['cwe_usage'][cwe_id] += 1

        # Move processed file as before
        if move_processed:
            try:
                dest = os.path.join(processed_full, sample_filename)
                await asyncio.to_thread(shutil.move, file_path, dest)
            except Exception as e:
                logger.error(f"Failed to move {file_path} to {processed_full}: {e}")

        processed_count += 1
        if processed_count % 5 == 0 or processed_count == total:
            print(f"[{processed_count}/{total}] files processed for language: {language}")

        # Process samples in batches: after each batch, persist intermediate results (same save_mappings call as original)
        # We will process batches of size batch_size to keep memory bounded and to persist progress
    for batch_idx, batch in enumerate(chunked(samples, batch_size)):
        tasks = []
        for sample in batch:
            tasks.append(asyncio.create_task(process_one_sample(sample)))
        # await all tasks in this batch (exceptions are logged inside function)
        await asyncio.gather(*tasks, return_exceptions=True)

        # after batch is done, persist mappings for safety (the original did save at the end; here we save after each batch)
        # Use original save_mappings function below (it's synchronous) via to_thread to avoid blocking
        try:
            # Note: save_mappings expects mappings and language folder name; it returns saved file paths.
            await asyncio.to_thread(save_mappings, mappings, language, os.path.join(samples_dir, '..', 'data', 'cwe_mapping') if False else os.getcwd() if False else None)
            # Above line uses a dummy path to keep signature; we'll simply call the real save at the end of main to avoid confusion.
        except Exception:
            # ignore errors here to not interrupt processing; final save will occur in main
            pass

    # Return mappings to the caller (main will then call save_mappings/maybe persist)
    return mappings

# -----------------------
# Keep save_mappings and other file-writing functions unchanged for format compatibility
# (only minor tweaks to ensure imports exist)
# -----------------------

def merge_distribution_stats(stats_filepath, cwe_usage):
    """Merge cwe usage counts into a stats file (summing counts)"""
    try:
        existing = {}
        if os.path.exists(stats_filepath):
            with open(stats_filepath, 'r', encoding='utf-8') as f:
                existing = json.load(f)
        for k, v in cwe_usage.items():
            existing[k] = existing.get(k, 0) + v
        with open(stats_filepath, 'w', encoding='utf-8') as f:
            json.dump(existing, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to merge distribution stats {stats_filepath}: {e}")

def save_mappings(mappings, language_folder, output_dir="data/cwe_mapping"):
    """
    Save mappings in the same format as original file.
    This function is expected to be synchronous (as before).
    """
    saved_files = []
    output_dir = os.path.join(output_dir, language_folder)
    os.makedirs(output_dir, exist_ok=True)

    for vuln_count, data in mappings.items():
        # Save CSV per CWE mapping list
        filename = f"cwe_mapping_{vuln_count}vulns.csv"
        filepath = os.path.join(output_dir, filename)
        try:
            # write header if not exists
            write_header = not os.path.exists(filepath)
            with open(filepath, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=['filename', 'vulnerability_index', 'cwe_id', 'name', 'description'])
                if write_header:
                    writer.writeheader()
                for row in data['mapping']:
                    writer.writerow(row)
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

# -----------------------
# MAIN
# -----------------------

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
                        help='Which top counts of vulnerabilities to request/save')
    # NEW: concurrency and batch-size arguments
    parser.add_argument('--concurrency', type=int, default=6, help='Max concurrent API calls')
    parser.add_argument('--batch-size', type=int, default=20, help='How many samples to process per batch')
    parser.add_argument('--ollama-api-url', type=str, default=os.getenv("OLLAMA_API_URL"), help='Ollama API url')
    parser.add_argument('--move-processed', action='store_true', help='Move processed files to processed_<language> folder')
    parser.add_argument('--limit', type=int, default=None, help='If set, process only this many files (e.g., 20)')

    args = parser.parse_args()

    # read configuration of CWEs
    try:
        with open(args.config_path, 'r', encoding='utf-8') as f:
            cwes = json.load(f)
    except Exception as e:
        logger.error(f"Failed to load CWE config path {args.config_path}: {e}")
        sys.exit(1)

    # prepare samples list
    language_folder = args.language
    samples = list_samples_from_directory(args.samples_dir, language_folder)
    if not samples:
        print("No samples found.")
        return
    if args.limit is not None:
        samples = samples[:args.limit]
    print(f"Loaded {len(samples)} samples (processing limit: {args.limit})")

    api_key = os.getenv("OPENAI_API_KEY", None)  # used only if calling openai_api_url requiring it

    # Run async distribution
    loop = asyncio.get_event_loop()
    try:
        mappings = loop.run_until_complete(distribute_vulnerabilities_async(
            api_key=api_key,
            samples=samples,
            language=language_folder,
            cwes=cwes,
            samples_dir=args.samples_dir,
            vuln_counts=args.vuln_counts,
            move_processed=args.move_processed,
            processed_folder_name=f"Processed_{language_folder}",
            batch_size=args.batch_size,
            concurrency=args.concurrency,
            ollama_api_url=args.ollama_api_url
        ))
    finally:
        # ensure loop cleanup if required
        if loop.is_running():
            loop.close()

    # Save mappings (final)
    print("Saving mapping files...")
    saved_files = save_mappings(mappings, language_folder, args.output_dir)

    print(f"\n Successfully generated/updated {len(saved_files)} mapping files")
    print("Files created/updated:")
    for file_path in saved_files:
        print(f"  {file_path}")

if __name__ == "__main__":
    main()
