
import os
import sys
import csv
import json
import requests
import time
import random
import argparse
import logging
from tqdm import tqdm
from pathlib import Path


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class VulnerabilityInjector:
    def __init__(self, api_key=None):
        """Initialize the vulnerability injector."""
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OpenAI API key not provided. Set OPENAI_API_KEY environment variable.")

        # OpenAI API endpoint
        self.openai_api_url = f"https://api.openai.com/v1/chat/completions"
        self.ollama_api_url = "http://172.24.16.155:11434/api/generate"
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

    def call_ollama_api(self, prompt, max_tokens=16000, temperature=0.7):
        """Call the Ollama API with the given prompt (replaces OpenAI)."""

        # Ollama API endpoint (update host/port if different in your setup)
        api_url = self.ollama_api_url
        headers = {
            "Content-Type": "application/json"
        }
        data = {
            "model": "llama3.2:latest",
            "prompt": prompt,
            "stream": False
        }

        try:
            response = requests.post(api_url, headers=headers, json=data)
            response.raise_for_status()
            response_data = response.json()

            # Extract text from Ollama response format
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

    def call_openai_api(self, prompt, max_tokens=16000, temperature=0.7):
        """Call the OpenAI API with the given prompt."""
        data = {
            "model": "gpt-4",
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": max_tokens,
            "temperature": temperature
        }

        try:
            response = requests.post(self.openai_api_url, headers=self.headers, json=data)
            response.raise_for_status()
            response_data = response.json()

            # Extract text from OpenAI response format
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

    def read_code_from_file(self, file_path):
        """Read code from a file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return None

    def get_cwes_for_file(self, csv_path, filename):
        """Get CWEs for a specific file from the CSV."""
        cwes = []
        try:
            with open(csv_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['filename'] == filename:
                        cwe = {
                            'cwe_id': row['cwe_id'].strip(),
                            'name': row['name'].strip(),
                            'description': row['description'].strip(),
                            'implementation': row['implementation'].strip()
                        }
                        cwes.append(cwe)
        except Exception as e:
            logger.error(f"Error reading CSV {csv_path}: {e}")

        return cwes

    def extract_code_from_response(self, response):
        """Extract code from API response, handling different formats."""
        if not response:
            return None

        # Try to extract code from markdown code block
        import re
        code_match = re.search(r"```(?:python)?\s*(.*?)\s*```", response, re.DOTALL)
        if code_match:
            return code_match.group(1).strip()

        # If no code block found, return the whole response
        return response.strip()

    def is_response_truncated(self, original_code, generated_code):
        """Check if the response appears to be truncated."""
        if not generated_code:
            return True
        original_lines = len(original_code.strip().split('\n'))
        generated_lines = len(generated_code.strip().split('\n'))
        if generated_lines < original_lines * 0.8:
            return True
        try:
            compile(generated_code, '<string>', 'exec')
            return False
        except SyntaxError:
            return True

    def inject_vulnerabilities(self, code, cwes):
        """Inject vulnerabilities into the code based on the CWEs."""
        if not cwes or not code:
            logger.warning("No CWEs to inject or invalid code")
            return code

        # Create CWE descriptions
        cwe_descriptions = "\n".join([
            f"- {cwe['cwe_id']} ({cwe['name']}): {cwe['description']}"
            for cwe in cwes
        ])

        prompt = f"""You are a cybersecurity expert specializing in code vulnerabilities.


        I have the following code:
        ```
        {code}
        ```
        Please modify this code to introduce ALL of the following vulnerabilities:

        {cwe_descriptions}

        For each vulnerability, here are implementation suggestions:
        {chr(10).join([f"- {cwe['cwe_id']}: {cwe['implementation']}" for cwe in cwes])}

        IMPORTANT REQUIREMENTS:
        1. Make the changes as subtle as possible while still being real vulnerabilities that would be detected by security tools.
        2. Each vulnerability should be in a different part of the code if possible.
        3. The code MUST maintain its original functionality - if it performed task X before, it should still perform task X after modification.
        4. Don't add comments indicating the vulnerabilities.
        5. Don't add entirely new functions - modify existing code to introduce vulnerabilities.
        6. Ensure the code remains syntactically valid Python.


        Return ONLY the modified code, nothing else.
        """

        # response = self.call_openai_api(prompt, max_tokens=16000, temperature=0.8)
        response = self.call_ollama_api(prompt, max_tokens=16000, temperature=0.8)
        if not response:
            logger.error("No response from API when injecting vulnerabilities")
            return code

        vulnerable_code = self.extract_code_from_response(response)
        if not vulnerable_code:
            logger.error("Failed to extract code from API response")
            return code

        return vulnerable_code

    def process_sample(self, input_file, cwes, output_dir, vuln_count, language):
        """Process a single sample to inject vulnerabilities."""
        filename = os.path.basename(input_file)

        # Read original code
        code = self.read_code_from_file(input_file)
        if not code:
            logger.error(f"Could not read input file {input_file}")
            return None

        
        if not cwes:
            logger.warning(f"No CWEs found for {filename}")
            # Copy original file
            output_file = os.path.join(output_dir, language, filename)
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(code)
            return {
                "sample": filename,
                "cwe_id": [],
                "cwe_name": [],
                "cwe_description": [],
                "cwe_implementation": [],
                "is_response_truncated": False
            }

        logger.info(f"Found {len(cwes)} CWEs for {filename}")

        # Inject vulnerabilities
        logger.info("Injecting vulnerabilities...")
        vulnerable_code = self.inject_vulnerabilities(code, cwes)

        is_truncated = self.is_response_truncated(code, vulnerable_code)

        dataset_dir = os.path.join(output_dir, language, f"dataset_{vuln_count}vulns") 
        os.makedirs(dataset_dir, exist_ok=True)

        output_file = os.path.join(dataset_dir, filename)
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(vulnerable_code)

        except Exception as e:
            logger.error(f"Error writing output: {e}")
            return None
        return{
            "sample": filename,
            "cwe_id": [c['cwe_id'] for c in cwes],
            "cwe_name": [c['name'] for c in cwes],
            "cwe_description": [c['description'] for c in cwes],
            "cwe_implementation": [c['implementation'] for c in cwes],
            "is_response_truncated": is_truncated
        }

def main():
    parser = argparse.ArgumentParser(description='Inject vulnerabilities into Python code using OpenAI API')
    parser.add_argument('--samples-dir', type=str, 
                       default='data/source_files',
                       help='Directory containing extracted raw samples language wise')
    parser.add_argument('--mappings-dir', type=str,
                       default='data/cwe_mapping',
                       help='Directory containing CWE mapping files')
    parser.add_argument('--output-dir', type=str,
                       default='data/vulnerable_files',
                       help='Output directory for vulnerable samples language wise')
    parser.add_argument('--vuln-counts', nargs='+', type=int, default=[1, 3, 5, 9],
                       help='Vulnerability counts to process')
    parser.add_argument('--language', type=str, required=True,
                       help='Programming language of the samples (e.g., Python)')
    parser.add_argument('--api-key', type=str, help='OPENAI API key (or set OPENAI_API_KEY env var)')

    args = parser.parse_args()

    # Initialize injector
    try:
        injector = VulnerabilityInjector(args.api_key)
    except ValueError as e:
        logger.error(e)
        sys.exit(1)

    # Get list of sample files
    lang_map = {
        "Python": "Python",
        "python": "Python",
        "Java": "Java",
        "java": "Java",
        "JavaScript": "JavaScript",
        "javascript": "JavaScript",
        "JS": "JavaScript",
        "js": "JavaScript"
        "C++": "C++",
        "CPP": "C++",
        "cpp": "C++",
        "GO": "GO",
        "go": "GO",
        "C": "C",
        "c": "C",
    }
    language_folder = lang_map.get(args.language)
    samples_dir_str = os.path.join(args.samples_dir, language_folder)
    samples_dir = Path(samples_dir_str)
    lang_map_extension = {
        "Python": "py",
        "python": "py",
        "Java": "java",
        "java": "java",
        "JavaScript": "js",
        "javascript": "js",
        "JS": "js",
        "js": "js",
        "C++": "cpp",
        "CPP": "cpp",
        "cpp": "cpp",
        "GO": "go",
        "go": "go",
        "C": "c",
        "c": "c",
    }
    lang = lang_map_extension.get(args.language)
    sample_files = list(samples_dir.glob(f"sample_*.{lang}"))
    #testing
    sample_files = sample_files[:3]

    if not sample_files:
        logger.error(f"No sample files found in {samples_dir}")
        sys.exit(1)

    logger.info(f"Found {len(sample_files)} sample files")

    # Process each vulnerability count
    total_processed = 0
    total_failed = 0

    for vuln_count in args.vuln_counts:
        logger.info(f"\nProcessing {vuln_count} vulnerability(ies) per sample...")

        csv_path = os.path.join(args.mappings_dir, language_folder, f"cwe_mapping_{vuln_count}vulns.csv")
        if not os.path.exists(csv_path):
            logger.error(f"Mapping file not found: {csv_path}")
            continue
        with open(csv_path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            cwe_map = {}
            for row in reader:
                fname = row['filename']
                cwe_map.setdefault(fname, []).append({
                    'cwe_id': row['cwe_id'].strip(),
                    'name': row['name'].strip(),
                    'description': row['description'].strip(),
                    'implementation': row['implementation'].strip()
                })

        dataset_results = []
        processed = 0
        failed = 0

        dataset_dir = os.path.join(args.output_dir, language_folder, f"dataset_{vuln_count}vulns")
        os.makedirs(dataset_dir, exist_ok=True)

        for sample_file in tqdm(sample_files, desc=f"Processing {vuln_count} vulns"):
            fname = os.path.basename(sample_file)
            cwes = cwe_map.get(fname, [])
            result = injector.process_sample(sample_file, cwes, args.output_dir, vuln_count, language_folder)
            if result is not None:
                dataset_results.append(result)
                processed += 1
            else:
                failed += 1
            time.sleep(2) # Rate limiting
            
        json_path = os.path.join(dataset_dir, f"cwe_info_{vuln_count}vulns.json")
        with open(json_path, 'w', encoding='utf-8') as jf:
            json.dump(dataset_results, jf, indent=2)
        logger.info(f"CWE dataset info written to {json_path}")
        logger.info(f"Completed {vuln_count} vulns: {processed} successful, {failed} failed")
        total_processed += processed
        total_failed += failed

    # Create clean dataset (0 vulnerabilities)
    logger.info("\nCreating clean dataset (0 vulnerabilities)...")
    clean_dir = os.path.join(args.output_dir, language_folder, "dataset_0vulns") 
    os.makedirs(clean_dir, exist_ok=True)

    for sample_file in sample_files:
        output_file = os.path.join(clean_dir, os.path.basename(sample_file))
        with open(sample_file, 'r', encoding='utf-8') as src:
            with open(output_file, 'w', encoding='utf-8') as dst:
                dst.write(src.read())

    logger.info(f"✅ Pipeline complete!")
    logger.info(f"Total processed: {total_processed}")
    logger.info(f"Total failed: {total_failed}")
    logger.info(f"Created datasets: {len(args.vuln_counts) + 1} (including clean)")


if __name__ == "__main__":
    main()
