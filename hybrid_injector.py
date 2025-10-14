#!/usr/bin/env python3
import os
import sys
import csv
import json
import time
import random
import argparse
import logging
import asyncio
import aiohttp
import shutil
import itertools
from pathlib import Path
from dotenv import load_dotenv
from tqdm import tqdm

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# -----------------------------
# Utility functions
# -----------------------------
def estimate_tokens(text):
    """Rough token estimate (≈ 4 chars per token)."""
    return int(len(text) / 4)

def chunk_text(text, max_tokens=30000):
    """Split text safely to fit within model context."""
    max_chars = max_tokens * 4  # convert to chars
    return [text[i:i + max_chars] for i in range(0, len(text), max_chars)]

def chunked_iterable(iterable, size):
    """Yield successive chunks of given size from iterable."""
    it = list(iterable)
    for i in range(0, len(it), size):
        yield it[i:i + size]

# -----------------------------
# VulnerabilityInjector Class
# -----------------------------
class VulnerabilityInjector:
    def __init__(self, endpoint_infos, api_key=None, session=None, max_context_tokens=32768):
        """
        Initialize with multiple Modal endpoints.
        endpoint_infos: list of dicts: {"url": "...", "model": "model_name"}
        max_context_tokens: Model's total context window (default: 32768 for Qwen2.5-32B)
        """
        self.endpoint_infos = endpoint_infos
        self.endpoint_cycle = itertools.cycle(endpoint_infos)
        self.max_context_tokens = max_context_tokens
        self.headers = {"Content-Type": "application/json"}
        self.session = session

    async def _async_post_json(self, session, url, json_data, max_retries=2, backoff_base=0.5):
        """Helper to POST JSON with retries."""
        attempt = 0
        while True:
            attempt += 1
            try:
                async with session.post(url, json=json_data, timeout=300) as resp:
                    # Get response body before raising for better error messages
                    try:
                        response_body = await resp.text()
                    except:
                        response_body = ""
                    
                    if resp.status >= 400:
                        logger.error(f"HTTP {resp.status} from {url}")
                        logger.error(f"Response body: {response_body[:500]}")  # First 500 chars
                        logger.error(f"Request payload size: {len(json.dumps(json_data))} bytes")
                        resp.raise_for_status()
                    
                    try:
                        return json.loads(response_body)
                    except:
                        return {"response_text": response_body}
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt >= max_retries:
                    logger.exception(f"Failed POST to {url} after {max_retries} attempts: {e!r}")
                    raise
                sleep_time = backoff_base * (2 ** (attempt - 1)) + random.random() * 0.1
                logger.warning(f"Retry {attempt}/{max_retries} for {url} after {sleep_time:.2f}s due to {e!r}")
                await asyncio.sleep(sleep_time)

    async def call_modal_api_async(self, api_url, model_name, prompt, temperature=0.6, max_tokens=None):
        """Async call to Modal endpoint using a specific model name for that endpoint."""
        # Calculate input tokens
        input_tokens = estimate_tokens(prompt)
        
        # Model's total context window
        model_context_limit = 32768
        
        # If max_tokens not specified or too large, calculate appropriate value
        if max_tokens is None or max_tokens + input_tokens > model_context_limit:
            # Leave room for output: total_context - input - safety_buffer
            safety_buffer = 500  # Reserve some tokens for safety
            max_tokens = max(1000, model_context_limit - input_tokens - safety_buffer)
        
        logger.info(f"API call: input={input_tokens} tokens, max_output={max_tokens} tokens, total={input_tokens + max_tokens}/{model_context_limit}")
        
        data = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature
        }
        session = self.session or aiohttp.ClientSession(headers=self.headers)
        local = self.session is None
        try:
            return await self._async_post_json(session, api_url, data)
        finally:
            if local:
                await session.close()

    def extract_code_from_response(self, response):
        """Extract code from response."""
        if not response:
            return ""
        import re
        if isinstance(response, dict) and "choices" in response:
            text = response["choices"][0]["message"]["content"]
        else:
            text = str(response)
        match = re.search(r"```(?:python)?\s*(.*?)```", text, re.DOTALL)
        return match.group(1).strip() if match else text.strip()

    # --------------------------
    # Hybrid Vulnerability Injection Logic
    # --------------------------
    async def inject_vulnerabilities_hybrid(self, code, cwes):
        """
        Inject vulnerabilities with hybrid logic (multi-endpoint + chunk fallback).
        Chooses the next endpoint (url+model) from the cycle and uses that model for the request.
        """
        endpoint_info = next(self.endpoint_cycle)
        api_url = endpoint_info.get('url')
        model_name = endpoint_info.get('model', 'qwen2.5-32b-instruct')

        # Estimate total tokens needed (input + reasonable output)
        code_tokens = estimate_tokens(code)
        cwe_overhead = len(cwes) * 50  # Approximate tokens per CWE description
        prompt_tokens = code_tokens + cwe_overhead + 500  # +500 for prompt template
        
        # If prompt + reasonable output exceeds limit, use chunking
        # Reserve at least 8000 tokens for output
        if prompt_tokens + 8000 > self.max_context_tokens:
            logger.info(f"Code too large ({prompt_tokens} prompt tokens) → using chunking.")
            return await self.inject_with_chunking(code, cwes, api_url, model_name)
        else:
            return await self.inject_full_file(code, cwes, api_url, model_name)

    async def inject_full_file(self, code, cwes, api_url, model_name):
        """Inject vulnerabilities in one go using the given endpoint and model."""
        cwe_details = "\n".join([f"- {c['cwe_id']} ({c['name']}): {c['description']}" for c in cwes])
        prompt = f"""You are a cybersecurity expert. I have the following code:
                ```
                {code}
                ```
                Please modify this code to introduce ALL of the following vulnerabilities:

                {cwe_details}

                Requirements:
                1. Keep logic intact.
                2. Do not add comments or explanations.
                3. Return ONLY modified code.
                """
        try:
            response = await self.call_modal_api_async(api_url, model_name, prompt)
            return self.extract_code_from_response(response)
        except Exception as e:
            logger.error(f"Error injecting full file at {api_url} (model {model_name}): {e}")
            return code

    async def inject_with_chunking(self, code, cwes, api_url, model_name):
        """
        Split long code into safe chunks and distribute CWEs across them, calling same endpoint+model for all chunks.
        Distributes CWEs across chunks to ensure total CWE count remains equal to input list length.
        """
        code_chunks = chunk_text(code, max_tokens=self.max_context_tokens - 2000)
        total_cwes = len(cwes)
        full_modified_code = ""

        for i, chunk in enumerate(code_chunks):
            start = i * total_cwes // len(code_chunks)
            end = (i + 1) * total_cwes // len(code_chunks)
            chunk_cwes = cwes[start:end]
            if not chunk_cwes:
                full_modified_code += chunk
                continue

            cwe_details = "\n".join([f"- {c['cwe_id']} ({c['name']}): {c['description']}" for c in chunk_cwes])
            prompt = f"""You are a cybersecurity expert.
                I have this code (part {i+1}/{len(code_chunks)}):
                Inject the following vulnerabilities:

                {cwe_details}

                Rules:
                - Modify only this code.
                - Keep it valid and functional.
                - Return ONLY modified code.
                """
            try:
                response = await self.call_modal_api_async(api_url, model_name, prompt)
                modified = self.extract_code_from_response(response)
                full_modified_code += "\n" + modified
            except Exception as e:
                logger.error(f"Chunk {i+1} failed at {api_url} (model {model_name}): {e}")
                full_modified_code += "\n" + chunk

        return full_modified_code.strip()

# -----------------------------
# Main Async Pipeline
# -----------------------------
async def main_async(args):
    load_dotenv()

    # Read endpoint URLs and optional model names from env vars
    endpoint_infos = []
    for i in range(1, 5):
        url = os.getenv(f"MODAL_API_URL_{i}")
        model = os.getenv(f"MODAL_API_MODEL_{i}")
        if url:
            # If model env var not provided, try to derive a model name pattern from url as fallback
            if not model:
                if 'gpu0' in url:
                    model = 'qwen2.5-32b-instruct-gpu0'
                elif 'gpu1' in url:
                    model = 'qwen2.5-32b-instruct-gpu1'
                elif 'gpu2' in url:
                    model = 'qwen2.5-32b-instruct-gpu2'
                elif 'gpu3' in url:
                    model = 'qwen2.5-32b-instruct-gpu3'
                else:
                    model = 'qwen2.5-32b-instruct'
            endpoint_infos.append({'url': url, 'model': model})

    if not endpoint_infos:
        logger.error("No Modal endpoints configured in environment variables (MODAL_API_URL_1..4)")
        sys.exit(1)

    connector = aiohttp.TCPConnector(limit=args.concurrency)
    session = aiohttp.ClientSession(connector=connector)
    injector = VulnerabilityInjector(endpoint_infos, session=session)

    language_folder = args.language
    processed_dir = os.path.join(args.samples_dir, f"Processed_{language_folder}")
    final_dir = os.path.join(args.samples_dir, f"Final_Processed_{language_folder}")
    os.makedirs(final_dir, exist_ok=True)

    lang_ext = {"Python": "py", "Java": "java", "C": "c", "C++": "cpp", "JavaScript": "js"}.get(args.language, "py")
    sample_files = list(Path(processed_dir).glob(f"sample_*.{lang_ext}"))
    if args.limit:
        sample_files = sample_files[:args.limit]

    logger.info(f"Loaded {len(sample_files)} samples for {language_folder}")

    # Track successfully processed files
    processed_files = set()

    for vuln_count in args.vuln_counts:
        csv_path = os.path.join(args.mappings_dir, language_folder, f"cwe_mapping_{vuln_count}vulns.csv")
        if not os.path.exists(csv_path):
            logger.warning(f"No mapping CSV found for {vuln_count}vulns")
            continue

        # Build CWE mapping
        cwe_map = {}
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                fname = row['filename']
                cwe_map.setdefault(fname, []).append({
                    "cwe_id": row["cwe_id"],
                    "name": row["name"],
                    "description": row["description"]
                })

        dataset_dir = os.path.join(args.output_dir, language_folder, f"dataset_{vuln_count}vulns")
        os.makedirs(dataset_dir, exist_ok=True)

        semaphore = asyncio.Semaphore(args.concurrency)

        async def process_file(sample_path):
            async with semaphore:
                fname = os.path.basename(sample_path)
                cwes = cwe_map.get(fname, [])
                code = Path(sample_path).read_text(encoding='utf-8', errors='ignore')
                modified_code = await injector.inject_vulnerabilities_hybrid(code, cwes)
                output_path = os.path.join(dataset_dir, fname)
                await asyncio.to_thread(Path(output_path).write_text, modified_code, 'utf-8')
                # Track this file as successfully processed
                processed_files.add(str(sample_path))

        for batch in chunked_iterable(sample_files, args.batch_size):
            tasks = [asyncio.create_task(process_file(p)) for p in batch]
            await asyncio.gather(*tasks)
            logger.info(f"✅ Completed batch of {len(batch)} files for {vuln_count}vulns")

    # Now move all successfully processed files to final_dir
    logger.info(f"Moving {len(processed_files)} files to {final_dir}...")
    for sample_path in processed_files:
        fname = os.path.basename(sample_path)
        try:
            shutil.move(sample_path, os.path.join(final_dir, fname))
        except Exception as e:
            logger.error(f"Failed to move {fname}: {e}")

    await session.close()
    logger.info("✅ All processing complete.")

# -----------------------------
# Entrypoint
# -----------------------------
def main():
    parser = argparse.ArgumentParser(description="Hybrid vulnerability injection using multiple Modal endpoints")
    parser.add_argument("--samples-dir", default="data/source_files", help="Directory with source files")
    parser.add_argument("--mappings-dir", default="data/cwe_mapping", help="Directory with CWE mappings")
    parser.add_argument("--output-dir", default="data/vulnerable_files", help="Output directory")
    parser.add_argument("--language", required=True, help="Language folder (e.g., Python)")
    parser.add_argument("--vuln-counts", nargs="+", type=int, default=[1,3,5,9], help="Vulnerability counts")
    parser.add_argument("--concurrency", type=int, default=6, help="Max concurrent calls")
    parser.add_argument("--batch-size", type=int, default=10, help="Files per batch")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of files to process")
    args = parser.parse_args()

    asyncio.run(main_async(args))

if __name__ == "__main__":
    main()