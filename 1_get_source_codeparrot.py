import os
from datasets import load_dataset
import random
import hashlib
import time

languages = ["C", "C++", "Python", "GO", "Java", "JavaScript"]

extensions = {
    "C": "c",
    "C++": "cpp",
    "Python": "py",
    "GO": "go",
    "Java": "java",
    "JavaScript": "js"
}
def count_lines(code):
    """Count lines of code, excluding empty lines and comments."""
    lines = code.split('\n')
    code_lines = 0
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#'):
            code_lines += 1
    return code_lines

def get_code_samples(num_samples=200, min_lines=1000, max_lines=1500, output_dir="data/source_files/"):
    """
    Load Python code samples from the codeparrot/github-code dataset.
    
    Args:
        num_samples: Number of samples to return
        output_dir: Directory to save the samples
        
    Returns:
        A list of file paths where samples were saved
    """
    print("Loading codeparrot/github-code dataset...")
    
    datasets = []
    
    for language in languages:
        output_dir = output_dir + language
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"Created directory: {output_dir}")
        
        # Load the dataset 
        ds = load_dataset(
            "codeparrot/github-code", 
            streaming=True, 
            split="train",
            trust_remote_code=True
        )
        
        # Filter for Python files only
        datasets.append(ds.filter(lambda x: x["language"] == language))
        
        saved_files = []
        count = 0
        print(f"Collecting {num_samples} {language} samples...")
        
        for item in datasets[-1]:
            code = item["code"]
            line_count = count_lines(code)
            # Filter by line count
            if line_count < min_lines:
                continue
            if line_count > max_lines:
                continue
            
            # Generate a unique filename using hash of content + timestamp
            code_hash = hashlib.md5(code.encode()).hexdigest()[:10]
            timestamp = int(time.time() * 1000) % 10000  # Add some time-based uniqueness
            filename = f"sample_{code_hash}_{timestamp}.{extensions.get(language)}"
            filepath = os.path.join(output_dir, filename)
            
            # Save the code to a file
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(code)
            
            saved_files.append(filepath)
            count += 1
            
            if count % 10 == 0:
                print(f"Collected and saved {count}/{num_samples} samples so far...")
            
            if count >= num_samples:
                break
        
        print(f"Successfully collected and saved {len(saved_files)} {language} samples to {output_dir}/")
        output_dir="data/source_files/"
    return saved_files

if __name__ == "__main__":
    saved_files = get_code_samples(1000)
    if saved_files:
        print(f"Total files saved: {len(saved_files)}")
        # print(f"First few files:")
        # for file in saved_files[:5]:
        #     print(f"  - {file}")
    else:
        print("No samples were collected. Please check your authentication.") 