# Code Vulnerability Detection

This project automates the process of **collecting source code, mapping vulnerabilities (CWEs), and injecting them** into source files for testing and benchmarking security tools.

---

##  Project Structure

```
code_vuln/
 ├── .env                        # Environment variables (ignored in GitHub)
 ├── .gitignore                  # Git ignore rules
 ├── 1_get_source_codeparrot.py  # Script to collect source code samples
 ├── 2_generate_cwe_mappings.py  # Script to map source files to CWE vulnerabilities
 ├── 3_inject_vulnerabilities.py # Script to inject vulnerabilities into source code
 ├── README.md                   # Project documentation
 ├── requirements.txt            # Python dependencies (if present)
 └── data/
     ├── cwe_top25_2024.json     # Top 25 CWEs reference
     ├── cwe_mapping/            # Stores mapping results
     ├── source_files/           # Original clean source code (per language)
     │   ├── C/
     │   ├── C++/
     │   ├── GO/
     │   ├── Java/
     │   ├── JavaScript/
     │   └── Python/
     └── vulnerable_files/       # Output files with injected vulnerabilities
``` 

---

**Run the pipeline**

```bash
python 1_get_source_codeparrot.py
python 2_generate_cwe_mappings.py
python 3_inject_vulnerabilities.py
```

Outputs (vulnerable files and mappings) will be placed under `data/vulnerable_files/` and `data/cwe_mapping/` respectively.

---

## Scripts Overview

* `1_get_source_codeparrot.py` — Collects and organizes source files into `data/source_files/`.
* `2_generate_cwe_mappings.py` — Uses heuristics/ML to map source files to likely CWE categories and writes mapping outputs to `data/cwe_mapping/`.
* `3_inject_vulnerabilities.py` — Injects vulnerability patterns into selected source files and writes results into `data/vulnerable_files/`.

---
