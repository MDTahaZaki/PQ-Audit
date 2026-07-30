# PQ-Audit

**PQ-Audit** is a Post-Quantum Cryptography Migration Toolkit designed to scan GitHub repositories for classical cryptographic primitives and recommend NIST Post-Quantum Cryptography (PQC) replacements.

## The "Harvest Now, Decrypt Later" Threat Model

As quantum computers advance, classical cryptographic algorithms like RSA and ECC will become vulnerable to Shor's algorithm, threatening data security. Threat actors are currently engaging in "Harvest Now, Decrypt Later" (HNDL) attacks—stealing encrypted data today to decrypt it once quantum computers are sufficiently powerful. 

This toolkit proactively identifies vulnerable code paths within your organization's repositories. By mapping these vulnerabilities to NIST's standardized Post-Quantum Cryptography (PQC) algorithms, it accelerates the inevitable migration process and helps secure data against future quantum threats.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-org/PQ-Audit.git
   cd PQ-Audit
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the scanner by providing a target GitHub repository. You can supply the repository as `owner/repo` or as a full URL. For larger repositories, it is recommended to provide a GitHub Personal Access Token to avoid rate limits.

```bash
# Basic usage
python main.py owner/repo

# Secure Usage: Pass your GitHub Personal Access Token as an environment variable to avoid rate limits
# Windows (PowerShell):
$env:GITHUB_TOKEN="YOUR_GITHUB_TOKEN"
python main.py owner/repo

# Linux/macOS:
export GITHUB_TOKEN="YOUR_GITHUB_TOKEN"
python main.py owner/repo
```

### Output

The CLI provides a rich UI summary of the scan, including:
- Total files scanned
- Classical crypto instances found
- A Quantum Risk Score out of 100
- A detailed table of detected primitives, their risk level, and recommended PQC alternatives

Additionally, a JSON report is automatically exported to the `reports/` directory with a timestamp.
