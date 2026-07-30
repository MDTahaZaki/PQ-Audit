import sys
import requests
from rich.console import Console
from rules import RULES

console = Console()

TARGET_EXTS = ('.py', '.js', '.go', '.java', '.cpp', '.rs', '.pem')

def parse_repo_url(url):
    """Parse GitHub URL or string into 'owner/repo' format."""
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    if "github.com/" in url:
        parts = url.split("github.com/")[-1].split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
    parts = url.split("/")
    if len(parts) == 2:
        return url
    raise ValueError("Invalid GitHub repository format. Use 'owner/repo' or a GitHub URL (e.g., https://github.com/owner/repo).")

def get_headers(token):
    """Return appropriate request headers for GitHub API."""
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    return headers

def get_default_branch(repo, headers):
    """Fetch the default branch of the repository."""
    url = f"https://api.github.com/repos/{repo}"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        console.print(f"[bold red]Error fetching repo info for {repo}:[/bold red] {resp.json().get('message', resp.text)}")
        sys.exit(1)
    return resp.json().get("default_branch", "main")

def fetch_tree(repo, branch, headers):
    """Fetch the full file tree of the repository."""
    url = f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        console.print(f"[bold red]Error fetching tree for {repo}:[/bold red] {resp.json().get('message', resp.text)}")
        sys.exit(1)
    return resp.json().get("tree", [])

def scan_content(content, path):
    """Scan file content line by line using predefined regex rules.
    
    Why: Evaluating raw source code via static analysis allows us to catch cryptographic implementations before they are compiled or deployed. We use line-by-line regex scanning because it is language-agnostic and fast enough to run against massive codebases in real-time. This provides immediate, actionable feedback pinpointing the exact line where a vulnerable primitive is instantiated.
    """
    matches = []
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        for rule in RULES:
            if rule["pattern"].search(line):
                matches.append({
                    "file": path,
                    "line": str(i),
                    "primitive": rule["name"],
                    "risk": rule["risk"],
                    "recommendation": rule["recommendation"]
                })
    return matches
