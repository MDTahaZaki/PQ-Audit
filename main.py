#!/usr/bin/env python3
"""
PQ-Audit: Post-Quantum Cryptography Migration Toolkit
Scans GitHub repositories for classical cryptographic primitives and recommends
NIST PQC replacements.

Why: As quantum computers advance, classical cryptographic algorithms like RSA and ECC will become vulnerable to Shor's algorithm, threatening data security. This toolkit is necessary to proactively identify vulnerable code paths within an organization's repositories without requiring deep cryptographic expertise from every developer. By mapping these vulnerabilities to NIST's standardized Post-Quantum Cryptography (PQC) algorithms, it accelerates the inevitable migration process.
"""

import argparse
import base64
import sys
import time
import json
import os
from datetime import datetime

if sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text

from scanner import TARGET_EXTS, parse_repo_url, get_headers, get_default_branch, fetch_tree, scan_content

console = Console()

def main():
    """
    Main entry point for the PQ-Audit CLI.
    
    Why: We need a centralized orchestrator to handle user inputs, manage GitHub API interactions, and aggregate the raw scanning data. Designing this as a command-line interface ensures it can be easily integrated into developer workflows or automated CI/CD pipelines. The use of rich UI elements guarantees that the dense cryptographic findings are presented in an accessible and visually digestible format.
    """
    parser = argparse.ArgumentParser(description="PQ-Audit: Post-Quantum Cryptography Migration Toolkit")
    parser.add_argument("repo", nargs="?", default=None, help="GitHub repository URL or 'owner/repo'")
    parser.add_argument("--repo", dest="repo_flag", help="GitHub repository URL or 'owner/repo'")
    parser.add_argument("--token", help="Optional GitHub Personal Access Token to avoid rate limits", default=None)
    
    args = parser.parse_args()
    
    token = args.token or os.environ.get("GITHUB_TOKEN")
    
    repo_input = args.repo_flag or args.repo
    if not repo_input:
        parser.error("the following arguments are required: repo or --repo")
        
    is_local = os.path.exists(repo_input)
    
    if is_local:
        repo_name = os.path.basename(os.path.normpath(repo_input))
        console.print(Panel(f"[bold cyan]PQ-Audit[/bold cyan] - Post-Quantum Cryptography Migration Toolkit\nTarget: [bold]Local: {repo_input}[/bold]", expand=False))
        
        target_files = []
        if os.path.isdir(repo_input):
            for root, _, files in os.walk(repo_input):
                for file in files:
                    if file.endswith(TARGET_EXTS):
                        file_path = os.path.join(root, file)
                        target_files.append({"path": file_path, "local": True})
        elif os.path.isfile(repo_input) and repo_input.endswith(TARGET_EXTS):
            target_files.append({"path": repo_input, "local": True})
            
        total_files = len(target_files)
    else:
        try:
            repo_name = parse_repo_url(repo_input)
        except ValueError as e:
            console.print(f"[bold red]{e}[/bold red]")
            sys.exit(1)
            
        headers = get_headers(token)
        
        console.print(Panel(f"[bold cyan]PQ-Audit[/bold cyan] - Post-Quantum Cryptography Migration Toolkit\nTarget: [bold]{repo_name}[/bold]", expand=False))
        
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
            progress.add_task(description=f"Fetching repo info for {repo_name}...", total=None)
            branch = get_default_branch(repo_name, headers)
            
            progress.add_task(description=f"Fetching tree for branch '{branch}'...", total=None)
            tree = fetch_tree(repo_name, branch, headers)
            
        target_files = [item for item in tree if item["type"] == "blob" and item["path"].endswith(TARGET_EXTS)]
        total_files = len(target_files)
    
    if total_files == 0:
        console.print(f"[yellow]No supported source files {TARGET_EXTS} found in the repository.[/yellow]")
        sys.exit(0)
        
    all_findings = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    ) as progress:
        scan_task = progress.add_task(f"Scanning {total_files} files...", total=total_files)
        
        for file_item in target_files:
            file_path = file_item["path"]
            
            if file_item.get("local"):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    findings = scan_content(content, file_path)
                    all_findings.extend(findings)
                except Exception:
                    pass
            else:
                url = file_item["url"]
                
                resp = requests.get(url, headers=headers)
                if resp.status_code == 200:
                    try:
                        content_b64 = resp.json().get("content", "")
                        content = base64.b64decode(content_b64).decode("utf-8", errors="ignore")
                        findings = scan_content(content, file_path)
                        all_findings.extend(findings)
                    except Exception:
                        pass
                elif resp.status_code == 403 and "rate limit" in resp.text.lower():
                    console.print("\n[bold red]GitHub API rate limit exceeded. Please use the --token flag.[/bold red]")
                    sys.exit(1)
                    
            progress.advance(scan_task)
            
    # Calculate Risk Score (Starts at 0, increases by severity)
    score = 0
    for f in all_findings:
        if "High Risk" in f["risk"]:
            score += 10
        elif "Medium Risk" in f["risk"]:
            score += 5
    score = min(100, score)
    
    # Display Summary Banner
    score_color = "green"
    if score > 50:
        score_color = "red"
    elif score > 20:
        score_color = "yellow"
        
    summary_text = (
        f"Files Scanned: [bold]{total_files}[/bold]\n"
        f"Classical Crypto Instances Found: [bold]{len(all_findings)}[/bold]\n"
        f"Quantum Risk Score: [bold {score_color}]{score}/100[/bold {score_color}]"
    )
    console.print("\n")
    console.print(Panel(summary_text, title="[bold]Scan Summary[/bold]", border_style="blue", expand=False))
    
    # Display Results Table
    if all_findings:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("File Path", style="dim", overflow="fold")
        table.add_column("Line #", justify="right")
        table.add_column("Detected Primitive", style="cyan")
        table.add_column("Quantum Risk Level", style="red")
        table.add_column("Recommended PQC Alternative", style="green")
        
        for f in all_findings:
            risk_text = Text(f["risk"])
            if "High" in f["risk"]:
                risk_text.stylize("bold red")
            elif "Medium" in f["risk"]:
                risk_text.stylize("bold yellow")
                
            table.add_row(
                f["file"],
                f["line"],
                f["primitive"],
                risk_text,
                f["recommendation"]
            )
            
        console.print(table)
    else:
        console.print("\n[bold green]No classical cryptographic primitives found! This repository might be quantum-safe.[/bold green]")

    # Export scan findings as JSON
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join("reports", f"scan_results_{timestamp}.json")
    
    report_data = {
        "repository": repo_name,
        "files_scanned": total_files,
        "instances_found": len(all_findings),
        "quantum_risk_score": score,
        "findings": all_findings
    }
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=4)
        
    console.print(f"\n[bold green]Scan results exported to {report_path}[/bold green]")

if __name__ == "__main__":
    main()
