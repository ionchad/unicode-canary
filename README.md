# unicode-canary 🐦

> Detect invisible Unicode threats in source code before they execute.

Scans codebases for **Trojan Source** (CVE-2021-42574), **Zero-Width payloads**, 
**AI Prompt Injection**, and **Homoglyph** attacks, the exact techniques used in 
the [Glassworm](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode) 
supply chain attack that hit 150+ GitHub repositories in March 2026.

## Why This Exists

These invisible characters are undetectable by the human eye in:
- GitHub code review diffs
- VS Code (without special extensions)  
- Terminal output
- Any standard text editor

Compilers and runtimes execute them anyway.

## Installation

```bash
git clone https://github.com/ionchad/unicode-canary
cd unicode-canary
pip install -r requirements.txt
```

## Usage

```bash
# Scan a directory
python cli.py scan ./myproject

# Scan a single file  
python cli.py scan ./app.py

# Run the built-in demo
python cli.py demo

# Only scan specific extensions
python cli.py scan . --ext .py --ext .js
```

## Use Cases

- Pre-commit hook to block infected commits
- CI/CD pipeline security step
- Code review assistant  
- Supply chain security audit
- Incident response after suspicious package installs

When adding new Unicode attack patterns, add them to `unicode_canary/patterns.py` and write a test in `tests/test_scanner.py`.

- [Trojan Source Paper (Cambridge)](https://trojansource.codes)
- [Glassworm Attack Analysis (Aikido)](https://www.aikido.dev/blog/glassworm-returns-unicode-attack-github-npm-vscode)
- [CVE-2021-42574](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-42574)
