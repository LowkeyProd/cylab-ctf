# CyLab CTF Automation Tool

A command-line interface (CLI) tool designed for interacting with the CyLab Academy CTF platform (learn.cylabacademy.org). It automates challenge retrieval, session management, local workspace setup, and verification.

## Features

- Session Management: Handles authentication, session caching, and automated re-login.
- Challenge Synchronization: Fetches and categorizes challenges across Web, Forensics, Reverse Engineering, Cryptography, and General Skills.
- Workspace Organization: Automatically sets up organized local directories with challenge files and writeup templates.
- Automated Solvers: Modular solver scripts for common algorithmic, decoding, and cryptographic challenge patterns.
- Flag Submission: Verifies extracted flags and submits them to the platform directly from the terminal.

## Requirements

- Python 3.10+
- Dependencies:
  - curl_cffi
  - rich

Install dependencies:

```bash
pip install curl_cffi rich
```

## Setup & Usage

1. Clone the repository:

```bash
git clone https://github.com/LowkeyProd/cylab-ctf.git
cd cylab-ctf
```

2. Configure session:
Copy `.cylab_session.example.json` to `.cylab_session.json` and insert your session credentials:

```bash
cp .cylab_session.example.json .cylab_session.json
```

3. Run the tool:

```bash
python cylab_tool.py
```

## CLI Options

- `--help`: Display available command-line options and parameters.
- `--lang {vi,en}`: Select terminal interface language (Vietnamese or English).
- `--category <name>`: Filter challenges by category.
- `--writeups-only`: Filter for challenges with local writeups.
