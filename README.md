# CyLab CTF Automation Tool

A command-line interface (CLI) and automation suite designed for interacting with the CyLab Academy CTF platform (learn.cylabacademy.org). It streamlines challenge synchronization, dynamic instance deployment, automated solving, flag submission, and writeup documentation generation.

## Features

- Session & Platform Access: Cloudflare bypass via curl_cffi Chrome impersonation, session credential caching, and automated re-authentication.
- Challenge Discovery & Synchronization: Multi-threaded crawling across all categories (Web, Forensics, Reverse Engineering, Cryptography, Pwn, General Skills) with on-demand instance detection and solve tracking.
- Workspace Organization: Automatically structures dedicated challenge directories with downloaded files, attachments, and solver scripts.
- Automated Writeup Generation: Automatically compiles structured WRITEUP.md documentation upon solving a challenge, complete with challenge metadata, problem overview, hints, technical deep-dive, exploit source code, and verified flag logs.
- Dynamic Instance Lifecycle: Automates starting and stopping remote container instances, extracting connection details (host, port, netcat, URL) directly into solver scripts.
- Heuristic & Batch Solvers: Built-in solvers for common CTF patterns (RSA attacks, PCAP TLS extraction, audio steganography, ZIP timestamps, CRIME compression, PoW), with single-target or multi-worker batch execution modes.
- Flag Submission & Verification: Automated regex flag parsing from exploit outputs with instant platform submission and verification.
- Writeup Scanner & Flag Classifier: Scans local solved challenges to classify static vs dynamic flags, enabling batch submission workflows.
- Workspace Sanitization & Exfil Protocol: Built-in cleanup utility to purge heavy binaries and temporary files while preserving writeups and solve scripts, plus an emergency exfiltration (exfil) command for immediate process shutdown and cleanup.
- Bilingual Terminal Interface: Supports both English and Vietnamese terminal output.

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

2. Configure session credentials:
Copy `.cylab_session.example.json` to `.cylab_session.json` and insert your credentials:

```bash
cp .cylab_session.example.json .cylab_session.json
```

3. Launch the interactive menu:

```bash
python cylab_tool.py
```

## CLI Reference

The tool can be run interactively or automated via command-line arguments:

- `--crawl`: Crawl all challenges and metadata from the platform.
- `--category <name>`: Filter operations by category.
- `--stats`: Display challenge completion statistics.
- `--list`: List challenges with optional filters.
- `--search <keyword>`: Search challenges by title or ID.
- `--unsolved`: Filter listing or batch execution to unsolved challenges.
- `--instance-only`: Filter to instance-based challenges.
- `--difficulty <level>`: Filter challenges by difficulty (1/easy, 2/medium, 3/hard).
- `--select <id>`: Deploy instance, download attachments, and prepare challenge workspace.
- `--solve <id>`: Run automated solver pipeline against a specific challenge.
- `--batch`: Batch solve filtered challenges.
- `--dual`: Run batch solver using dual workers (1 instance + 1 static concurrently).
- `--auto-solve`: Launch interactive batch solver selector.
- `--submit <id> <flag>`: Manually submit a flag for a challenge.
- `--stop <id>`: Stop a running remote container instance.
- `--scan-writeups`: Scan local writeups and classify static vs dynamic flags.
- `--writeups-only`: Limit batch execution to challenges with existing local writeups.
- `--cleanup`: Clean up solved challenge directories by removing heavy artifacts while retaining solve scripts and writeups.
- `--quota`: Display solver engine quota and account status.
- `--force-login`: Force re-authentication.
