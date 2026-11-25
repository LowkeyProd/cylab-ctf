#!/usr/bin/env python3
"""
Clean, self-contained solver for 'Gatekeeper' (#731)
Category: Reverse Engineering

Challenge Overview:
  The gatekeeper binary inspects user input:
  1. Checks if all characters are decimal digits -> parses with atoi().
     If so, since strlen(input) == 3, maximum value is 999.
  2. If non-decimal hex characters exist, parses with strtol(input, 16).
  3. Validates that 999 < value <= 9999 and strlen(input) == 3.
  4. Access is granted only for a 3-character hexadecimal string representing
     a value >= 1000 (e.g. 0x3e8 = 1000).

  Response Transformation:
  - The server emits the flag reversed and interleaved with 'ftc_oc_ip'
    injected at every 4th index.
  - Inverse transformation: remove 'ftc_oc_ip', then reverse the string.
"""
import re
import socket
import sys
import time
from pathlib import Path


def find_repo_root():
    """Locate workspace root to access shared helper tools if available."""
    curr = Path(__file__).resolve().parent
    for _ in range(6):
        if (curr / "cylab_tool.py").exists():
            return curr
        curr = curr.parent
    return None


repo_root = find_repo_root()
if repo_root and str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))


def load_connection_config():
    """Dynamically load target host and port from connection.cfg."""
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = None, None
    if cfg_file.exists():
        for line in cfg_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("HOST="):
                val = line.split("=", 1)[1].strip()
                if val:
                    host = val
            elif line.startswith("PORT="):
                val = line.split("=", 1)[1].strip()
                if val.isdigit() and int(val) > 0:
                    port = int(val)
    return host, port


def ensure_running_instance():
    """Ensure an instance is running via CyLabClient if network params are missing."""
    host, port = load_connection_config()
    if host and port:
        return host, port

    print("[*] Target endpoint not found in connection.cfg. Attempting platform sync...", flush=True)
    try:
        from cylab_tool import CyLabClient

        client = CyLabClient()
        if not client.login():
            print("[-] Platform login failed.", flush=True)
            return host, port

        # Check existing user status for running instances
        status = client.get_user_status()
        instances = status.get("instances", [])
        for inst in instances:
            if inst.get("challenge_id") != 731:
                print(f"[*] Stopping conflicting instance #{inst.get('challenge_id')}...", flush=True)
                client.stop_instance(inst.get("challenge_id"))
                time.sleep(1)

        print("[*] Deploying container instance for #731 (Gatekeeper)...", flush=True)
        client.deploy_instance(731)
        for _ in range(15):
            time.sleep(2)
            info = client.get_challenge_instance_info(731)
            if info and info.get("status") == "RUNNING":
                desc = info.get("description", "")
                m = re.search(r"nc\s+([a-zA-Z0-9\.\-]+)\s+(\d+)", desc)
                if m:
                    host = m.group(1)
                    port = int(m.group(2))
                    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
                    cfg_file.write_text(f"HOST={host}\nPORT={port}\nURL=nc {host} {port}\n", encoding="utf-8")
                    print(f"[+] Instance deployed: {host}:{port}", flush=True)
                    return host, port
    except Exception as e:
        print(f"[-] Auto-deploy helper unavailable: {e}", flush=True)

    return host, port


def synthesize_input_key() -> str:
    """
    Use Z3 SMT solver to find a 3-character hexadecimal string satisfying:
      1. len(key) == 3
      2. key characters in [0-9, a-f]
      3. At least one non-decimal hex character (ensuring hex parser is used)
      4. 999 < int(key, 16) <= 9999
    """
    try:
        import z3

        solver = z3.Solver()
        chars = [z3.BitVec(f"c_{i}", 16) for i in range(3)]
        val_parts = []
        is_hex_alphas = []

        for c in chars:
            is_digit = z3.And(c >= ord("0"), c <= ord("9"))
            is_hex_alpha = z3.And(c >= ord("a"), c <= ord("f"))
            solver.add(z3.Or(is_digit, is_hex_alpha))

            # Numerical value mapping
            val = z3.If(is_digit, c - ord("0"), c - ord("a") + 10)
            val_parts.append(val)
            is_hex_alphas.append(is_hex_alpha)

        # Enforce that the string contains at least one non-decimal character
        solver.add(z3.Or(*is_hex_alphas))

        # Enforce numerical range constraint
        total_val = val_parts[0] * 256 + val_parts[1] * 16 + val_parts[2]
        solver.add(total_val > 999)
        solver.add(total_val <= 9999)

        if solver.check() == z3.sat:
            model = solver.model()
            synthesized = "".join(chr(model[c].as_long()) for c in chars)
            val = int(synthesized, 16)
            print(f"[+] Z3 constraint solver found key: '{synthesized}' (0x{synthesized} = {val} > 999)", flush=True)
            return synthesized
    except Exception as e:
        print(f"[-] Z3 synthesis fallback: {e}", flush=True)

    # Deterministic fallback: '3e8' (0x3e8 = 1000 > 999)
    return "3e8"


def decode_transformed_flag(raw_response: str) -> str:
    """
    Invert the transformation applied by the binary:
      1. Extract payload after 'Access granted: '
      2. Strip all occurrences of the obfuscation token 'ftc_oc_ip'
      3. Reverse string to recover the original plaintext flag
    """
    print(f"[*] Raw response received: {raw_response.strip()}", flush=True)
    if "Access granted:" not in raw_response:
        print("[-] 'Access granted:' banner not found in response.", flush=True)
        return ""

    content = raw_response.split("Access granted:", 1)[1].strip()
    cleaned = content.replace("ftc_oc_ip", "")
    reversed_flag = cleaned[::-1].strip()
    print(f"[*] Reversed & cleaned output: {reversed_flag}", flush=True)

    m = re.search(r"academy\{[^}]+\}", reversed_flag)
    if m:
        return m.group(0)
    return reversed_flag


def solve():
    """Main solver entrypoint."""
    print("==================================================", flush=True)
    print("  Solving Gatekeeper (#731)", flush=True)
    print("==================================================", flush=True)

    # 1. Resolve connection parameters dynamically
    host, port = ensure_running_instance()
    if not host or not port:
        print("[-] Error: Unable to determine target HOST and PORT from connection.cfg or platform.", flush=True)
        return None

    print(f"[*] Target endpoint: {host}:{port}", flush=True)

    # 2. Synthesize valid input satisfying gatekeeper conditions
    key = synthesize_input_key()
    payload = f"{key}\n".encode("utf-8")
    print(f"[*] Prepared payload: {repr(payload)}", flush=True)

    # 3. Connect and exchange data with target
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10.0)
            print(f"[*] Connecting to {host}:{port}...", flush=True)
            s.connect((host, port))

            banner = s.recv(1024).decode(errors="ignore")
            print(f"[*] Prompt received: {banner.strip()}", flush=True)

            print(f"[*] Sending synthesized input '{key}'...", flush=True)
            s.sendall(payload)

            response = s.recv(4096).decode(errors="ignore")
    except Exception as e:
        print(f"[-] Connection or communication failed: {e}", flush=True)
        return None

    # 4. Invert response transformation
    flag = decode_transformed_flag(response)
    if flag:
        print(f"[+] Flag successfully recovered: {flag}", flush=True)
        out_flag = Path(__file__).resolve().parent / "flag.txt"
        out_flag.write_text(flag + "\n", encoding="utf-8")
        print(f"[+] Saved flag to {out_flag.name}", flush=True)
        return flag
    else:
        print("[-] Failed to extract flag from server response.", flush=True)
        return None


if __name__ == "__main__":
    solve()
