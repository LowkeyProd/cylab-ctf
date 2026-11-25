import re
import zlib
import base64
from pathlib import Path

def solve():
    pdf_path = Path("Financial_Report_for_ABC_Labs.pdf")
    content = pdf_path.read_bytes()
    
    start_idx = content.find(b"stream")
    flag = ""
    if start_idx != -1:
        start_idx += len("stream")
        while content[start_idx:start_idx+1] in (b'\r', b'\n'):
            start_idx += 1
        end_idx = content.find(b"endstream", start_idx)
        stream_data = content[start_idx:end_idx].strip()
        
        if not stream_data.startswith(b'<~'):
            stream_data = b'<~' + stream_data
        if not stream_data.endswith(b'~>'):
            stream_data = stream_data + b'~>'
            
        decoded = base64.a85decode(stream_data, adobe=True)
        decompressed = zlib.decompress(decoded).decode('latin-1', errors='replace')
        
        match = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', decompressed)
        if match:
            flag = match.group(1)

    print(f"[*] Found flag: {flag}")
    if flag:
        Path("flag.txt").write_text(flag, encoding="utf-8")
        print("[+] Wrote flag to flag.txt")
    return flag

if __name__ == "__main__":
    solve()
