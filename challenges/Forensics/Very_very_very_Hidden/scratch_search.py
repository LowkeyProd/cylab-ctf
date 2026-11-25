import re
import sys

with open('try_me.pcap', 'rb') as f:
    data = f.read()

urls = re.findall(rb'https?://[a-zA-Z0-9_\-\./\?=%&+:;]+', data)
for u in sorted(set(urls)):
    try:
        print(u.decode('ascii'))
    except Exception:
        pass
