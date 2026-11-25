from scapy.all import rdpcap, IP, TCP, UDP, DNS
import datetime

packets = rdpcap('try_me.pcap')
print(f"Total packets: {len(packets)}")

start_time = packets[0].time
print(f"Start time: {start_time}")

events = []

for i, p in enumerate(packets):
    t = float(p.time - start_time)
    if p.haslayer(DNS) and p[DNS].qd:
        qr = p[DNS].qd
        if hasattr(qr, 'qname'):
            events.append((t, f"Packet {i} DNS query: {qr.qname.decode('latin1', errors='ignore')} (type {qr.qtype})"))
    elif TCP in p and p.haslayer('Raw'):
        raw = bytes(p['Raw'])
        if raw.startswith(b'GET ') or raw.startswith(b'POST ') or raw.startswith(b'HTTP/'):
            line = raw.split(b'\r\n')[0].decode('latin1', errors='ignore')
            events.append((t, f"Packet {i} HTTP {p[IP].src}:{p[TCP].sport}->{p[IP].dst}:{p[TCP].dport}: {line}"))
        elif b'powershell' in raw.lower():
            events.append((t, f"Packet {i} TCP powershell mention: {p[IP].src}->{p[IP].dst}"))

for t, desc in events[:100]:
    print(f"[{t:7.2f}s] {desc}")

print(f"Total interesting events: {len(events)}")
