from scapy.all import PcapReader, DNS

queries = []
with PcapReader('try_me.pcap') as pcap:
    for i, pkt in enumerate(pcap):
        if pkt.haslayer(DNS):
            qr = pkt[DNS].qd
            if qr and hasattr(qr, 'qname'):
                name = qr.qname.decode('latin1', errors='ignore')
                qtype = qr.qtype
                queries.append((i, name, qtype))

for idx, name, qtype in queries:
    print(f"{idx}: (type {qtype}) {name}")
