from scapy.all import PcapReader, IP, UDP

queries = []
with PcapReader('try_me.pcap') as pcap:
    for i, pkt in enumerate(pcap):
        if pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            if dport in (53, 5353, 5355, 137) or sport in (53, 5353, 5355, 137):
                raw = bytes(pkt[UDP].payload)
                queries.append((i, sport, dport, raw[:50]))

print(f"Total UDP query packets: {len(queries)}")
for q in queries[:20]:
    print(q)
