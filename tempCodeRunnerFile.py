import pyshark
from pyad import adimage

def detect_cryptomining_traffic(pcap_file):
    cap = pyshark.FileCapture(pcap_file)
    suspicious_ips = []

    for packet in cap:
        try:
            if 'http' in packet:
                if any(keyword in packet.http.request_full_uri for keyword in ['mining', 'cryptominer']):
                    suspicious_ips.append(packet.ip.dst)
        except AttributeError:
            continue

    return suspicious_ips

def extract_cryptomining_evidence(image_file):
    evidence = []
    img = adimage.Adiso(image_file)
    for entry in img.entries:
        if any(keyword in entry.name.lower() for keyword in ["mining", "cryptominer"]):
            evidence.append(entry.name)

    return evidence

suspicious_ips = detect_cryptomining_traffic("wiresharkReport.pcap")
print("suspicious ips:", suspicious_ips)

evidence = extract_cryptomining_evidence("edgeReport.ad1")
print("evidence of cryptomining:", evidence)
