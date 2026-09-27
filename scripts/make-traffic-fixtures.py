# Builds tests/fixtures/traffic/*.pcap(ng): small, synthetic captures that exercise every analyzer
# rule. Only documentation / private addresses are used (RFC 5737 TEST-NET for "internet" hosts).
# Usage: python3 scripts/make-traffic-fixtures.py   (needs scapy)
from scapy.all import (ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap, wrpcapng)
import os, struct

def tls_record(hs_type, body):
    hs = bytes([hs_type]) + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + struct.pack('>H', len(hs)) + hs

def client_hello(sni):
    name = sni.encode()
    sni_ext = struct.pack('>HHHBH', 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    exts = sni_ext
    body = b'\x03\x03' + b'\x11' * 32 + b'\x00' + struct.pack('>H', 2) + b'\x13\x01' + b'\x01\x00' + struct.pack('>H', len(exts)) + exts
    return tls_record(1, body)

def server_hello(version):
    body = struct.pack('>H', version) + b'\x22' * 32 + b'\x00' + b'\x00\x2f' + b'\x00' + struct.pack('>H', 0)
    return tls_record(2, body)

OUT = os.path.join(os.path.dirname(__file__), '..', 'tests', 'fixtures', 'traffic')
PC = '3c:2e:ff:11:22:33'      # Apple
PHONE = 'da:a1:19:44:55:66'   # random (private) Wi-Fi address
ROUTER = 'b8:27:eb:aa:bb:cc'  # Raspberry Pi as the "router"
ROGUE = '00:15:5d:de:ad:01'   # Microsoft Hyper-V
PUB = '198.51.100.7'          # TEST-NET-2, stands in for an internet server
PUB2 = '203.0.113.9'          # TEST-NET-3
t = [1_700_000_000.0]
def ts(p):
    t[0] += 0.01
    p.time = t[0]
    return p

pk = []
# DNS: query + answer, and a burst of NXDOMAIN answers to the phone (DGA-like pattern).
pk.append(ts(Ether(src=PC, dst=ROUTER) / IP(src='192.168.1.10', dst='192.168.1.1') / UDP(sport=53001, dport=53) / DNS(id=1, rd=1, qd=DNSQR(qname='example.org'))))
pk.append(ts(Ether(src=ROUTER, dst=PC) / IP(src='192.168.1.1', dst='192.168.1.10') / UDP(sport=53, dport=53001) / DNS(id=1, qr=1, qd=DNSQR(qname='example.org'), an=DNSRR(rrname='example.org', rdata=PUB))))
for i in range(45):
    name = f'x{i:02d}qzt.example'
    pk.append(ts(Ether(src=PHONE, dst=ROUTER) / IP(src='192.168.1.20', dst='192.168.1.1') / UDP(sport=40000 + i, dport=53) / DNS(id=100 + i, rd=1, qd=DNSQR(qname=name))))
    pk.append(ts(Ether(src=ROUTER, dst=PHONE) / IP(src='192.168.1.1', dst='192.168.1.20') / UDP(sport=53, dport=40000 + i) / DNS(id=100 + i, qr=1, rcode=3, qd=DNSQR(qname=name))))
# TLS ClientHello with SNI, and a ServerHello negotiating TLS 1.0 (weak).
pk.append(ts(Ether(src=PC, dst=ROUTER) / IP(src='192.168.1.10', dst=PUB) / TCP(sport=50000, dport=443, flags='PA') / Raw(client_hello('example.org'))))
pk.append(ts(Ether(src=ROUTER, dst=PC) / IP(src=PUB, dst='192.168.1.10') / TCP(sport=443, dport=50000, flags='PA') / Raw(server_hello(0x0301))))
# Plain HTTP with a secret cookie, auth header and query token — none may appear in the report.
http = b'GET /login?token=SECRET123 HTTP/1.1\r\nHost: plain.example\r\nUser-Agent: TestAgent/1.0\r\nCookie: session=SECRETCOOKIE\r\nAuthorization: Basic U0VDUkVU\r\n\r\n'
pk.append(ts(Ether(src=PC, dst=ROUTER) / IP(src='192.168.1.10', dst=PUB2) / TCP(sport=50001, dport=80, flags='PA') / Raw(http)))
# FTP banner (cleartext login protocol).
pk.append(ts(Ether(src=ROUTER, dst=PC) / IP(src=PUB2, dst='192.168.1.10') / TCP(sport=21, dport=50002, flags='PA') / Raw(b'220 Welcome FTP\r\n')))
# DHCP: offers from two different servers (the second one is rogue); DHCP host name of the phone.
for srv, mac in (('192.168.1.1', ROUTER), ('192.168.1.66', ROGUE)):
    pk.append(ts(Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / IP(src=srv, dst='255.255.255.255') / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr='192.168.1.20', chaddr=bytes.fromhex(PHONE.replace(':', '')) + b'\0' * 10) / DHCP(options=[('message-type', 'offer'), ('server_id', srv), 'end'])))
pk.append(ts(Ether(src=PHONE, dst='ff:ff:ff:ff:ff:ff') / IP(src='0.0.0.0', dst='255.255.255.255') / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=bytes.fromhex(PHONE.replace(':', '')) + b'\0' * 10) / DHCP(options=[('message-type', 'request'), ('hostname', b'Sara-iPhone'), 'end'])))
# ARP: the router's address claimed by a second MAC (ARP spoofing / IP conflict pattern).
pk.append(ts(Ether(src=ROUTER, dst=PC) / ARP(op=2, hwsrc=ROUTER, psrc='192.168.1.1', hwdst=PC, pdst='192.168.1.10')))
pk.append(ts(Ether(src=ROGUE, dst=PC) / ARP(op=2, hwsrc=ROGUE, psrc='192.168.1.1', hwdst=PC, pdst='192.168.1.10')))
# Port-scan pattern: one host SYNs 30 ports on another.
for port in range(20, 50):
    pk.append(ts(Ether(src=ROGUE, dst=PC) / IP(src='192.168.1.66', dst='192.168.1.10') / TCP(sport=41000, dport=port, flags='S')))
# Inbound RDP attempt from the internet that was answered (exposed service).
pk.append(ts(Ether(src=ROUTER, dst=PC) / IP(src=PUB2, dst='192.168.1.10') / TCP(sport=51000, dport=3389, flags='S')))
pk.append(ts(Ether(src=PC, dst=ROUTER) / IP(src='192.168.1.10', dst=PUB2) / TCP(sport=3389, dport=51000, flags='SA')))

os.makedirs(OUT, exist_ok=True)
wrpcap(os.path.join(OUT, 'sample.pcap'), pk)
wrpcapng(os.path.join(OUT, 'sample.pcapng'), pk)
print(len(pk), 'packets')
