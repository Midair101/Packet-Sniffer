from scapy.all import IP, TCP, UDP, Raw
from network_spy import detect_unencrypted


def make_pkt(ip_src, ip_dst, sport, dport, payload, proto='TCP'):
    pkt = IP(src=ip_src, dst=ip_dst)
    if proto == 'TCP':
        pkt = pkt / TCP(sport=sport, dport=dport) / Raw(load=payload)
    else:
        pkt = pkt / UDP(sport=sport, dport=dport) / Raw(load=payload)
    return pkt


def test_http_detects_plaintext():
    p = make_pkt('192.168.1.2','93.184.216.34', 12345, 80, b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n')
    unenc, reason = detect_unencrypted(p)
    assert unenc and 'http' in reason


def test_tls_like_not_flagged():
    p = make_pkt('1.1.1.1', '2.2.2.2', 23456, 443, b'\x16\x03\x01\x02\x00randombinary')
    unenc, reason = detect_unencrypted(p)
    assert not unenc


def test_sensitive_in_plaintext():
    p = make_pkt('10.0.0.1','10.0.0.2', 3333, 4444, b'email=user@example.com&cc=4111 1111 1111 1111')
    unenc, reason = detect_unencrypted(p)
    assert unenc and 'sensitive' in reason
