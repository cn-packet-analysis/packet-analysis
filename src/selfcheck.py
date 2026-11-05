"""네트워크·권한 없이 고정 프레임·경계·출력·필터를 자체 점검한다."""
import io, re, socket, struct, types
from contextlib import redirect_stdout, redirect_stderr
import output
from parse import parse
SRC, DST = "aabbccddeeff", "112233445566"
MAC = re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b")
def eth(etype, body):
    return struct.pack("!6s6sH", bytes.fromhex(DST), bytes.fromhex(SRC), etype) + body
def ip4(proto, body, flags=0, frag=0, ihl=5, tlen=None, opts=b"", pad=b""):
    tlen = ihl * 4 + len(body) if tlen is None else tlen
    return eth(0x0800, struct.pack(
        "!BBHHHBBH4s4s", 0x40 | ihl, 0, tlen, 0x1c46, (flags << 13) | frag, 64, proto, 0,
        socket.inet_aton("192.168.0.5"), socket.inet_aton("8.8.8.8")) + opts + body + pad)
def arp(op=1, htype=1, ptype=0x0800, hlen=6, plen=4, cut=0):
    body = struct.pack("!HHBBH6s4s6s4s", htype, ptype, hlen, plen, op, bytes.fromhex(SRC),
                       socket.inet_aton("192.168.0.5"), b"\x00" * 6,
                       socket.inet_aton("192.168.0.1"))
    return eth(0x0806, body[:len(body) - cut])
def tcp(sport=52134, dport=80, flags=0x02, off=5, body=b"", ack=0):
    return struct.pack("!HHIIBBHHH", sport, dport, 1234567, ack, off << 4, flags, 64240, 0, 0) + body
def udp(body, sport=51000, dport=53, ulen=None):
    return struct.pack("!HHHH", sport, dport, 8 + len(body) if ulen is None else ulen, 0) + body
def dns(qname=b"\x07example\x03com\x00", qd=1, tail=b"\x00\x01\x00\x01"):
    return struct.pack("!6H", 0x1234, 0x0100, qd, 0, 0, 0) + qname + tail
ICMP_ECHO = ip4(1, struct.pack("!BBH", 8, 0, 0) + b"\x00\x01\x00\x01")
TCP_SYN = ip4(6, tcp())
DNS_QUERY = ip4(17, udp(dns()))
ARP_REQ = arp()
TRUNCATED = eth(0x0800, b"\x45\x00\x00\x1c\x00\x00")     # Ethernet 직후 잘린 IPv4
KEYS = {"eth": "src dst type",
        "ipv4": "src dst ihl tos len id flags frag_off ttl proto csum",
        "arp": "htype ptype hlen plen opcode sha tha spa tpa",
        "tcp": "sport dport seq ack off flags win csum urp",
        "udp": "sport dport len csum", "icmp": "type code csum", "http": "line",
        "dns": "id flags qdcount ancount nscount arcount qname qtype answers wire", "tls": "note"}
def ok(frame, layers):
    p = parse(0.0, frame)
    assert p["error"] is None, p["error"]
    assert p["layers"] == layers, (p["layers"], layers)
    for k in layers:
        assert set(KEYS[k].split()) <= p[k].keys(), (k, sorted(p[k]))
    return p
def err(frame, layers):
    p = parse(0.0, frame)
    assert p["error"], layers
    assert p["layers"] == layers, (p["layers"], layers)
    assert layers[-1] not in p, layers
    return p
def run():
    a = ok(ARP_REQ, ["eth", "arp"])["arp"]
    assert a["opcode"] == 1 and a["sha"] == "aa:bb:cc:dd:ee:ff" and a["tha"] == "00:00:00:00:00:00"
    assert a["spa"] == "192.168.0.5" and a["tpa"] == "192.168.0.1"
    buf = io.StringIO()
    with redirect_stdout(buf):
        output.show(parse(0.0, ARP_REQ))
    line = buf.getvalue().rstrip("\n")
    assert "\n" not in line and len(MAC.findall(line)) == 2, line
    err(arp(htype=6), ["eth", "arp"])                    # 미지원 하드웨어 조합
    err(arp(ptype=0x86DD), ["eth", "arp"])
    err(arp(cut=1), ["eth", "arp"])                      # 지원 조합인데 28B 미만
    i = ok(ICMP_ECHO, ["eth", "ipv4", "icmp"])["ipv4"]
    assert (i["src"], i["dst"]) == ("192.168.0.5", "8.8.8.8")
    assert (i["ihl"], i["ttl"], i["proto"], i["len"]) == (5, 64, 1, 28)
    err(TRUNCATED, ["eth", "ipv4"])
    err(ip4(1, b"", ihl=4), ["eth", "ipv4"])             # IHL < 5
    err(ip4(1, b"\x08\x00\x00\x00", ihl=6), ["eth", "ipv4"])   # 옵션 길이 부족
    err(ip4(1, b"\x08\x00\x00\x00", tlen=8), ["eth", "ipv4"])  # total_len < IHL*4
    err(ip4(1, b"\x08\x00\x00\x00", tlen=999), ["eth", "ipv4"])  # total_len > 실제 길이
    for frag in (ip4(6, tcp(), flags=1), ip4(6, tcp(), frag=185)):
        assert "tcp" not in ok(frag, ["eth", "ipv4"])    # MF=1 / 후속 단편 → IPv4까지만
    p = parse(0.0, ip4(1, struct.pack("!BBH", 8, 0, 0) + b"\x00\x01", pad=b"\x00" * 18))
    assert p["payload"] == b"\x00\x01", p["payload"]     # Ethernet padding이 섞이지 않는다
    p = ok(TCP_SYN, ["eth", "ipv4", "tcp"])
    t = p["tcp"]
    assert t["flags"] == ["SYN"] and (t["sport"], t["dport"]) == (52134, 80)
    assert (t["off"], t["win"], t["seq"]) == (5, 64240, 1234567)
    assert "http" not in p and "dns" not in p            # 빈 payload → 상위 파서 호출 안 함
    assert ok(ICMP_ECHO, ["eth", "ipv4", "icmp"])["icmp"]["type"] == 8
    err(ip4(6, tcp(off=4)), ["eth", "ipv4", "tcp"])      # off < 5
    err(ip4(6, tcp(off=8)), ["eth", "ipv4", "tcp"])      # 옵션 잘림
    err(ip4(17, udp(b"", ulen=4)), ["eth", "ipv4", "udp"])       # len < 8
    err(ip4(17, udp(b"xx", ulen=99)), ["eth", "ipv4", "udp"])    # len > 실제
    err(ip4(1, b"\x08\x00"), ["eth", "ipv4", "icmp"])            # ICMP < 4B
    d = ok(DNS_QUERY, ["eth", "ipv4", "udp", "dns"])["dns"]
    assert d["qname"] == "example.com" and d["qtype"] == 1
    assert (d["id"], d["qdcount"], d["ancount"]) == (0x1234, 1, 0)
    assert bytes.fromhex(d["wire"]) == dns()
    question = dns()[12:]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("1.2.3.4")
    response = struct.pack("!6H", 0x1234, 0x8180, 1, 2, 0, 0) + question + answer + answer[:-4] + b"\x05\x06\x07\x08"
    p = ok(ip4(17, udp(response)), ["eth", "ipv4", "udp", "dns"])
    assert p["dns"]["answers"] == ["1.2.3.4", "5.6.7.8"]
    assert response.hex() in output.detail(p) and response.hex() not in output.summary(p)
    assert all("answers=1.2.3.4,5.6.7.8" in s for s in (output.summary(p), output.detail(p)))
    for bad in (response[:-1], response[:-10], response[:-len(answer)]):
        err(ip4(17, udp(bad)), ["eth", "ipv4", "udp", "dns"])
    t = parse(0.0, ip4(6, tcp(ack=7654321)))
    assert "ack=7654321" in output.detail(t)
    p = parse(0.0, ip4(17, udp(dns(qname=b"", qd=0, tail=b""))))
    assert p["dns"]["qname"] is None and p["dns"]["qtype"] is None       # qdcount=0
    ptr = struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\xc0\x12\x00\x01\x00\x01\x07example\x03com\x00"
    p = parse(0.0, ip4(17, udp(ptr)))
    assert p["dns"]["qname"] == "example.com", p["dns"]              # 정상 압축 포인터
    err(ip4(17, udp(dns(qname=b"\xc0\x0c", tail=b"\x00\x01\x00\x01"))), ["eth", "ipv4", "udp", "dns"])
    err(ip4(17, udp(dns(qname=b"\xc0\xff", tail=b"\x00\x01\x00\x01"))), ["eth", "ipv4", "udp", "dns"])
    err(ip4(17, udp(dns(qname=b"\x07exam", tail=b""))), ["eth", "ipv4", "udp", "dns"])
    err(ip4(17, udp(b"\x00" * 8)), ["eth", "ipv4", "udp", "dns"])    # DNS 12B 미만
    ok(ip4(6, tcp(dport=53, body=b"\x00\x1cxx")), ["eth", "ipv4", "tcp"])  # TCP 53은 TCP에서 중단
    p = ok(ip4(6, tcp(dport=80, body=b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")),
           ["eth", "ipv4", "tcp", "http"])
    assert p["http"]["line"] == "GET /index.html HTTP/1.1", p["http"]
    p = parse(0.0, ip4(6, tcp(dport=80, body=b"GET /a\rHTTP\x00\n")))
    assert "\n" not in p["http"]["line"] and "\\r" in p["http"]["line"]   # 제어 문자 이스케이프
    assert ok(ip4(6, tcp(dport=443, body=b"\x16\x03\x01")),
              ["eth", "ipv4", "tcp", "tls"])["tls"] == {"note": "encrypted"}
    for frame, expected in (
        (ip4(6, tcp(body=b"GET / HTTP/1.1\r\n")), "HTTP GET / HTTP/1.1"),
        (DNS_QUERY, "example.com  qtype=1"),
        (ip4(17, udp(dns(qname=b"\x03a\nb\x00"))), r"a\nb"),
        (ip4(6, tcp(dport=443, body=b"x")), "TLS encrypted"),
        (ip4(6, tcp(dport=123, body=bytes(range(20)))), "hex=" + bytes(range(16)).hex())):
        p = parse(0.0, frame)
        s, d = output.summary(p), output.detail(p)
        assert expected in s and "\n" not in s, s
        assert " ".join(expected.split()) in " ".join(d.replace("[", "").replace("]", "").split())
    f = output.summary(parse(0.0, TCP_SYN)).split()
    assert (f[1], f[3], f[5]) == ("IPv4", "→", "TCP") and f[2].endswith(":52134") and f[4].endswith(":80")
    assert output.summary(parse(0.0, ICMP_ECHO)).split()[5] == "ICMP"
    assert output.summary(parse(0.0, ARP_REQ)).split()[5] == "request"
    assert output.summary(parse(0.0, ip4(6, tcp(), flags=1))).split()[5] == "frag"
    assert output.summary(parse(0.0, eth(0x86DD, b"x" * 60))).split()[5] == "type=0x86dd"
    e = output.summary(parse(0.0, TRUNCATED)).split()
    assert e[1] == "other" and e[5] == "malformed=ipv4" and len(e) == 6
    d2 = output.detail(parse(0.0, TCP_SYN)).splitlines()
    g = d2[1].replace("ttl=", "").replace("proto=", "").split()
    assert g[0] == "[IPv4]" and (g[1], g[3], g[4], g[5]) == ("192.168.0.5", "8.8.8.8", "64", "6")
    h = d2[2].split()
    assert h[0] == "[TCP]" and (h[1], h[3]) == ("52134", "80")
    for verbose in (False, True):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            output.show(parse(0.0, TRUNCATED), verbose)
        assert "truncated" not in stdout.getvalue() and stderr.getvalue() == "[ERROR] ipv4: truncated\n"
    opts = types.SimpleNamespace(proto=None, host=None, port=None)
    frames = [TCP_SYN, ICMP_ECHO, ARP_REQ, DNS_QUERY, TRUNCATED, ip4(6, tcp(sport=22))]
    stats = output.Stats()
    with redirect_stdout(io.StringIO()) as buf, redirect_stderr(io.StringIO()):
        for f in frames:
            p = parse(0.0, f)
            if output.match(p, opts):
                stats.add(p)
                output.show(p)
    assert stats.captured == 5 and stats.n["tcp"] == 1, stats.n        # 22번 포트 기본 제외
    assert (stats.n["icmp"], stats.n["arp"], stats.n["udp"], stats.n["other"]) == (1, 1, 1, 1)
    assert len(buf.getvalue().splitlines()) == 5                       # 패킷당 정확히 한 줄
    opts.proto = "tcp"
    assert output.match(parse(0.0, ip4(6, tcp(sport=1))), opts)
    assert not output.match(parse(0.0, ICMP_ECHO), opts)
    opts.proto, opts.host = None, "192.168.0.1"
    assert output.match(parse(0.0, ARP_REQ), opts)                     # ARP tpa
    opts.host, opts.port = None, 80
    assert output.match(parse(0.0, TCP_SYN), opts)
    assert not output.match(parse(0.0, ICMP_ECHO), opts)
    for f in frames:                                                   # 상세 출력도 죽지 않는다
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            output.show(parse(0.0, f), verbose=True)
    print("selfcheck: all checks passed")
if __name__ == "__main__":
    run()
