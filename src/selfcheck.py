"""네트워크·권한 없이 고정 프레임·경계·출력·필터를 자체 점검한다."""
import io, re, socket, struct, types
from contextlib import redirect_stdout, redirect_stderr
import output
from parse import parse
SRC, DST = "aabbccddeeff", "112233445566"
MAC = re.compile(r"\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b")
def eth(etype, body):
    return struct.pack("!6s6sH", bytes.fromhex(DST), bytes.fromhex(SRC), etype) + body
def ip4(proto, body, flags=0, frag=0, ihl=5, tlen=None, opts=b"", pad=b"", src="192.168.0.5", dst="8.8.8.8", ttl=64):
    tlen = ihl * 4 + len(body) if tlen is None else tlen
    return eth(0x0800, struct.pack("!BBHHHBBH4s4s", 0x40 | ihl, 0, tlen, 0x1c46, (flags << 13) | frag, ttl,
                                   proto, 0, socket.inet_aton(src), socket.inet_aton(dst)) + opts + body + pad)
def arp(op=1, htype=1, ptype=0x0800, hlen=6, plen=4, cut=0):
    body = struct.pack("!HHBBH6s4s6s4s", htype, ptype, hlen, plen, op, bytes.fromhex(SRC),
                       socket.inet_aton("192.168.0.5"), b"\x00" * 6, socket.inet_aton("192.168.0.1"))
    return eth(0x0806, body[:len(body) - cut])
def tcp(sport=52134, dport=80, flags=0x02, off=5, body=b"", ack=0):
    return struct.pack("!HHIIBBHHH", sport, dport, 1234567, ack, off << 4, flags, 64240, 0, 0) + body
def udp(body, sport=51000, dport=53, ulen=None):
    return struct.pack("!HHHH", sport, dport, 8 + len(body) if ulen is None else ulen, 0) + body
def dns(qname=b"\x07example\x03com\x00", qd=1, tail=b"\x00\x01\x00\x01"):
    return struct.pack("!6H", 0x1234, 0x0100, qd, 0, 0, 0) + qname + tail
ICMP_ECHO = ip4(1, struct.pack("!BBH", 8, 0, 0) + b"\x00\x01\x00\x01")
TCP_SYN, DNS_QUERY, ARP_REQ = ip4(6, tcp()), ip4(17, udp(dns())), arp()
TRUNCATED = eth(0x0800, b"\x45\x00\x00\x1c\x00\x00")
KEYS = {"eth": "src dst type", "ipv4": "src dst ihl tos len id flags frag_off ttl proto csum",
        "arp": "htype ptype hlen plen opcode sha tha spa tpa",
        "tcp": "sport dport seq ack off flags win csum urp", "udp": "sport dport len csum",
        "icmp": "type code csum", "http": "line",
        "dns": "id flags qdcount ancount nscount arcount qname qtype answers wire", "tls": "note"}
def ok(frame, layers):
    p = parse(0.0, frame)
    assert p["error"] is None and p["layers"] == layers, (p["error"], p["layers"], layers)
    for k in layers:
        assert set(KEYS[k].split()) <= p[k].keys(), (k, sorted(p[k]))
    return p
def err(frame, layers):
    p = parse(0.0, frame)
    assert p["error"] and p["layers"] == layers and layers[-1] not in p, layers
    return p
def _show(pkt, verbose=False):
    out, err_buf = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err_buf):
        output.show(pkt, verbose)
    return out.getvalue(), err_buf.getvalue()
def run():
    a = ok(ARP_REQ, ["eth", "arp"])["arp"]
    assert (a["opcode"], a["sha"], a["tha"], a["spa"], a["tpa"]) == (
        1, "aa:bb:cc:dd:ee:ff", "00:00:00:00:00:00", "192.168.0.5", "192.168.0.1")
    line = _show(parse(0.0, ARP_REQ))[0].rstrip("\n")
    assert "\n" not in line and len(MAC.findall(line)) == 2, line
    assert "reply  192.168.0.5  is-at  aa:bb:cc:dd:ee:ff" in output.summary(parse(0.0, arp(op=2)))
    assert "opcode=3" in output.summary(parse(0.0, arp(op=3)))
    for bad in (arp(htype=6), arp(ptype=0x86DD), arp(cut=1)):
        err(bad, ["eth", "arp"])
    p = ok(ICMP_ECHO, ["eth", "ipv4", "icmp"])
    i, ic = p["ipv4"], p["icmp"]
    assert (i["src"], i["dst"], i["ihl"], i["ttl"], i["proto"], i["len"]) == ("192.168.0.5", "8.8.8.8", 5, 64, 1, 28)
    assert (ic["type"], ic["id"], ic["seq"], p["payload"]) == (8, 1, 1, b"")
    assert "id=0x0001 seq=1" in output.summary(p) and "id=0x0001  seq=1" in output.detail(p)
    probe = ip4(17, udp(b"probe", dport=33434), ttl=1)
    for typ, code, rsrc in ((11, 0, "192.168.0.1"), (3, 3, "8.8.8.8")):
        qfrm = ip4(1, struct.pack("!BBHI", typ, code, 0, 0) + probe[14:42], src=rsrc, dst="192.168.0.5")
        qp = ok(qfrm, ["eth", "ipv4", "icmp"])
        assert qp["icmp"]["quoted"] == {"src": "192.168.0.5", "dst": "8.8.8.8", "ttl": 1, "proto": 17,
                                        "id": 0x1c46, "sport": 51000, "dport": 33434}
        assert "[Quoted]" in output.detail(qp) and "33434" in output.detail(qp) and "orig=" in output.summary(qp)
    assert "quoted" not in ok(ip4(1, struct.pack("!BBHI", 11, 0, 0, 0) + b"\x00" * 4), ["eth", "ipv4", "icmp"])["icmp"]
    qfrag = ok(ip4(1, struct.pack("!BBHI", 11, 0, 0, 0) + ip4(17, b"\xaa\xbb\xcc\xdd", frag=10)[14:42]), ["eth", "ipv4", "icmp"])
    assert "quoted" in qfrag["icmp"] and "sport" not in qfrag["icmp"]["quoted"]
    for bad in (TRUNCATED, ip4(1, b"", ihl=4), ip4(1, b"\x08\x00\x00\x00", ihl=6),
                ip4(1, b"\x08\x00\x00\x00", tlen=8), ip4(1, b"\x08\x00\x00\x00", tlen=999)):
        err(bad, ["eth", "ipv4"])
    for frag in (ip4(6, tcp(), flags=1), ip4(6, tcp(), frag=185)):
        assert "tcp" not in ok(frag, ["eth", "ipv4"])
    assert parse(0.0, ip4(1, struct.pack("!BBH", 8, 0, 0) + b"\x00\x01", pad=b"\x00" * 18))["payload"] == b"\x00\x01"
    p = ok(TCP_SYN, ["eth", "ipv4", "tcp"])
    t = p["tcp"]
    assert (t["flags"], t["sport"], t["dport"], t["off"], t["win"], t["seq"]) == (["SYN"], 52134, 80, 5, 64240, 1234567)
    assert "http" not in p and "dns" not in p
    for bad, layers in ((ip4(6, tcp(off=4)), ["eth", "ipv4", "tcp"]), (ip4(6, tcp(off=8)), ["eth", "ipv4", "tcp"]),
                        (ip4(17, udp(b"", ulen=4)), ["eth", "ipv4", "udp"]), (ip4(17, udp(b"xx", ulen=99)), ["eth", "ipv4", "udp"]),
                        (ip4(1, b"\x08\x00"), ["eth", "ipv4", "icmp"])):
        err(bad, layers)
    d = ok(DNS_QUERY, ["eth", "ipv4", "udp", "dns"])["dns"]
    assert (d["qname"], d["qtype"], d["id"], d["qdcount"], d["ancount"]) == ("example.com", 1, 0x1234, 1, 0)
    assert bytes.fromhex(d["wire"]) == dns()
    question, answer = dns()[12:], b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("1.2.3.4")
    response = struct.pack("!6H", 0x1234, 0x8180, 1, 2, 0, 0) + question + answer + answer[:-4] + b"\x05\x06\x07\x08"
    p = ok(ip4(17, udp(response)), ["eth", "ipv4", "udp", "dns"])
    assert p["dns"]["answers"] == ["1.2.3.4", "5.6.7.8"]
    assert response.hex() in output.detail(p) and response.hex() not in output.summary(p)
    assert all("answers=1.2.3.4,5.6.7.8" in s for s in (output.summary(p), output.detail(p)))
    for bad in (response[:-1], response[:-10], response[:-len(answer)], dns(qname=b"\xc0\x0c", tail=b"\x00\x01\x00\x01"),
                dns(qname=b"\xc0\xff", tail=b"\x00\x01\x00\x01"), dns(qname=b"\x07exam", tail=b""), b"\x00" * 8):
        err(ip4(17, udp(bad)), ["eth", "ipv4", "udp", "dns"])
    assert "ack=7654321" in output.detail(parse(0.0, ip4(6, tcp(ack=7654321))))
    p = parse(0.0, ip4(17, udp(dns(qname=b"", qd=0, tail=b""))))
    assert p["dns"]["qname"] is None and p["dns"]["qtype"] is None
    ptr = struct.pack("!6H", 1, 0, 1, 0, 0, 0) + b"\xc0\x12\x00\x01\x00\x01\x07example\x03com\x00"
    assert parse(0.0, ip4(17, udp(ptr)))["dns"]["qname"] == "example.com"
    ok(ip4(6, tcp(dport=53, body=b"\x00\x1cxx")), ["eth", "ipv4", "tcp"])
    assert ok(ip4(6, tcp(dport=80, body=b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n")),
              ["eth", "ipv4", "tcp", "http"])["http"]["line"] == "GET /index.html HTTP/1.1"
    p = parse(0.0, ip4(6, tcp(dport=80, body=b"GET /a\rHTTP\x00\n")))
    assert "\n" not in p["http"]["line"] and "\\r" in p["http"]["line"]
    assert ok(ip4(6, tcp(dport=443, body=b"\x16\x03\x01")), ["eth", "ipv4", "tcp", "tls"])["tls"] == {"note": "encrypted"}
    for frame, expected in ((ip4(6, tcp(body=b"GET / HTTP/1.1\r\n")), "HTTP GET / HTTP/1.1"),
                            (DNS_QUERY, "example.com  qtype=1"), (ip4(17, udp(dns(qname=b"\x03a\nb\x00"))), r"a\nb"),
                            (ip4(6, tcp(dport=443, body=b"x")), "TLS encrypted"),
                            (ip4(6, tcp(dport=123, body=bytes(range(20)))), "hex=" + bytes(range(16)).hex())):
        p = parse(0.0, frame)
        s, d = output.summary(p), output.detail(p)
        assert expected in s and "\n" not in s and " ".join(expected.split()) in " ".join(d.replace("[", "").replace("]", "").split())
    f = output.summary(parse(0.0, TCP_SYN)).split()
    assert (f[1], f[3], f[5]) == ("IPv4", "→", "TCP") and f[2].endswith(":52134") and f[4].endswith(":80")
    for frame, tok in ((ICMP_ECHO, "ICMP"), (ARP_REQ, "request"), (ip4(6, tcp(), flags=1), "frag"), (eth(0x86DD, b"x" * 60), "type=0x86dd")):
        assert output.summary(parse(0.0, frame)).split()[5] == tok
    e = output.summary(parse(0.0, TRUNCATED)).split()
    assert e[1] == "other" and e[5] == "malformed=ipv4" and len(e) == 6
    d2 = output.detail(parse(0.0, TCP_SYN)).splitlines()
    g = d2[1].replace("ttl=", "").replace("proto=", "").split()
    assert g[0] == "[IPv4]" and (g[1], g[3], g[4], g[5]) == ("192.168.0.5", "8.8.8.8", "64", "6") and "id=0x1c46" in d2[1]
    assert d2[2].split()[0:4:3] == ["[TCP]", "80"] and d2[2].split()[1] == "52134"
    for verbose in (False, True):
        out, err_s = _show(parse(0.0, TRUNCATED), verbose)
        assert "truncated" not in out and err_s == "[ERROR] ipv4: truncated\n"
    opts, frames, stats = types.SimpleNamespace(proto=None, host=None, port=None), [
        TCP_SYN, ICMP_ECHO, ARP_REQ, DNS_QUERY, TRUNCATED, ip4(6, tcp(sport=22))], output.Stats()
    lines = []
    for f in frames:
        p = parse(0.0, f)
        if output.match(p, opts):
            stats.add(p)
            lines.extend(_show(p)[0].splitlines())
        _show(p, verbose=True)
    assert stats.captured == 5 and len(lines) == 5
    assert (stats.n["tcp"], stats.n["icmp"], stats.n["arp"], stats.n["udp"], stats.n["other"]) == (1, 1, 1, 1, 1)
    opts.proto = "tcp"
    assert output.match(parse(0.0, ip4(6, tcp(sport=1))), opts) and not output.match(parse(0.0, ICMP_ECHO), opts)
    opts.proto, opts.host = None, "192.168.0.1"
    assert output.match(parse(0.0, ARP_REQ), opts)
    q_pkt = parse(0.0, ip4(1, struct.pack("!BBHI", 11, 0, 0, 0) + probe[14:42], src="192.168.0.1", dst="192.168.0.5"))
    opts.host, opts.port = "8.8.8.8", 33434
    assert output.match(q_pkt, opts) and not output.match(parse(0.0, ICMP_ECHO), opts)
    assert r"a\xffb" in output.detail(parse(0.0, ip4(17, udp(dns(qname=b"\x03a\xffb\x00"))))) and r"a\\xffb" not in output.detail(parse(0.0, ip4(17, udp(dns(qname=b"\x03a\xffb\x00")))))
    opts.host, opts.port = None, 80
    assert output.match(parse(0.0, TCP_SYN), opts) and not output.match(parse(0.0, ICMP_ECHO), opts)
    opts.port = None
    assert output.match(parse(0.0, ip4(6, tcp(sport=22))), opts, exclude_ssh=False)
    print("selfcheck: all checks passed")
if __name__ == "__main__":
    run()
