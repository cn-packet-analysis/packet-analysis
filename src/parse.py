"""parse_xxx(data, pkt) -> (다음 키 | None, 남은 bytes).
완성한 계층만 pkt에 대입. 미지원은 None, 잘못된 입력은 ValueError.
"""
import socket, struct
def esc(s, space=" "):
    return s.encode("unicode_escape").decode("ascii").replace(" ", space)
def _header(fmt, data, offset=0, *, error="truncated"):
    if len(data) < offset + struct.calcsize(fmt):
        raise ValueError(error)
    return struct.unpack_from(fmt, data, offset)
def _app(layer, sport, dport, rest):
    if not rest:
        return None, rest
    ports = PORTMAP[layer]
    return ports.get(dport) or ports.get(sport), rest
def parse_eth(data, pkt):
    dst, src, etype = _header("!6s6sH", data)
    pkt["eth"] = {"src": src.hex(":"), "dst": dst.hex(":"), "type": etype}
    return ETHERTYPE.get(etype), data[14:]
def parse_ipv4(data, pkt):
    v_ihl, tos, tlen, ident, ff, ttl, proto, csum, src, dst = _header("!BBHHHBBH4s4s", data)
    ihl = v_ihl & 0x0F
    if v_ihl >> 4 != 4:
        raise ValueError("bad version")
    if ihl < 5:
        raise ValueError("bad ihl")
    if not ihl * 4 <= tlen <= len(data):
        raise ValueError("bad total length")
    pkt["ipv4"] = {"src": socket.inet_ntoa(src), "dst": socket.inet_ntoa(dst),
                   "ihl": ihl, "tos": tos, "len": tlen, "id": ident,
                   "flags": ff >> 13, "frag_off": ff & 0x1FFF,
                   "ttl": ttl, "proto": proto, "csum": csum}
    rest = data[ihl * 4:tlen]                       # Ethernet padding 제외
    if ff & 0x3FFF:                                 # MF=1 또는 후속 단편
        return None, rest                           # 재조립은 범위 밖 — 여기서 정상 중단
    return IPPROTO.get(proto), rest
def parse_arp(data, pkt):
    htype, ptype, hlen, plen, op, sha, spa, tha, tpa = _header("!HHBBH6s4s6s4s", data)
    if (htype, ptype, hlen, plen) != (1, 0x0800, 6, 4):
        raise ValueError("unsupported hw/proto pair")
    pkt["arp"] = {"htype": htype, "ptype": ptype, "hlen": hlen, "plen": plen, "opcode": op,
                  "sha": sha.hex(":"), "tha": tha.hex(":"),
                  "spa": socket.inet_ntoa(spa), "tpa": socket.inet_ntoa(tpa)}
    return None, data[28:]
def parse_tcp(data, pkt):
    sport, dport, seq, ack, off_r, flg, win, csum, urp = _header("!HHIIBBHHH", data)
    off = off_r >> 4
    if not 20 <= off * 4 <= len(data):
        raise ValueError("bad data offset")
    pkt["tcp"] = {"sport": sport, "dport": dport, "seq": seq, "ack": ack, "off": off,
                  "flags": [n for b, n in TCPFLAGS if flg & b],
                  "win": win, "csum": csum, "urp": urp}
    return _app("tcp", sport, dport, data[off * 4:])
def parse_udp(data, pkt):
    sport, dport, ulen, csum = _header("!HHHH", data)
    if not 8 <= ulen <= len(data):
        raise ValueError("bad length")
    pkt["udp"] = {"sport": sport, "dport": dport, "len": ulen, "csum": csum}
    return _app("udp", sport, dport, data[8:ulen])
def parse_icmp(data, pkt):
    typ, code, csum = _header("!BBH", data)
    pkt["icmp"] = {"type": typ, "code": code, "csum": csum}
    return None, data[4:]                           # 추가 필드는 해석하지 않는다
def parse_http(data, pkt):
    line, _, rest = data.partition(b"\n")
    pkt["http"] = {"line": esc(line.rstrip(b"\r").decode("latin-1"))}
    return None, rest                               # 프레임 안의 첫 줄만 — 스트림 보장 없음
def parse_tls(data, pkt):
    pkt["tls"] = {"note": "encrypted"}              # 복호화·핸드셰이크 파싱 없음
    return None, data
def _qname(msg, off):
    labels, seen, end = [], set(), None
    while True:
        if off >= len(msg):
            raise ValueError("qname out of range")
        n = msg[off]
        if n & 0xC0 == 0xC0:                        # 압축 포인터
            if off + 1 >= len(msg):
                raise ValueError("truncated pointer")
            ptr = ((n & 0x3F) << 8) | msg[off + 1]
            if end is None:
                end = off + 2
            if ptr in seen:
                raise ValueError("qname pointer loop")
            seen.add(ptr)
            off = ptr
            continue
        if n & 0xC0:
            raise ValueError("bad label length")
        off += 1
        if n == 0:
            return ".".join(labels) or ".", end if end is not None else off
        if off + n > len(msg):
            raise ValueError("truncated label")
        labels.append(msg[off:off + n].decode("ascii", "backslashreplace"))
        off += n
def parse_dns(data, pkt):
    ident, flags, qd, an, ns, ar = _header("!6H", data)
    qname = qtype = None
    end = 12
    for i in range(qd):                             # 첫 질문만 요약. 나머지는 길이 검증
        name, end = _qname(data, end)
        typ, cls = _header("!HH", data, end, error="truncated question")
        if i == 0:
            qname, qtype = name, typ
        end += 4
    answers = []
    for _ in range(an):
        _, end = _qname(data, end)
        typ, cls, ttl, size = _header("!HHIH", data, end, error="truncated answer header")
        end += 10
        if end + size > len(data):
            raise ValueError("truncated answer data")
        if (typ, cls) == (1, 1):
            if size != 4:
                raise ValueError("bad A record length")
            answers.append(socket.inet_ntoa(data[end:end + size]))
        end += size
    pkt["dns"] = {"id": ident, "flags": flags, "qdcount": qd, "ancount": an, "nscount": ns,
                  "arcount": ar, "qname": qname, "qtype": qtype, "answers": answers, "wire": data.hex()}
    return None, data[end:]                         # 권한·추가 구역은 payload로 둔다
PARSERS = {"eth": parse_eth, "ipv4": parse_ipv4, "arp": parse_arp,
           "tcp": parse_tcp, "udp": parse_udp, "icmp": parse_icmp,
           "http": parse_http, "dns": parse_dns, "tls": parse_tls}
ETHERTYPE = {0x0800: "ipv4", 0x0806: "arp"}         # 그 외 → None
IPPROTO = {1: "icmp", 6: "tcp", 17: "udp"}
PORTMAP = {"tcp": {80: "http", 8080: "http", 443: "tls"},
           "udp": {53: "dns"}}
TCPFLAGS = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
            (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"))
def parse(ts, data):
    pkt = {"ts": ts, "layers": [], "error": None}
    key = "eth"
    try:
        while key in PARSERS:
            pkt["layers"].append(key)
            key, data = PARSERS[key](data, pkt)
    except (struct.error, IndexError, ValueError, OSError) as e:   # inet_ntoa는 OSError
        pkt["error"] = f"{key}: {e}"
    pkt["payload"] = data
    return pkt
