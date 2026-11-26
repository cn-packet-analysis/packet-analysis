"""요약/상세 출력, 통계, 필터. 토큰 순서가 계약이다 — 검증 awk가 이 자리에 필드를 건다."""
import sys, time
from parse import esc
LABEL = {"eth": "Ethernet", "ipv4": "IPv4", "arp": "ARP", "tcp": "TCP",
         "udp": "UDP", "icmp": "ICMP", "http": "HTTP", "dns": "DNS", "tls": "TLS"}
TRANSPORT = ("tcp", "udp", "icmp")
COUNTERS = (*TRANSPORT, "arp", "other")
APP = ("http", "dns", "tls")            # 페이로드를 대신 요약하는 계층
def _icmp(d):
    s = f"type={d['type']}  code={d['code']}  csum=0x{d['csum']:04x}"
    return s + (f"  id=0x{d['id']:04x}  seq={d['seq']}" if "id" in d else "")
def _quoted(q):
    s = f"{q['src']} → {q['dst']}   ttl={q['ttl']}  proto={q['proto']}  id=0x{q['id']:04x}"
    return s + (f"  {q['sport']} → {q['dport']}" if "sport" in q else "")
DETAIL = {
    "eth": lambda d: f"{d['src']} → {d['dst']}   type=0x{d['type']:04x}",
    "ipv4": lambda d: f"{d['src']} → {d['dst']}   ttl={d['ttl']}  proto={d['proto']}  len={d['len']}  id=0x{d['id']:04x}",
    "arp": lambda d: f"{d['sha']} → {d['tha']}   opcode={d['opcode']}  {d['spa']} → {d['tpa']}",
    "tcp": lambda d: f"{d['sport']} → {d['dport']}   seq={d['seq']}  flags={','.join(d['flags']) or '-'}  win={d['win']}  ack={d['ack']}",
    "udp": lambda d: f"{d['sport']} → {d['dport']}   len={d['len']}",
    "icmp": _icmp,
    "http": lambda d: d["line"],
    "dns": lambda d: f"id=0x{d['id']:04x}  flags=0x{d['flags']:04x}  qd={d['qdcount']}  {esc(d['qname'] or '.')}  qtype={d['qtype']}  answers={','.join(d['answers']) or '-'}",
    "tls": lambda d: d["note"],
}
def _ts(ts):
    return f"{time.strftime('%H:%M:%S', time.localtime(ts))}.{int(ts % 1 * 1000):03d}"
def payload(pkt):
    for key in APP:
        if key in pkt:
            return f"{LABEL[key]} {DETAIL[key](pkt[key])}"
    return "hex=" + pkt["payload"][:16].hex() if pkt["payload"] else ""
def summary(pkt):
    """$1 ts, $2 L3 이름, $3/$5 주소, $4 화살표, $6~ 꼬리. $6에 TCP/UDP/ICMP는 L4 성공 시에만."""
    eth, ip, arp = pkt.get("eth", {}), pkt.get("ipv4"), pkt.get("arp")
    if ip:
        name, src, dst = "IPv4", ip["src"], ip["dst"]
    elif arp:
        name, src, dst = "ARP", arp["sha"], arp["tha"]
    else:
        name, src, dst = "other", eth.get("src", "?"), eth.get("dst", "?")
    n = len(pkt["payload"])
    l4 = next((k for k in TRANSPORT if k in pkt), None)
    if pkt["error"]:
        tail = ["malformed=" + pkt["layers"][-1]]
    elif l4:
        d = pkt[l4]
        if l4 != "icmp":
            src, dst = f"{src}:{d['sport']}", f"{dst}:{d['dport']}"
        tail = [LABEL[l4]]
        if l4 == "tcp":
            tail.append(f"[{','.join(d['flags'])}]")
        elif l4 == "icmp":
            tail.append(f"type={d['type']}")
            if "id" in d:
                tail.append(f"id=0x{d['id']:04x} seq={d['seq']}")
            elif "quoted" in d:
                q = d["quoted"]
                tail.append(f"orig={q['src']}→{q['dst']}" + (f":{q['dport']}" if "dport" in q else ""))
        tail.append(f"len={n}")
    elif arp:
        tail = (["request", "who-has", arp["tpa"]] if arp["opcode"] == 1 else
                ["reply", arp["spa"], "is-at", arp["sha"]] if arp["opcode"] == 2 else
                [f"opcode={arp['opcode']}", arp["spa"], "→", arp["tpa"]])
    elif ip:
        frag = ip["frag_off"] or ip["flags"] & 1
        tail = ["frag" if frag else f"proto={ip['proto']}", f"len={n}"]
    else:
        tail = [f"type=0x{eth.get('type', 0):04x}", f"len={n}"]
    if not pkt["error"] and (text := payload(pkt)):
        tail.append(text)
    return f"{_ts(pkt['ts'])}  {name:<5} {src} → {dst}   {'  '.join(tail)}"
def detail(pkt):
    out = []
    for i, key in enumerate(pkt["layers"]):
        d = pkt.get(key)
        out.append("  " * i + (f"[{LABEL[key]}]  {DETAIL[key](d)}" if d else f"[Malformed]  {key}"))
        if key == "dns" and d:
            out.append("  " * (i + 1) + f"[Wire]  hex={d['wire']}")
        elif key == "icmp" and d and "quoted" in d:
            out.append("  " * (i + 1) + f"[Quoted]  {_quoted(d['quoted'])}")
    if not pkt["error"] and pkt["payload"] and not any(k in pkt for k in APP):
        out.append("  " * len(pkt["layers"]) + f"[Payload]  {payload(pkt)}")
    return "\n".join(out)
def show(pkt, verbose=False):
    print(detail(pkt) if verbose else summary(pkt))
    if pkt["error"]:
        print("[ERROR] " + esc(pkt["error"]), file=sys.stderr)
class Stats:
    def __init__(self):
        self.captured, self.n = 0, dict.fromkeys(COUNTERS, 0)
    def add(self, pkt):
        self.captured += 1
        self.n[next((k for k in COUNTERS if k in pkt), "other")] += 1
    def line(self):
        return f"captured {self.captured}  |  {'  '.join(f'{LABEL.get(k, k)} {self.n[k]}' for k in COUNTERS)}"
def match(pkt, opts, exclude_ssh=True):
    if opts.proto and opts.proto not in pkt:
        return False
    q = pkt.get("icmp", {}).get("quoted", {})
    if opts.host:
        ip, arp = pkt.get("ipv4", {}), pkt.get("arp", {})
        if opts.host not in (ip.get("src"), ip.get("dst"), arp.get("spa"), arp.get("tpa"), q.get("src"), q.get("dst")):
            return False
    ports = [d[f] for d in (pkt.get("tcp"), pkt.get("udp"), q) if d for f in ("sport", "dport") if f in d]
    return (22 not in ports if exclude_ssh else True) if opts.port is None else opts.port in ports
