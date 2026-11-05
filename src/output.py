"""요약/상세 출력, 통계, 필터. 토큰 순서가 계약이다 — 검증 awk가 이 자리에 필드를 건다."""
import sys, time
from parse import esc
LABEL = {"eth": "Ethernet", "ipv4": "IPv4", "arp": "ARP", "tcp": "TCP",
         "udp": "UDP", "icmp": "ICMP", "http": "HTTP", "dns": "DNS", "tls": "TLS"}
PORT_PROTOCOLS = ("tcp", "udp")
TRANSPORT = (*PORT_PROTOCOLS, "icmp")
COUNTERS = (*TRANSPORT, "arp", "other")
APP = ("http", "dns", "tls")            # 페이로드를 대신 요약하는 계층
DETAIL = {
    "eth": lambda d: "%s → %s   type=0x%04x" % (d["src"], d["dst"], d["type"]),
    "ipv4": lambda d: "%s → %s   ttl=%d  proto=%d  len=%d" % (
        d["src"], d["dst"], d["ttl"], d["proto"], d["len"]),
    "arp": lambda d: "%s → %s   opcode=%d  %s → %s" % (
        d["sha"], d["tha"], d["opcode"], d["spa"], d["tpa"]),
    "tcp": lambda d: "%d → %d   seq=%d  flags=%s  win=%d  ack=%d" % (
        d["sport"], d["dport"], d["seq"], ",".join(d["flags"]) or "-", d["win"], d["ack"]),
    "udp": lambda d: "%d → %d   len=%d" % (d["sport"], d["dport"], d["len"]),
    "icmp": lambda d: "type=%d  code=%d" % (d["type"], d["code"]),
    "http": lambda d: d["line"],
    "dns": lambda d: "id=0x%04x  flags=0x%04x  qd=%d  %s  qtype=%s  answers=%s" % (
        d["id"], d["flags"], d["qdcount"], esc(d["qname"] or "."), d["qtype"], ",".join(d["answers"]) or "-"),
    "tls": lambda d: d["note"],
}
def _ts(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts)) + ".%03d" % (ts % 1 * 1000)
def payload(pkt):
    for key in APP:
        if key in pkt:
            return "%s %s" % (LABEL[key], DETAIL[key](pkt[key]))
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
            src, dst = "%s:%d" % (src, d["sport"]), "%s:%d" % (dst, d["dport"])
        tail = [LABEL[l4]]
        if l4 == "tcp":
            tail.append("[%s]" % ",".join(d["flags"]))
        elif l4 == "icmp":
            tail.append("type=%d" % d["type"])
        tail.append("len=%d" % n)
    elif arp:
        tail = ["request" if arp["opcode"] == 1 else "reply", "who-has", arp["tpa"]]
    elif ip:
        frag = ip["frag_off"] or ip["flags"] & 1
        tail = ["frag" if frag else "proto=%d" % ip["proto"], "len=%d" % n]
    else:
        tail = ["type=0x%04x" % eth.get("type", 0), "len=%d" % n]
    if not pkt["error"] and (text := payload(pkt)):
        tail.append(text)
    return "%s  %-5s %s → %s   %s" % (_ts(pkt["ts"]), name, src, dst, "  ".join(tail))
def detail(pkt):
    out = []
    for i, key in enumerate(pkt["layers"]):
        d = pkt.get(key)
        text = "[%s]  %s" % (LABEL[key], DETAIL[key](d)) if d else "[Malformed]  " + key
        out.append("  " * i + text)
        if key == "dns" and d:
            out.append("  " * (i + 1) + "[Wire]  hex=" + d["wire"])
    if not pkt["error"] and pkt["payload"] and not any(k in pkt for k in APP):
        out.append("%s[Payload]  %s" % ("  " * len(pkt["layers"]), payload(pkt)))
    return "\n".join(out)
def show(pkt, verbose=False):
    print(detail(pkt) if verbose else summary(pkt))
    if pkt["error"]:
        print("[ERROR] " + esc(pkt["error"]), file=sys.stderr)
class Stats:
    def __init__(self):
        self.captured = 0
        self.n = dict.fromkeys(COUNTERS, 0)
    def add(self, pkt):
        self.captured += 1
        self.n[next((k for k in COUNTERS if k in pkt), "other")] += 1
    def line(self):
        return "captured %d  |  %s" % (
            self.captured, "  ".join("%s %d" % (LABEL.get(k, k), self.n[k]) for k in COUNTERS))
def match(pkt, opts):
    if opts.proto and opts.proto not in pkt:
        return False
    if opts.host:
        ip, arp = pkt.get("ipv4", {}), pkt.get("arp", {})
        if opts.host not in (ip.get("src"), ip.get("dst"), arp.get("spa"), arp.get("tpa")):
            return False
    ports = [pkt[k][f] for k in PORT_PROTOCOLS if k in pkt for f in ("sport", "dport")]
    return 22 not in ports if opts.port is None else opts.port in ports
