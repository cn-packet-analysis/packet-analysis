#!/usr/bin/env python3
"""표준 라이브러리 curses 기반 wirefish 3-패널 TUI.

기존 CLI 4파일(capture/parse/output/selfcheck)의 파싱·필터·통계·pcap 저장을
그대로 재사용하며 실시간 캡처(-i), pcap 오프라인 분석(-r), 샘플 데모(--demo)를 제공한다.
"""
import argparse
import curses
import locale
import os
import queue
import socket
import struct
import sys
import tempfile
import threading
import time
import types
from contextlib import ExitStack, closing
from dataclasses import dataclass

import capture
import output
from parse import esc, parse

MAX_RECORDS = 50000

PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}

ICMP_TYPES = {
    0: "Echo Reply",
    3: "Dest Unreachable",
    8: "Echo Request",
    11: "Time Exceeded",
}


@dataclass(slots=True)
class PacketRecord:
    no: int
    ts: float
    raw: bytes
    pkt: dict
    proto: str
    src: str
    dst: str
    info: str
    search_text: str


def _proto_name(pkt):
    if pkt["error"]:
        return "ERR"
    for key, label in (
        ("http", "HTTP"),
        ("dns", "DNS"),
        ("tls", "TLS"),
        ("tcp", "TCP"),
        ("udp", "UDP"),
        ("icmp", "ICMP"),
        ("arp", "ARP"),
        ("ipv4", "IPv4"),
    ):
        if key in pkt:
            return label
    return "ETH"


def _endpoints(pkt):
    eth = pkt.get("eth", {})
    ip = pkt.get("ipv4")
    arp = pkt.get("arp")
    if ip:
        src, dst = ip["src"], ip["dst"]
        for l4 in ("tcp", "udp"):
            if l4 in pkt:
                d = pkt[l4]
                return f"{src}:{d['sport']}", f"{dst}:{d['dport']}"
        return src, dst
    if arp:
        return arp["spa"], arp["tpa"]
    return eth.get("src", "?"), eth.get("dst", "?")


def _info_text(pkt, raw_len):
    if pkt["error"]:
        layer = pkt["layers"][-1] if pkt["layers"] else "?"
        return f"Malformed ({layer}): {esc(pkt['error'])}"
    if "http" in pkt:
        return pkt["http"]["line"]
    if "dns" in pkt:
        d = pkt["dns"]
        kind = "Resp" if d["flags"] & 0x8000 else "Query"
        qname = esc(d["qname"] or ".")
        ans = f" -> {','.join(d['answers'])}" if d["answers"] else ""
        return f"{kind} id=0x{d['id']:04x} {qname} (qtype={d['qtype']}){ans}"
    if "tls" in pkt:
        tcp = pkt.get("tcp", {})
        fl = ",".join(tcp.get("flags", [])) or "-"
        return f"[{fl}] TLS encrypted ({len(pkt['payload'])}B)"
    if "tcp" in pkt:
        t = pkt["tcp"]
        fl = ",".join(t["flags"]) or "-"
        return f"[{fl}] seq={t['seq']} ack={t['ack']} win={t['win']} len={len(pkt['payload'])}"
    if "udp" in pkt:
        u = pkt["udp"]
        return f"len={u['len']} payload={len(pkt['payload'])}B"
    if "icmp" in pkt:
        ic = pkt["icmp"]
        name = ICMP_TYPES.get(ic["type"], f"type={ic['type']}")
        if "id" in ic:
            return f"{name} id=0x{ic['id']:04x} seq={ic['seq']}"
        if "quoted" in ic:
            q = ic["quoted"]
            dport = f":{q['dport']}" if "dport" in q else ""
            return f"{name} (code={ic['code']}) orig={q['src']}->{q['dst']}{dport}"
        return f"{name} code={ic['code']} csum=0x{ic['csum']:04x}"
    if "arp" in pkt:
        a = pkt["arp"]
        if a["opcode"] == 1:
            return f"Who has {a['tpa']}? Tell {a['spa']}"
        if a["opcode"] == 2:
            return f"{a['spa']} is at {a['sha']}"
        return f"opcode={a['opcode']} {a['spa']} -> {a['tpa']}"
    if "ipv4" in pkt:
        ip = pkt["ipv4"]
        if ip["frag_off"] or (ip["flags"] & 1):
            return f"Fragment off={ip['frag_off']} flags={ip['flags']} proto={ip['proto']} len={ip['len']}"
        return f"proto={ip['proto']} ttl={ip['ttl']} len={ip['len']}"
    eth = pkt.get("eth", {})
    return f"EtherType 0x{eth.get('type', 0):04x} len={raw_len}"


def make_record(no, ts, raw, pkt=None):
    if pkt is None:
        pkt = parse(ts, raw)
    proto = _proto_name(pkt)
    src, dst = _endpoints(pkt)
    info = _info_text(pkt, len(raw))
    detail = output.detail(pkt)
    search_text = " ".join((str(no), proto, src, dst, info, detail, pkt["error"] or "")).lower()
    return PacketRecord(no, ts, raw, pkt, proto, src, dst, info, search_text)


def detail_lines(rec):
    """계층별 상세 패널용 (스타일 키, 텍스트) 줄 목록을 만든다."""
    ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(rec.ts)) + ".%03d" % (rec.ts % 1 * 1000)
    lines = [("meta", f"Frame #{rec.no}: {len(rec.raw)} bytes on wire, captured {ts_str}")]
    for line in output.detail(rec.pkt).splitlines():
        s = line.lstrip()
        if s.startswith(("[Malformed]", "[ERROR]")):
            style = "err"
        elif s.startswith(("[HTTP]", "[DNS]", "[TLS]", "[Wire]")):
            style = "app"
        elif s.startswith(("[TCP]", "[UDP]", "[ICMP]", "[Quoted]")):
            style = "l4"
        elif s.startswith(("[Ethernet]", "[IPv4]", "[ARP]")):
            style = "l23"
        else:
            style = "muted"
        lines.append((style, line))
    if rec.pkt["error"]:
        lines.append(("err", "[ERROR] " + esc(rec.pkt["error"])))
    return lines


def hexdump_lines(raw, per_line=16):
    """Wireshark 스타일 오프셋 + Hex + ASCII 덤프 줄 목록을 만든다."""
    if not raw:
        return ["(empty frame)"]
    half = per_line // 2
    out = []
    for off in range(0, len(raw), per_line):
        chunk = raw[off:off + per_line]
        left = " ".join(f"{b:02x}" for b in chunk[:half])
        right = " ".join(f"{b:02x}" for b in chunk[half:])
        hex_width = half * 3 - 1
        if per_line >= 16:
            hex_part = f"{left:<{hex_width}}  {right:<{hex_width}}"
        else:
            hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(per_line * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        out.append(f"{off:04x}  {hex_part}  |{ascii_part:<{per_line}}|")
    return out


def read_pcap(path):
    """표준 libpcap(.pcap) 파일에서 (ts, raw) 목록을 읽는다."""
    with open(path, "rb") as fh:
        ghdr = fh.read(24)
        if len(ghdr) < 24:
            raise ValueError("pcap 글로벌 헤더가 잘렸습니다")
        magic = ghdr[:4]
        if magic not in PCAP_MAGIC:
            raise ValueError("지원하지 않는 pcap 형식입니다(pcapng 또는 손상된 매직)")
        endian, scale = PCAP_MAGIC[magic]
        _, _, _, _, _, network = struct.unpack(endian + "HHiIII", ghdr[4:24])
        if network != 1:
            raise ValueError(f"Ethernet(1) 링크타입만 지원합니다(현재 {network})")
        frames = []
        while True:
            rhdr = fh.read(16)
            if not rhdr:
                break
            if len(rhdr) < 16:
                raise ValueError("pcap 패킷 헤더가 잘렸습니다")
            ts_sec, ts_sub, incl_len, _ = struct.unpack(endian + "IIII", rhdr)
            raw = fh.read(incl_len)
            if len(raw) < incl_len:
                raise ValueError("pcap 패킷 데이터가 잘렸습니다")
            frames.append((ts_sec + ts_sub * scale, raw))
        return frames


def demo_frames():
    """selfcheck 프레임 빌더를 재사용해 5종 프로토콜 시나리오 샘플을 생성한다."""
    import selfcheck as sc

    base = time.time() - 1.5
    question = sc.dns()[12:]
    ans1 = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.34")
    ans2 = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("93.184.216.35")
    dns_resp = struct.pack("!6H", 0x1234, 0x8180, 1, 2, 0, 0) + question + ans1 + ans2
    probe1 = sc.ip4(17, sc.udp(b"wirefish-trace-1", sport=51001, dport=33434), src="192.168.0.5", dst="8.8.8.8", ttl=1)
    probe2 = sc.ip4(17, sc.udp(b"wirefish-trace-2", sport=51002, dport=33435), src="192.168.0.5", dst="8.8.8.8", ttl=2)
    http_req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: wirefish\r\n\r\n"
    http_res = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<h1>Hello</h1>"
    arp_reply = sc.eth(
        0x0806,
        struct.pack(
            "!HHBBH6s4s6s4s",
            1, 0x0800, 6, 4, 2,
            bytes.fromhex("112233445566"), socket.inet_aton("192.168.0.1"),
            bytes.fromhex("aabbccddeeff"), socket.inet_aton("192.168.0.5"),
        ),
    )
    samples = [
        sc.ARP_REQ,
        arp_reply,
        sc.ip4(17, sc.udp(sc.dns(), sport=53001, dport=53), src="192.168.0.5", dst="8.8.8.8"),
        sc.ip4(17, sc.udp(dns_resp, sport=53, dport=53001), src="8.8.8.8", dst="192.168.0.5"),
        sc.ip4(6, sc.tcp(sport=52134, dport=80, flags=0x02, ack=0), src="192.168.0.5", dst="93.184.216.34"),
        sc.ip4(6, sc.tcp(sport=80, dport=52134, flags=0x12, ack=1234568), src="93.184.216.34", dst="192.168.0.5"),
        sc.ip4(6, sc.tcp(sport=52134, dport=80, flags=0x18, ack=1234568, body=http_req), src="192.168.0.5", dst="93.184.216.34"),
        sc.ip4(6, sc.tcp(sport=80, dport=52134, flags=0x18, ack=1234638, body=http_res), src="93.184.216.34", dst="192.168.0.5"),
        sc.ip4(6, sc.tcp(sport=52140, dport=443, flags=0x18, ack=778899, body=b"\x16\x03\x01\x00\x10" + bytes(range(16))), src="192.168.0.5", dst="93.184.216.34"),
        sc.ip4(1, struct.pack("!BBHHH", 8, 0, 0x4D5A, 0x0042, 1) + b"abcdefghijklmnop", src="192.168.0.5", dst="8.8.8.8"),
        sc.ip4(1, struct.pack("!BBHHH", 0, 0, 0x555A, 0x0042, 1) + b"abcdefghijklmnop", src="8.8.8.8", dst="192.168.0.5"),
        sc.ip4(1, struct.pack("!BBHI", 11, 0, 0x1A2B, 0) + probe1[14:42], src="192.168.0.1", dst="192.168.0.5"),
        sc.ip4(1, struct.pack("!BBHI", 3, 3, 0x3C4D, 0) + probe2[14:42], src="8.8.8.8", dst="192.168.0.5"),
        sc.TRUNCATED,
    ]
    return [(base + i * 0.085, raw) for i, raw in enumerate(samples)]


class TuiState:
    """curses와 분리된 3-패널 TUI 상태 모델."""

    def __init__(self, mode, source_label, opts, notice=""):
        self.mode = mode
        self.source_label = source_label
        self.opts = opts
        self.records = []
        self.filtered = []
        self.stats = output.Stats()
        self.focus = 0
        self.selected = 0
        self.list_scroll = 0
        self.detail_scroll = 0
        self.hex_scroll = 0
        self.follow = mode == "LIVE"
        self.paused = False
        self.done = mode != "LIVE"
        self.search_query = ""
        self.search_mode = False
        self.search_buf = ""
        self.show_help = False
        self.notice = notice
        self.dropped = 0
        self._next_no = 1

    def _matches_search(self, rec):
        if not self.search_query:
            return True
        tokens = self.search_query.lower().split()
        return all(tok in rec.search_text for tok in tokens)

    def add_packet(self, ts, raw, pkt=None):
        rec = make_record(self._next_no, ts, raw, pkt)
        self._next_no += 1
        self.stats.add(rec.pkt)
        if len(self.records) >= MAX_RECORDS:
            evicted = self.records.pop(0)
            self.dropped += 1
            if self.filtered and self.filtered[0].no == evicted.no:
                self.filtered.pop(0)
                if self.selected > 0:
                    self.selected -= 1
                if self.list_scroll > 0:
                    self.list_scroll -= 1
        self.records.append(rec)
        if self._matches_search(rec):
            self.filtered.append(rec)
            if self.follow:
                self.selected = len(self.filtered) - 1
                self.detail_scroll = 0
                self.hex_scroll = 0
        return rec

    def current(self):
        if 0 <= self.selected < len(self.filtered):
            return self.filtered[self.selected]
        return None

    def set_search(self, query):
        prev_no = self.current().no if self.current() else None
        self.search_query = query.strip()
        self.filtered = [r for r in self.records if self._matches_search(r)]
        if not self.filtered:
            self.selected = 0
            self.list_scroll = 0
        elif prev_no is not None:
            idx = next((i for i, r in enumerate(self.filtered) if r.no == prev_no), 0)
            self.selected = idx
        else:
            self.selected = 0
        self.detail_scroll = 0
        self.hex_scroll = 0

    def set_focus(self, panel):
        self.focus = panel % 3

    def move_selection(self, delta, visible_rows):
        if not self.filtered:
            self.selected = 0
            return
        old = self.selected
        self.selected = max(0, min(len(self.filtered) - 1, self.selected + delta))
        if self.selected != old:
            self.detail_scroll = 0
            self.hex_scroll = 0
        if self.selected < len(self.filtered) - 1:
            self.follow = False
        self.ensure_list_visible(visible_rows)

    def ensure_list_visible(self, visible_rows):
        rows = max(1, visible_rows)
        if self.selected < self.list_scroll:
            self.list_scroll = self.selected
        elif self.selected >= self.list_scroll + rows:
            self.list_scroll = self.selected - rows + 1
        max_scroll = max(0, len(self.filtered) - rows)
        self.list_scroll = max(0, min(self.list_scroll, max_scroll))

    def scroll_active(self, delta, list_rows, detail_total, detail_rows, hex_total, hex_rows):
        if self.focus == 0:
            self.move_selection(delta, list_rows)
        elif self.focus == 1:
            max_off = max(0, detail_total - max(1, detail_rows))
            self.detail_scroll = max(0, min(max_off, self.detail_scroll + delta))
        else:
            max_off = max(0, hex_total - max(1, hex_rows))
            self.hex_scroll = max(0, min(max_off, self.hex_scroll + delta))

    def jump_edge(self, to_end, list_rows, detail_total, detail_rows, hex_total, hex_rows):
        if self.focus == 0:
            if not self.filtered:
                return
            self.selected = len(self.filtered) - 1 if to_end else 0
            self.detail_scroll = 0
            self.hex_scroll = 0
            if not to_end:
                self.follow = False
            self.ensure_list_visible(list_rows)
        elif self.focus == 1:
            self.detail_scroll = max(0, detail_total - max(1, detail_rows)) if to_end else 0
        else:
            self.hex_scroll = max(0, hex_total - max(1, hex_rows)) if to_end else 0


class LiveCapture:
    """백그라운드 스레드에서 AF_PACKET 프레임을 수신해 큐로 전달한다."""

    def __init__(self, sock, opts, writer=None):
        self.sock = sock
        self.opts = opts
        self.writer = writer
        self.queue = queue.Queue(maxsize=4096)
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.error = None
        self.done = False
        self._thread = threading.Thread(target=self._run, name="wirefish-live", daemon=True)

    def start(self):
        self.sock.settimeout(0.2)
        self._thread.start()

    def set_paused(self, paused):
        if paused:
            self.pause_event.set()
        else:
            self.pause_event.clear()

    def stop(self):
        self.stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def _run(self):
        captured = 0
        try:
            while not self.stop_event.is_set():
                try:
                    raw, _ = self.sock.recvfrom(65535)
                except (TimeoutError, socket.timeout, InterruptedError):
                    continue
                if self.pause_event.is_set():
                    continue
                ts = time.time()
                pkt = parse(ts, raw)
                if not output.match(pkt, self.opts):
                    continue
                if self.writer:
                    self.writer.write(ts, raw)
                captured += 1
                try:
                    self.queue.put((ts, raw, pkt), timeout=0.1)
                except queue.Full:
                    pass
                if self.opts.count and captured >= self.opts.count:
                    break
        except OSError as exc:
            if not self.stop_event.is_set():
                self.error = esc(str(exc))
        finally:
            self.done = True


def _safe_addstr(win, y, x, text, attr=0):
    max_y, max_x = win.getmaxyx()
    if y < 0 or y >= max_y or x >= max_x:
        return
    if x < 0:
        text = text[-x:]
        x = 0
    limit = max_x - x
    if y == max_y - 1:
        limit -= 1
    if limit <= 0:
        return
    try:
        win.addnstr(y, x, text, limit, attr)
    except curses.error:
        pass


def _fill_line(win, y, text, attr):
    _, max_x = win.getmaxyx()
    padded = text.ljust(max_x)
    _safe_addstr(win, y, 0, padded, attr)


class CursesApp:
    """Wireshark 스타일 3-패널 curses UI."""

    def __init__(self, state, live=None):
        self.state = state
        self.live = live
        self.colors = {}

    def _init_colors(self):
        if not curses.has_colors():
            return
        curses.start_color()
        try:
            curses.use_default_colors()
            bg = -1
        except curses.error:
            bg = curses.COLOR_BLACK
        pairs = {
            "cyan": (curses.COLOR_CYAN, bg),
            "green": (curses.COLOR_GREEN, bg),
            "blue": (curses.COLOR_BLUE, bg),
            "magenta": (curses.COLOR_MAGENTA, bg),
            "yellow": (curses.COLOR_YELLOW, bg),
            "red": (curses.COLOR_RED, bg),
            "bar": (curses.COLOR_BLACK, curses.COLOR_CYAN),
            "active_hdr": (curses.COLOR_BLACK, curses.COLOR_WHITE),
        }
        for idx, (name, (fg, pbg)) in enumerate(pairs.items(), 1):
            try:
                curses.init_pair(idx, fg, pbg)
                self.colors[name] = curses.color_pair(idx)
            except curses.error:
                self.colors[name] = 0

    def _c(self, name, extra=0):
        return self.colors.get(name, 0) | extra

    def _proto_attr(self, proto):
        mapping = {
            "TCP": self._c("cyan"),
            "HTTP": self._c("green"),
            "TLS": self._c("green"),
            "UDP": self._c("blue"),
            "DNS": self._c("blue", curses.A_BOLD),
            "ICMP": self._c("magenta"),
            "ARP": self._c("yellow"),
            "ERR": self._c("red", curses.A_BOLD),
        }
        return mapping.get(proto, 0)

    def _detail_attr(self, style):
        mapping = {
            "meta": self._c("yellow", curses.A_BOLD),
            "l23": self._c("cyan"),
            "l4": self._c("magenta"),
            "app": self._c("green", curses.A_BOLD),
            "err": self._c("red", curses.A_BOLD),
            "muted": curses.A_DIM,
        }
        return mapping.get(style, 0)

    def _layout(self, max_y, max_x):
        body_h = max_y - 3
        list_h = max(4, int(body_h * 0.44))
        detail_h = max(4, int(body_h * 0.30))
        hex_h = body_h - list_h - detail_h
        if hex_h < 4:
            deficit = 4 - hex_h
            take_list = min(deficit, max(0, list_h - 4))
            list_h -= take_list
            deficit -= take_list
            take_det = min(deficit, max(0, detail_h - 4))
            detail_h -= take_det
            hex_h = body_h - list_h - detail_h
        list_y = 1
        detail_y = list_y + list_h
        hex_y = detail_y + detail_h
        return (list_y, list_h), (detail_y, detail_h), (hex_y, hex_h)

    def _filter_badge(self):
        o = self.state.opts
        parts = []
        if o.proto:
            parts.append(f"p={o.proto}")
        if o.host:
            parts.append(f"host={o.host}")
        if o.port is not None:
            parts.append(f"port={o.port}")
        elif self.state.mode == "LIVE":
            parts.append("port!=22")
        if o.count:
            parts.append(f"c={o.count}")
        if self.state.search_query:
            parts.append(f"find='{self.state.search_query}'")
        return " ".join(parts) if parts else "all"

    def _draw_panel_header(self, win, y, title, focused):
        marker = "▶" if focused else " "
        if focused:
            attr = self._c("active_hdr", curses.A_BOLD)
        else:
            attr = curses.A_REVERSE | curses.A_DIM
        _fill_line(win, y, f" {marker} {title}", attr)

    def _draw_list_panel(self, win, y, h, w):
        st = self.state
        count_info = f"{len(st.filtered)}/{len(st.records)}" if st.search_query else f"{len(st.filtered)}"
        follow_tag = " [FOLLOW]" if st.follow else ""
        self._draw_panel_header(win, y, f"[1] Packet List ({count_info}){follow_tag}", st.focus == 0)
        if h <= 1:
            return 0
        addr_w = 21 if w >= 100 else (16 if w >= 80 else 13)
        hdr = f"{'No.':>5} {'Time':<12} {'Proto':<5} {'Source':<{addr_w}} {'Destination':<{addr_w}} {'Len':>5} Info"
        _safe_addstr(win, y + 1, 0, hdr[:w], curses.A_UNDERLINE | curses.A_BOLD)
        rows = max(0, h - 2)
        if rows == 0:
            return 0
        st.ensure_list_visible(rows)
        if not st.filtered:
            msg = "필터에 일치하는 패킷이 없습니다." if st.records else "패킷을 기다리는 중..."
            _safe_addstr(win, y + 2, 2, msg, curses.A_DIM)
            return rows
        for row_i in range(rows):
            idx = st.list_scroll + row_i
            if idx >= len(st.filtered):
                break
            rec = st.filtered[idx]
            ts = output._ts(rec.ts)
            src = rec.src if len(rec.src) <= addr_w else rec.src[:addr_w - 1] + "~"
            dst = rec.dst if len(rec.dst) <= addr_w else rec.dst[:addr_w - 1] + "~"
            line = f"{rec.no:>5} {ts:<12} {rec.proto:<5} {src:<{addr_w}} {dst:<{addr_w}} {len(rec.raw):>5} {rec.info}"
            is_sel = idx == st.selected
            attr = self._proto_attr(rec.proto)
            if is_sel:
                attr |= curses.A_REVERSE | curses.A_BOLD
                _fill_line(win, y + 2 + row_i, line, attr)
            else:
                _safe_addstr(win, y + 2 + row_i, 0, line, attr)
        return rows

    def _draw_detail_panel(self, win, y, h, dlines):
        st = self.state
        rec = st.current()
        subtitle = f"Frame #{rec.no} ({rec.proto})" if rec else "No packet selected"
        self._draw_panel_header(win, y, f"[2] Packet Details — {subtitle}", st.focus == 1)
        rows = max(0, h - 1)
        if rows == 0:
            return 0
        if not dlines:
            _safe_addstr(win, y + 1, 2, "패킷을 선택하면 계층별 상세 구조가 표시됩니다.", curses.A_DIM)
            return rows
        max_off = max(0, len(dlines) - rows)
        st.detail_scroll = max(0, min(st.detail_scroll, max_off))
        for row_i in range(rows):
            idx = st.detail_scroll + row_i
            if idx >= len(dlines):
                break
            style, text = dlines[idx]
            _safe_addstr(win, y + 1 + row_i, 1, text, self._detail_attr(style))
        return rows

    def _draw_hex_panel(self, win, y, h, hlines, per_line):
        st = self.state
        rec = st.current()
        subtitle = f"{len(rec.raw)} bytes ({per_line}B/row)" if rec else "0 bytes"
        self._draw_panel_header(win, y, f"[3] Packet Bytes (Hex + ASCII) — {subtitle}", st.focus == 2)
        rows = max(0, h - 1)
        if rows == 0:
            return 0
        if not hlines:
            _safe_addstr(win, y + 1, 2, "원시 프레임 바이트가 여기에 표시됩니다.", curses.A_DIM)
            return rows
        max_off = max(0, len(hlines) - rows)
        st.hex_scroll = max(0, min(st.hex_scroll, max_off))
        for row_i in range(rows):
            idx = st.hex_scroll + row_i
            if idx >= len(hlines):
                break
            _safe_addstr(win, y + 1 + row_i, 1, hlines[idx], 0)
        return rows

    def _draw_help_overlay(self, win, max_y, max_x):
        lines = [
            " wirefish TUI 단축키 ",
            "",
            "  ↑ / ↓, j / k       활성 패널 한 줄 이동",
            "  PgUp / PgDn        활성 패널 한 페이지 이동",
            "  g / G, Home / End  맨 위 / 맨 아래로 이동",
            "  Tab / Shift-Tab    패널 포커스 순환 (목록 → 상세 → Hex)",
            "  1 / 2 / 3          패널 직접 선택",
            "  /                  화면 내 검색·필터 입력 (빈 입력 시 해제)",
            "  Space              실시간 캡처 일시정지 / 재개",
            "  f                  최신 패킷 자동 추적(Follow) 토글",
            "  ? / Esc            이 도움말 닫기",
            "  q / Ctrl-C         종료 및 최종 통계 출력",
        ]
        box_w = min(max_x - 4, max(len(x) for x in lines) + 4)
        box_h = min(max_y - 2, len(lines) + 2)
        top = max(0, (max_y - box_h) // 2)
        left = max(0, (max_x - box_w) // 2)
        attr = self._c("bar", curses.A_BOLD)
        for row in range(box_h):
            _safe_addstr(win, top + row, left, " " * box_w, curses.A_REVERSE)
        _safe_addstr(win, top, left, ("+" + "-" * (box_w - 2) + "+")[:box_w], attr)
        _safe_addstr(win, top + box_h - 1, left, ("+" + "-" * (box_w - 2) + "+")[:box_w], attr)
        for i, text in enumerate(lines[: box_h - 2]):
            _safe_addstr(win, top + 1 + i, left + 1, text.ljust(box_w - 2), curses.A_REVERSE)

    def _drain_live(self):
        if not self.live:
            return
        for _ in range(256):
            try:
                ts, raw, pkt = self.live.queue.get_nowait()
            except queue.Empty:
                break
            self.state.add_packet(ts, raw, pkt)
        if self.live.error:
            self.state.notice = f"수신 오류: {self.live.error}"
        if self.live.done:
            self.state.done = True

    def run(self, stdscr):
        curses.curs_set(0)
        stdscr.keypad(True)
        stdscr.timeout(100)
        self._init_colors()
        st = self.state
        while True:
            self._drain_live()
            max_y, max_x = stdscr.getmaxyx()
            stdscr.erase()
            if max_y < 14 or max_x < 48:
                _safe_addstr(stdscr, 0, 0, "wirefish TUI: 터미널 크기를 48x14 이상으로 키워주세요.", self._c("yellow", curses.A_BOLD))
                _safe_addstr(stdscr, 1, 0, f"현재 크기: {max_x}x{max_y}  (q: 종료)")
                stdscr.refresh()
                ch = stdscr.getch()
                if ch in (ord("q"), ord("Q")):
                    break
                continue

            (ly, lh), (dy, dh), (hy, hh) = self._layout(max_y, max_x)
            rec = st.current()
            dlines = detail_lines(rec) if rec else []
            per_line = 16 if max_x >= 76 else 8
            hlines = hexdump_lines(rec.raw, per_line) if rec else []

            status_tag = "PAUSED" if st.paused else ("DONE" if st.done else "CAPTURING")
            top_left = f" wirefish TUI | {st.mode}: {st.source_label} | filter: {self._filter_badge()}"
            top_right = f"[{status_tag}] "
            gap = max(1, max_x - len(top_left) - len(top_right))
            _fill_line(stdscr, 0, top_left + " " * gap + top_right, self._c("bar", curses.A_BOLD))

            list_rows = self._draw_list_panel(stdscr, ly, lh, max_x)
            detail_rows = self._draw_detail_panel(stdscr, dy, dh, dlines)
            hex_rows = self._draw_hex_panel(stdscr, hy, hh, hlines, per_line)

            pos = f"{st.selected + 1}/{len(st.filtered)}" if st.filtered else "0/0"
            panel_names = ("List", "Detail", "Hex")
            notice = f" | {st.notice}" if st.notice else ""
            stat_bar = f" {st.stats.line()} | sel {pos} | [{panel_names[st.focus]}]{notice}"
            _fill_line(stdscr, max_y - 2, stat_bar, self._c("bar"))

            if st.search_mode:
                _fill_line(stdscr, max_y - 1, f" /{st.search_buf}_  (Enter:적용  Esc:취소)", curses.A_BOLD)
            else:
                keys_bar = " ↑↓/jk:이동  Tab/1-3:패널  /:검색  Space:일시정지  f:자동추적  ?:도움말  q:종료"
                _safe_addstr(stdscr, max_y - 1, 0, keys_bar, curses.A_DIM)

            if st.show_help:
                self._draw_help_overlay(stdscr, max_y, max_x)

            stdscr.refresh()
            ch = stdscr.getch()
            if ch == -1 or ch == curses.KEY_RESIZE:
                continue
            if st.show_help:
                if ch in (ord("?"), 27, ord("q"), ord("Q"), ord(" "), 10, 13):
                    st.show_help = False
                continue
            if st.search_mode:
                if ch == 27:
                    st.search_mode = False
                elif ch in (10, 13, curses.KEY_ENTER):
                    st.set_search(st.search_buf)
                    st.search_mode = False
                elif ch in (curses.KEY_BACKSPACE, 127, 8):
                    st.search_buf = st.search_buf[:-1]
                elif 32 <= ch <= 126:
                    st.search_buf += chr(ch)
                continue

            if ch in (ord("q"), ord("Q")):
                break
            elif ch == ord("?"):
                st.show_help = True
            elif ch == ord("/"):
                st.search_mode = True
                st.search_buf = st.search_query
            elif ch == ord("\t"):
                st.set_focus(st.focus + 1)
            elif ch == curses.KEY_BTAB:
                st.set_focus(st.focus - 1)
            elif ch in (ord("1"), ord("2"), ord("3")):
                st.set_focus(ch - ord("1"))
            elif ch in (curses.KEY_DOWN, ord("j")):
                st.scroll_active(1, list_rows, len(dlines), detail_rows, len(hlines), hex_rows)
            elif ch in (curses.KEY_UP, ord("k")):
                st.scroll_active(-1, list_rows, len(dlines), detail_rows, len(hlines), hex_rows)
            elif ch == curses.KEY_NPAGE:
                page = max(1, (list_rows, detail_rows, hex_rows)[st.focus] - 1)
                st.scroll_active(page, list_rows, len(dlines), detail_rows, len(hlines), hex_rows)
            elif ch == curses.KEY_PPAGE:
                page = max(1, (list_rows, detail_rows, hex_rows)[st.focus] - 1)
                st.scroll_active(-page, list_rows, len(dlines), detail_rows, len(hlines), hex_rows)
            elif ch in (curses.KEY_HOME, ord("g")):
                st.jump_edge(False, list_rows, len(dlines), detail_rows, len(hlines), hex_rows)
            elif ch in (curses.KEY_END, ord("G")):
                st.jump_edge(True, list_rows, len(dlines), detail_rows, len(hlines), hex_rows)
            elif ch == ord(" ") and self.live:
                st.paused = not st.paused
                self.live.set_paused(st.paused)
                st.notice = "캡처 일시정지됨" if st.paused else ""
            elif ch in (ord("f"), ord("F")):
                st.follow = not st.follow
                if st.follow and st.filtered:
                    st.selected = len(st.filtered) - 1
                    st.detail_scroll = 0
                    st.hex_scroll = 0
                    st.ensure_list_visible(list_rows)


def run_selfcheck():
    """curses TTY 없이 pcap 리더·데모·3-패널 모델·필터·스크롤을 자체 점검한다."""
    opts = types.SimpleNamespace(proto=None, host=None, port=None, count=None)
    samples = demo_frames()
    assert len(samples) >= 12

    # 1. PcapWriter -> read_pcap 왕복 + 빅엔디언/나노초/손상 예외 검증
    with tempfile.TemporaryDirectory() as td:
        pcap_path = os.path.join(td, "demo.pcap")
        with closing(capture.PcapWriter(pcap_path)) as writer:
            for ts, raw in samples:
                writer.write(ts, raw)
        loaded = read_pcap(pcap_path)
        assert len(loaded) == len(samples)
        assert [r for _, r in loaded] == [r for _, r in samples]

        # 빅엔디언 나노초 pcap 검증
        be_path = os.path.join(td, "be_ns.pcap")
        ts0, raw0 = samples[0]
        with open(be_path, "wb") as fh:
            fh.write(b"\xa1\xb2\x3c\x4d" + struct.pack(">HHiIII", 2, 4, 0, 0, 65535, 1))
            fh.write(struct.pack(">IIII", 100, 500_000_000, len(raw0), len(raw0)) + raw0)
        be_loaded = read_pcap(be_path)
        assert len(be_loaded) == 1 and abs(be_loaded[0][0] - 100.5) < 1e-6 and be_loaded[0][1] == raw0

        # 잘못된 매직 / 링크타입 / 절단 레코드
        for name, data in (
            ("bad_magic.pcap", b"\x0a\x0d\x0d\x0a" + b"\x00" * 20),
            ("bad_link.pcap", struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 113)),
            ("trunc_rec.pcap", struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1, 0, 20, 20) + b"\x00" * 5),
        ):
            bad_p = os.path.join(td, name)
            with open(bad_p, "wb") as fh:
                fh.write(data)
            try:
                read_pcap(bad_p)
                raise AssertionError(f"expected ValueError for {name}")
            except ValueError:
                pass

    # 2. TuiState 적재·3-패널 출력·스크롤·검색·포커스 검증
    st = TuiState("DEMO", "sample frames", opts)
    for ts, raw in samples:
        pkt = parse(ts, raw)
        if output.match(pkt, opts):
            st.add_packet(ts, raw, pkt)
    assert st.stats.captured == len(samples)
    protos = {r.proto for r in st.records}
    assert {"ARP", "DNS", "TCP", "HTTP", "TLS", "ICMP", "ERR"} <= protos, protos

    # 상세·Hex 덤프 확인 (DNS 응답 + ICMP Quoted + Malformed)
    dns_rec = next(r for r in st.records if r.proto == "DNS" and "93.184.216.34" in r.info)
    d_lines = detail_lines(dns_rec)
    assert any("[DNS]" in t for _, t in d_lines) and any("[Wire]" in t for _, t in d_lines)
    h16 = hexdump_lines(dns_rec.raw, 16)
    h8 = hexdump_lines(dns_rec.raw, 8)
    assert h16[0].startswith("0000  ") and "|" in h16[0] and len(h8) >= len(h16)

    err_rec = next(r for r in st.records if r.proto == "ERR")
    assert any(s == "err" and "[ERROR]" in t for s, t in detail_lines(err_rec))

    # 검색·선택·포커스·스크롤 검증
    st.set_search("33434")
    assert len(st.filtered) == 1 and st.filtered[0].proto == "ICMP"
    matched_no = st.filtered[0].no
    st.set_search("")
    assert len(st.filtered) == len(samples) and st.current().no == matched_no

    st.jump_edge(False, 5, 10, 4, 10, 4)
    assert st.selected == 0
    st.set_focus(1)
    assert st.focus == 1
    st.scroll_active(2, 5, 10, 4, 10, 4)
    assert st.detail_scroll == 2
    st.set_focus(0)
    st.move_selection(3, 5)
    assert st.selected == 3 and st.detail_scroll == 0 and st.hex_scroll == 0
    st.jump_edge(True, 5, 10, 4, 10, 4)
    assert st.selected == len(samples) - 1

    # CLI 필터 연동 (ICMP 인용 포트 포함)
    q_opts = types.SimpleNamespace(proto=None, host="8.8.8.8", port=33434, count=None)
    matched = [r for ts, r in samples if output.match(parse(ts, r), q_opts)]
    assert len(matched) == 1

    # LiveCapture 모의 소켓 수신·개수 제한(-c)·정리 검증
    class _FakeSock:
        def __init__(self, frames):
            self._it = iter(frames)
        def settimeout(self, _t):
            pass
        def recvfrom(self, _n):
            try:
                return next(self._it), None
            except StopIteration:
                raise TimeoutError()
    live_opts = types.SimpleNamespace(proto=None, host=None, port=None, count=3)
    live = LiveCapture(_FakeSock([r for _, r in samples[:5]]), live_opts)
    live.start()
    deadline = time.time() + 2.0
    while not live.done and time.time() < deadline:
        time.sleep(0.02)
    live.stop()
    assert live.done and live.error is None and live.queue.qsize() == 3

    print("tui selfcheck: all checks passed")


def build_parser():
    ap = argparse.ArgumentParser(description="wirefish 3-패널 TUI (curses 표준 라이브러리)")
    src_group = ap.add_mutually_exclusive_group()
    src_group.add_argument("-i", dest="iface", help="실시간 캡처 인터페이스 (Linux, root/CAP_NET_RAW 필요)")
    src_group.add_argument("-r", dest="read_pcap", metavar="PCAP", help="분석할 .pcap 파일 경로")
    src_group.add_argument("--demo", action="store_true", help="샘플 패킷 데모 모드로 실행 (기본값)")
    ap.add_argument("-c", dest="count", type=int, help="필터를 통과한 패킷 N개만 표시/수집")
    ap.add_argument("-p", dest="proto", choices=("tcp", "udp", "icmp", "arp"), help="프로토콜 필터")
    ap.add_argument("--host", help="IPv4/ARP/ICMP 인용 주소 필터")
    ap.add_argument("--port", type=int, help="TCP/UDP/ICMP 인용 포트 필터 (실시간 캡처 시 미지정이면 SSH 22 제외)")
    ap.add_argument("-w", dest="pcap", help="필터를 통과한 패킷을 .pcap으로 저장")
    ap.add_argument("--selfcheck", action="store_true", help="비대화형 자체 점검 실행")
    return ap


def main(argv=None):
    opts = build_parser().parse_args(argv)
    if opts.selfcheck:
        return run_selfcheck()
    if opts.count is not None and opts.count <= 0:
        sys.exit("-c 값은 1 이상이어야 합니다")

    locale.setlocale(locale.LC_ALL, "")
    state = None
    try:
        with ExitStack() as stack:
            writer = stack.enter_context(closing(capture.PcapWriter(opts.pcap))) if opts.pcap else None
            live = None
            if opts.iface:
                sock = stack.enter_context(closing(capture.open_socket(opts.iface)))
                notice = "SSH(22) 기본 제외 (--port로 해제)" if opts.port is None else ""
                state = TuiState("LIVE", opts.iface, opts, notice=notice)
                live = LiveCapture(sock, opts, writer=writer)
                live.start()
                stack.callback(live.stop)
            elif opts.read_pcap:
                frames = read_pcap(opts.read_pcap)
                state = TuiState("PCAP", os.path.basename(opts.read_pcap), opts)
                for ts, raw in frames:
                    pkt = parse(ts, raw)
                    if not output.match(pkt, opts):
                        continue
                    state.add_packet(ts, raw, pkt)
                    if writer:
                        writer.write(ts, raw)
                    if opts.count and state.stats.captured >= opts.count:
                        break
            else:
                frames = demo_frames()
                state = TuiState("DEMO", "sample frames", opts, notice="샘플 데모 모드 (-i/-r 지정 가능)")
                for ts, raw in frames:
                    pkt = parse(ts, raw)
                    if not output.match(pkt, opts):
                        continue
                    state.add_packet(ts, raw, pkt)
                    if writer:
                        writer.write(ts, raw)
                    if opts.count and state.stats.captured >= opts.count:
                        break

            app = CursesApp(state, live=live)
            try:
                curses.wrapper(app.run)
            except KeyboardInterrupt:
                pass
    except (OSError, ValueError) as exc:
        sys.exit(f"TUI 실행 실패: {esc(str(exc))}")
    except curses.error as exc:
        sys.exit(f"터미널(TTY) 초기화 실패: {esc(str(exc))}")

    if state is not None:
        print(state.stats.line())


if __name__ == "__main__":
    main()
