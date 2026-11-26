#!/usr/bin/env python3
"""표준 라이브러리 curses 기반 wirefish 3-패널 TUI.

기존 CLI 4파일(capture/parse/output/selfcheck)의 파싱·필터·통계·pcap 저장을
그대로 재사용하며 실시간 캡처(-i), pcap 오프라인 분석(-r), 샘플 데모(--demo)를 제공한다.
"""
import argparse, curses, locale, os, queue, socket, struct, sys, tempfile, threading, time, types, unicodedata
from contextlib import ExitStack, closing
from dataclasses import dataclass

import capture, output
from parse import esc, parse

MAX_RECORDS = 50000
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}
ICMP_TYPES = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "Time Exceeded"}
PROTO_ORDER = ("http", "dns", "tls", "tcp", "udp", "icmp", "arp", "ipv4")
DETAIL_PREFIXES = (
    (("[Malformed]", "[ERROR]"), "err"),
    (("[HTTP]", "[DNS]", "[TLS]", "[Wire]"), "app"),
    (("[TCP]", "[UDP]", "[ICMP]", "[Quoted]"), "l4"),
    (("[Ethernet]", "[IPv4]", "[ARP]"), "l23"),
)
PROTO_STYLE = {
    "TCP": ("cyan", 0), "HTTP": ("green", 0), "TLS": ("green", 0), "UDP": ("blue", 0),
    "DNS": ("blue", curses.A_BOLD), "ICMP": ("magenta", 0), "ARP": ("yellow", 0), "ERR": ("red", curses.A_BOLD),
}
DETAIL_STYLE = {
    "meta": ("yellow", curses.A_BOLD), "l23": ("cyan", 0), "l4": ("magenta", 0),
    "app": ("green", curses.A_BOLD), "err": ("red", curses.A_BOLD), "muted": ("", curses.A_DIM),
}
HELP_LINES = (
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
)

def _clamp(val, hi):
    return max(0, min(hi, val))

def _char_width(ch):
    if unicodedata.combining(ch) or unicodedata.category(ch) in ("Mn", "Me", "Cf"):
        return 0
    return 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1

def _disp_width(text):
    return sum(_char_width(ch) for ch in text)

def _clip_cols(text, max_cols):
    if max_cols <= 0:
        return ""
    out, cols = [], 0
    for ch in text:
        w = _char_width(ch)
        if cols + w > max_cols:
            break
        out.append(ch)
        cols += w
    return "".join(out)

def _pad_cols(text, cols):
    clipped = _clip_cols(text, cols)
    return clipped + " " * max(0, cols - _disp_width(clipped))

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
    return "ERR" if pkt["error"] else next((output.LABEL[k] for k in PROTO_ORDER if k in pkt), "ETH")

def _endpoints(pkt):
    if ip := pkt.get("ipv4"):
        if l4 := pkt.get("tcp") or pkt.get("udp"):
            return f"{ip['src']}:{l4['sport']}", f"{ip['dst']}:{l4['dport']}"
        return ip["src"], ip["dst"]
    if arp := pkt.get("arp"):
        return arp["spa"], arp["tpa"]
    eth = pkt.get("eth", {})
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
        ans = f" -> {','.join(d['answers'])}" if d["answers"] else ""
        return f"{kind} id=0x{d['id']:04x} {esc(d['qname'] or '.')} (qtype={d['qtype']}){ans}"
    if "tls" in pkt:
        fl = ",".join(pkt.get("tcp", {}).get("flags", [])) or "-"
        return f"[{fl}] TLS encrypted ({len(pkt['payload'])}B)"
    if "tcp" in pkt:
        t = pkt["tcp"]
        return f"[{','.join(t['flags']) or '-'}] seq={t['seq']} ack={t['ack']} win={t['win']} len={len(pkt['payload'])}"
    if "udp" in pkt:
        return f"len={pkt['udp']['len']} payload={len(pkt['payload'])}B"
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
    return f"EtherType 0x{pkt.get('eth', {}).get('type', 0):04x} len={raw_len}"

def make_record(no, ts, raw, pkt=None):
    pkt = parse(ts, raw) if pkt is None else pkt
    proto, (src, dst), info = _proto_name(pkt), _endpoints(pkt), _info_text(pkt, len(raw))
    search_text = " ".join((str(no), proto, src, dst, info, output.detail(pkt), pkt["error"] or "")).lower()
    return PacketRecord(no, ts, raw, pkt, proto, src, dst, info, search_text)

def detail_lines(rec):
    """계층별 상세 패널용 (스타일 키, 텍스트) 줄 목록을 만든다."""
    ts_str = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(rec.ts))}.{int(rec.ts % 1 * 1000):03d}"
    lines = [("meta", f"Frame #{rec.no}: {len(rec.raw)} bytes on wire, captured {ts_str}")]
    for line in output.detail(rec.pkt).splitlines():
        s = line.lstrip()
        style = next((st for prefixes, st in DETAIL_PREFIXES if s.startswith(prefixes)), "muted")
        lines.append((style, line))
    if rec.pkt["error"]:
        lines.append(("err", "[ERROR] " + esc(rec.pkt["error"])))
    return lines

def hexdump_lines(raw, per_line=16):
    """Wireshark 스타일 오프셋 + Hex + ASCII 덤프 줄 목록을 만든다."""
    if not raw:
        return ["(empty frame)"]
    half, half_w = per_line // 2, per_line // 2 * 3 - 1
    out = []
    for off in range(0, len(raw), per_line):
        chunk = raw[off:off + per_line]
        hx = [f"{b:02x}" for b in chunk]
        if per_line >= 16:
            hex_part = f"{' '.join(hx[:half]):<{half_w}}  {' '.join(hx[half:]):<{half_w}}"
        else:
            hex_part = " ".join(hx).ljust(per_line * 3 - 1)
        ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        out.append(f"{off:04x}  {hex_part}  |{ascii_part:<{per_line}}|")
    return out

def read_pcap(path):
    """표준 libpcap(.pcap) 파일에서 (ts, raw) 목록을 읽는다."""
    with open(path, "rb") as fh:
        ghdr = fh.read(24)
        if len(ghdr) < 24:
            raise ValueError("pcap 글로벌 헤더가 잘렸습니다")
        if ghdr[:4] not in PCAP_MAGIC:
            raise ValueError("지원하지 않는 pcap 형식입니다(pcapng 또는 손상된 매직)")
        endian, scale = PCAP_MAGIC[ghdr[:4]]
        network = struct.unpack(endian + "HHiIII", ghdr[4:24])[5]
        if network != 1:
            raise ValueError(f"Ethernet(1) 링크타입만 지원합니다(현재 {network})")
        frames = []
        while rhdr := fh.read(16):
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
    ans = lambda ip: b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    dns_resp = struct.pack("!6H", 0x1234, 0x8180, 1, 2, 0, 0) + sc.dns()[12:] + ans("93.184.216.34") + ans("93.184.216.35")
    probe1 = sc.ip4(17, sc.udp(b"wirefish-trace-1", sport=51001, dport=33434), src="192.168.0.5", dst="8.8.8.8", ttl=1)
    probe2 = sc.ip4(17, sc.udp(b"wirefish-trace-2", sport=51002, dport=33435), src="192.168.0.5", dst="8.8.8.8", ttl=2)
    http_req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: wirefish\r\n\r\n"
    http_res = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<h1>Hello</h1>"
    arp_reply = sc.eth(0x0806, struct.pack(
        "!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 2,
        bytes.fromhex("112233445566"), socket.inet_aton("192.168.0.1"),
        bytes.fromhex("aabbccddeeff"), socket.inet_aton("192.168.0.5"),
    ))
    samples = [
        sc.ARP_REQ, arp_reply,
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
        self.mode, self.source_label, self.opts, self.notice = mode, source_label, opts, notice
        self.records, self.filtered, self.stats = [], [], output.Stats()
        self.focus = self.selected = self.list_scroll = self.detail_scroll = self.hex_scroll = 0
        self.follow, self.paused, self.done = mode == "LIVE", False, mode != "LIVE"
        self.search_query = self.search_buf = ""
        self.search_mode = self.show_help = False
        self._next_no = 1

    def _reset_subscroll(self):
        self.detail_scroll = self.hex_scroll = 0

    def _matches_search(self, rec):
        return all(tok in rec.search_text for tok in self.search_query.lower().split())

    def add_packet(self, ts, raw, pkt=None):
        rec = make_record(self._next_no, ts, raw, pkt)
        self._next_no += 1
        self.stats.add(rec.pkt)
        if len(self.records) >= MAX_RECORDS:
            evicted = self.records.pop(0)
            if self.filtered and self.filtered[0].no == evicted.no:
                self.filtered.pop(0)
                self.selected = max(0, self.selected - 1)
                self.list_scroll = max(0, self.list_scroll - 1)
        self.records.append(rec)
        if self._matches_search(rec):
            self.filtered.append(rec)
            if self.follow:
                self.selected = len(self.filtered) - 1
                self._reset_subscroll()
        return rec

    def current(self):
        return self.filtered[self.selected] if 0 <= self.selected < len(self.filtered) else None

    def set_search(self, query):
        prev_no = cur.no if (cur := self.current()) else None
        self.search_query = query.strip()
        self.filtered = [r for r in self.records if self._matches_search(r)]
        if not self.filtered:
            self.selected = self.list_scroll = 0
        else:
            self.selected = next((i for i, r in enumerate(self.filtered) if r.no == prev_no), 0)
        self._reset_subscroll()

    def set_focus(self, panel):
        self.focus = panel % 3

    def ensure_list_visible(self, visible_rows):
        rows = max(1, visible_rows)
        if self.selected < self.list_scroll:
            self.list_scroll = self.selected
        elif self.selected >= self.list_scroll + rows:
            self.list_scroll = self.selected - rows + 1
        self.list_scroll = _clamp(self.list_scroll, max(0, len(self.filtered) - rows))

    def move_selection(self, delta, visible_rows):
        if not self.filtered:
            self.selected = 0
            return
        new = _clamp(self.selected + delta, len(self.filtered) - 1)
        if new != self.selected:
            self.selected = new
            self._reset_subscroll()
        if self.selected < len(self.filtered) - 1:
            self.follow = False
        self.ensure_list_visible(visible_rows)

    def _scroll_sub(self, attr, total, rows, delta=None, to_end=False):
        max_off = max(0, total - max(1, rows))
        val = _clamp(getattr(self, attr) + delta, max_off) if delta is not None else (max_off if to_end else 0)
        setattr(self, attr, val)

    def scroll_active(self, delta, list_rows, detail_total, detail_rows, hex_total, hex_rows):
        if self.focus == 0:
            self.move_selection(delta, list_rows)
        elif self.focus == 1:
            self._scroll_sub("detail_scroll", detail_total, detail_rows, delta=delta)
        else:
            self._scroll_sub("hex_scroll", hex_total, hex_rows, delta=delta)

    def jump_edge(self, to_end, list_rows, detail_total, detail_rows, hex_total, hex_rows):
        if self.focus == 0:
            if not self.filtered:
                return
            self.selected = len(self.filtered) - 1 if to_end else 0
            self._reset_subscroll()
            if not to_end:
                self.follow = False
            self.ensure_list_visible(list_rows)
        elif self.focus == 1:
            self._scroll_sub("detail_scroll", detail_total, detail_rows, to_end=to_end)
        else:
            self._scroll_sub("hex_scroll", hex_total, hex_rows, to_end=to_end)

class LiveCapture:
    """백그라운드 스레드에서 AF_PACKET 프레임을 수신해 큐로 전달한다."""

    def __init__(self, sock, opts, writer=None):
        self.sock, self.opts, self.writer = sock, opts, writer
        self.queue = queue.Queue()
        self.stop_event, self.pause_event = threading.Event(), threading.Event()
        self.error, self.done = None, False
        self._thread = threading.Thread(target=self._run, name="wirefish-live", daemon=True)

    def start(self):
        self.sock.settimeout(0.2)
        self._thread.start()

    def set_paused(self, paused):
        (self.pause_event.set if paused else self.pause_event.clear)()

    def stop(self):
        self.stop_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def drain_to(self, state, limit=None):
        count = 0
        while limit is None or count < limit:
            try:
                state.add_packet(*self.queue.get_nowait())
                count += 1
            except queue.Empty:
                break

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
                self.queue.put_nowait((ts, raw, pkt))
                if self.opts.count and captured >= self.opts.count:
                    break
        except OSError as exc:
            if not self.stop_event.is_set():
                self.error = esc(str(exc))
        finally:
            self.done = True

def _safe_addstr(win, y, x, text, attr=0):
    max_y, max_x = win.getmaxyx()
    if not (0 <= y < max_y and x < max_x):
        return
    if x < 0:
        skip, idx = -x, 0
        while idx < len(text) and skip > 0:
            skip -= _char_width(text[idx])
            idx += 1
        text, x = text[idx:], max(0, -skip)
    limit = max_x - x - (y == max_y - 1)
    clipped = _clip_cols(text, limit)
    if clipped:
        try:
            win.addstr(y, x, clipped, attr)
        except curses.error:
            pass

def _fill_line(win, y, text, attr):
    max_y, max_x = win.getmaxyx()
    limit = max_x - (y == max_y - 1)
    _safe_addstr(win, y, 0, _pad_cols(text, limit), attr)

class CursesApp:
    """Wireshark 스타일 3-패널 curses UI."""

    def __init__(self, state, live=None):
        self.state, self.live, self.colors = state, live, {}

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
            "cyan": (curses.COLOR_CYAN, bg), "green": (curses.COLOR_GREEN, bg),
            "blue": (curses.COLOR_BLUE, bg), "magenta": (curses.COLOR_MAGENTA, bg),
            "yellow": (curses.COLOR_YELLOW, bg), "red": (curses.COLOR_RED, bg),
            "bar": (curses.COLOR_BLACK, curses.COLOR_CYAN), "active_hdr": (curses.COLOR_BLACK, curses.COLOR_WHITE),
        }
        for idx, (name, (fg, pbg)) in enumerate(pairs.items(), 1):
            try:
                curses.init_pair(idx, fg, pbg)
                self.colors[name] = curses.color_pair(idx)
            except curses.error:
                self.colors[name] = 0

    def _c(self, name, extra=0):
        return self.colors.get(name, 0) | extra

    def _style(self, table, key):
        name, extra = table.get(key, ("", 0))
        return self._c(name, extra)

    def _layout(self, max_y):
        body_h = max_y - 3
        list_h = max(4, min(body_h - 8, int(body_h * 0.44)))
        detail_h = max(4, min(body_h - list_h - 4, int(body_h * 0.30)))
        return (1, list_h), (1 + list_h, detail_h), (1 + list_h + detail_h, body_h - list_h - detail_h)

    def _filter_badge(self):
        o = self.state.opts
        parts = [x for x in (
            f"p={o.proto}" if o.proto else "",
            f"host={o.host}" if o.host else "",
            f"port={o.port}" if o.port is not None else ("port!=22" if self.state.mode == "LIVE" else ""),
            f"c={o.count}" if o.count else "",
            f"find='{self.state.search_query}'" if self.state.search_query else "",
        ) if x]
        return " ".join(parts) or "all"

    def _draw_panel_header(self, win, y, title, focused):
        attr = self._c("active_hdr", curses.A_BOLD) if focused else (curses.A_REVERSE | curses.A_DIM)
        _fill_line(win, y, f" {'▶' if focused else ' '} {title}", attr)

    def _draw_list_panel(self, win, y, h, w):
        st = self.state
        cnt = f"{len(st.filtered)}/{len(st.records)}" if st.search_query else f"{len(st.filtered)}"
        self._draw_panel_header(win, y, f"[1] Packet List ({cnt}){' [FOLLOW]' if st.follow else ''}", st.focus == 0)
        if h <= 1:
            return 0
        addr_w = 21 if w >= 100 else (16 if w >= 80 else 13)
        hdr = f"{'No.':>5} {'Time':<12} {'Proto':<5} {'Source':<{addr_w}} {'Destination':<{addr_w}} {'Len':>5} Info"
        _safe_addstr(win, y + 1, 0, hdr[:w], curses.A_UNDERLINE | curses.A_BOLD)
        rows = max(0, h - 2)
        if not rows:
            return 0
        st.ensure_list_visible(rows)
        if not st.filtered:
            _safe_addstr(win, y + 2, 2, "필터에 일치하는 패킷이 없습니다." if st.records else "패킷을 기다리는 중...", curses.A_DIM)
            return rows
        clip = lambda s: s if len(s) <= addr_w else s[:addr_w - 1] + "~"
        for row_i, rec in enumerate(st.filtered[st.list_scroll:st.list_scroll + rows]):
            line = f"{rec.no:>5} {output._ts(rec.ts):<12} {rec.proto:<5} {clip(rec.src):<{addr_w}} {clip(rec.dst):<{addr_w}} {len(rec.raw):>5} {rec.info}"
            attr = self._style(PROTO_STYLE, rec.proto)
            if st.list_scroll + row_i == st.selected:
                _fill_line(win, y + 2 + row_i, line, attr | curses.A_REVERSE | curses.A_BOLD)
            else:
                _safe_addstr(win, y + 2 + row_i, 0, line, attr)
        return rows

    def _draw_text_panel(self, win, y, h, title, focused, lines, scroll_attr, empty_msg, fmt):
        self._draw_panel_header(win, y, title, focused)
        rows = max(0, h - 1)
        if not rows:
            return 0
        if not lines:
            _safe_addstr(win, y + 1, 2, empty_msg, curses.A_DIM)
            return rows
        scroll = _clamp(getattr(self.state, scroll_attr), max(0, len(lines) - rows))
        setattr(self.state, scroll_attr, scroll)
        for row_i, item in enumerate(lines[scroll:scroll + rows]):
            text, attr = fmt(item)
            _safe_addstr(win, y + 1 + row_i, 1, text, attr)
        return rows

    def _draw_help_overlay(self, win, max_y, max_x):
        box_w = max(4, min(max_x - 4, max(_disp_width(x) for x in HELP_LINES) + 4))
        box_h = max(3, min(max_y - 2, len(HELP_LINES) + 2))
        top, left = max(0, (max_y - box_h) // 2), max(0, (max_x - box_w) // 2)
        border = ("+" + "-" * (box_w - 2) + "+")[:box_w]
        for row in range(box_h):
            _safe_addstr(win, top + row, left, " " * box_w, curses.A_REVERSE)
        _safe_addstr(win, top, left, border, self._c("bar", curses.A_BOLD))
        _safe_addstr(win, top + box_h - 1, left, border, self._c("bar", curses.A_BOLD))
        for i, text in enumerate(HELP_LINES[:box_h - 2]):
            _safe_addstr(win, top + 1 + i, left + 1, _pad_cols(text, box_w - 2), curses.A_REVERSE)

    def _drain_live(self):
        if not self.live:
            return
        self.live.drain_to(self.state, limit=256)
        if self.live.error:
            self.state.notice = f"수신 오류: {self.live.error}"
        if self.live.done:
            self.state.done = True

    def _handle_key(self, ch, bounds, panel_rows):
        st = self.state
        if ch in (-1, curses.KEY_RESIZE):
            return True
        if st.show_help:
            if ch in (ord("?"), 27, ord("q"), ord("Q"), ord(" "), 10, 13):
                st.show_help = False
            return True
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
            return True
        if ch in (ord("q"), ord("Q")):
            return False
        if ch == ord("?"):
            st.show_help = True
        elif ch == ord("/"):
            st.search_mode, st.search_buf = True, st.search_query
        elif ch in (ord("\t"), curses.KEY_BTAB):
            st.set_focus(st.focus + (1 if ch == ord("\t") else -1))
        elif ch in (ord("1"), ord("2"), ord("3")):
            st.set_focus(ch - ord("1"))
        elif ch in (curses.KEY_DOWN, ord("j"), curses.KEY_UP, ord("k")):
            st.scroll_active(1 if ch in (curses.KEY_DOWN, ord("j")) else -1, *bounds)
        elif ch in (curses.KEY_NPAGE, curses.KEY_PPAGE):
            page = max(1, panel_rows[st.focus] - 1)
            st.scroll_active(page if ch == curses.KEY_NPAGE else -page, *bounds)
        elif ch in (curses.KEY_HOME, ord("g"), curses.KEY_END, ord("G")):
            st.jump_edge(ch in (curses.KEY_END, ord("G")), *bounds)
        elif ch == ord(" ") and self.live:
            st.paused = not st.paused
            self.live.set_paused(st.paused)
            st.notice = "캡처 일시정지됨" if st.paused else ""
        elif ch in (ord("f"), ord("F")):
            st.follow = not st.follow
            if st.follow and st.filtered:
                st.selected = len(st.filtered) - 1
                st._reset_subscroll()
                st.ensure_list_visible(bounds[0])
        return True

    def run(self, stdscr):
        try:
            curses.curs_set(0)
        except curses.error:
            pass
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
                if stdscr.getch() in (ord("q"), ord("Q")):
                    break
                continue
            (ly, lh), (dy, dh), (hy, hh) = self._layout(max_y)
            rec = st.current()
            dlines = detail_lines(rec) if rec else []
            per_line = 16 if max_x >= 76 else 8
            hlines = hexdump_lines(rec.raw, per_line) if rec else []

            status = "PAUSED" if st.paused else ("DONE" if st.done else "CAPTURING")
            top_l = f" wirefish TUI | {st.mode}: {st.source_label} | filter: {self._filter_badge()}"
            top_r = f"[{status}] "
            top_l_fit = _clip_cols(top_l, max(0, max_x - _disp_width(top_r) - 1))
            gap = max(1, max_x - _disp_width(top_l_fit) - _disp_width(top_r))
            _fill_line(stdscr, 0, top_l_fit + " " * gap + top_r, self._c("bar", curses.A_BOLD))

            list_rows = self._draw_list_panel(stdscr, ly, lh, max_x)
            detail_rows = self._draw_text_panel(
                stdscr, dy, dh, f"[2] Packet Details — {f'Frame #{rec.no} ({rec.proto})' if rec else 'No packet selected'}",
                st.focus == 1, dlines, "detail_scroll", "패킷을 선택하면 계층별 상세 구조가 표시됩니다.",
                lambda item: (item[1], self._style(DETAIL_STYLE, item[0])),
            )
            hex_rows = self._draw_text_panel(
                stdscr, hy, hh, f"[3] Packet Bytes (Hex + ASCII) — {f'{len(rec.raw)} bytes ({per_line}B/row)' if rec else '0 bytes'}",
                st.focus == 2, hlines, "hex_scroll", "원시 프레임 바이트가 여기에 표시됩니다.", lambda item: (item, 0),
            )
            pos = f"{st.selected + 1}/{len(st.filtered)}" if st.filtered else "0/0"
            notice = f" | {st.notice}" if st.notice else ""
            _fill_line(stdscr, max_y - 2, f" {st.stats.line()} | sel {pos} | [{('List', 'Detail', 'Hex')[st.focus]}]{notice}", self._c("bar"))
            if st.search_mode:
                _fill_line(stdscr, max_y - 1, f" /{st.search_buf}_  (Enter:적용  Esc:취소)", curses.A_BOLD)
            else:
                _safe_addstr(stdscr, max_y - 1, 0, " ↑↓/jk:이동  Tab/1-3:패널  /:검색  Space:일시정지  f:자동추적  ?:도움말  q:종료", curses.A_DIM)
            if st.show_help:
                self._draw_help_overlay(stdscr, max_y, max_x)
            stdscr.refresh()
            if not self._handle_key(stdscr.getch(), (list_rows, len(dlines), detail_rows, len(hlines), hex_rows), (list_rows, detail_rows, hex_rows)):
                break

def run_selfcheck():
    """curses TTY 없이 pcap 리더·데모·3-패널 모델·필터·스크롤을 자체 점검한다."""
    opts = types.SimpleNamespace(proto=None, host=None, port=None, count=None)
    samples = demo_frames()
    assert len(samples) >= 12
    with tempfile.TemporaryDirectory() as td:
        pcap_path = os.path.join(td, "demo.pcap")
        with closing(capture.PcapWriter(pcap_path)) as writer:
            for ts, raw in samples:
                writer.write(ts, raw)
        loaded = read_pcap(pcap_path)
        assert [r for _, r in loaded] == [r for _, r in samples]
        be_path, raw0 = os.path.join(td, "be_ns.pcap"), samples[0][1]
        with open(be_path, "wb") as fh:
            fh.write(b"\xa1\xb2\x3c\x4d" + struct.pack(">HHiIII", 2, 4, 0, 0, 65535, 1))
            fh.write(struct.pack(">IIII", 100, 500_000_000, len(raw0), len(raw0)) + raw0)
        be_loaded = read_pcap(be_path)
        assert len(be_loaded) == 1 and abs(be_loaded[0][0] - 100.5) < 1e-6 and be_loaded[0][1] == raw0
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
    st = TuiState("DEMO", "sample frames", opts)
    for ts, raw in samples:
        pkt = parse(ts, raw)
        if output.match(pkt, opts):
            st.add_packet(ts, raw, pkt)
    assert st.stats.captured == len(samples) and {"ARP", "DNS", "TCP", "HTTP", "TLS", "ICMP", "ERR"} <= {r.proto for r in st.records}
    dns_rec = next(r for r in st.records if r.proto == "DNS" and "93.184.216.34" in r.info)
    d_lines = detail_lines(dns_rec)
    assert any("[DNS]" in t for _, t in d_lines) and any("[Wire]" in t for _, t in d_lines)
    h16, h8 = hexdump_lines(dns_rec.raw, 16), hexdump_lines(dns_rec.raw, 8)
    assert h16[0].startswith("0000  ") and "|" in h16[0] and len(h8) >= len(h16)
    err_rec = next(r for r in st.records if r.proto == "ERR")
    assert any(s == "err" and "[ERROR]" in t for s, t in detail_lines(err_rec))
    st.set_search("33434")
    assert len(st.filtered) == 1 and st.filtered[0].proto == "ICMP"
    matched_no = st.filtered[0].no
    st.set_search("")
    assert len(st.filtered) == len(samples) and st.current().no == matched_no
    st.jump_edge(False, 5, 10, 4, 10, 4); assert st.selected == 0
    st.set_focus(1); st.scroll_active(2, 5, 10, 4, 10, 4); assert st.focus == 1 and st.detail_scroll == 2
    st.set_focus(0); st.move_selection(3, 5); assert st.selected == 3 and st.detail_scroll == 0 and st.hex_scroll == 0
    st.jump_edge(True, 5, 10, 4, 10, 4); assert st.selected == len(samples) - 1
    q_opts = types.SimpleNamespace(proto=None, host="8.8.8.8", port=33434, count=None)
    assert len([r for ts, r in samples if output.match(parse(ts, r), q_opts)]) == 1
    class _FakeSock:
        def __init__(self, frames): self._it = iter(frames)
        def settimeout(self, _t): pass
        def recvfrom(self, _n):
            try: return next(self._it), None
            except StopIteration: raise TimeoutError()
    live = LiveCapture(_FakeSock([r for _, r in samples[:5]]), types.SimpleNamespace(proto=None, host=None, port=None, count=3))
    live.start()
    deadline = time.time() + 2.0
    while not live.done and time.time() < deadline:
        time.sleep(0.02)
    live.stop()
    assert live.done and live.error is None and live.queue.qsize() == 3
    import selfcheck as sc
    ssh_pkt = parse(0.0, sc.ip4(6, sc.tcp(sport=54321, dport=22, flags=0x02)))
    assert output.match(ssh_pkt, opts, exclude_ssh=False) and not output.match(ssh_pkt, opts, exclude_ssh=True)
    assert _disp_width("a한b") == 4 and _clip_cols("a한b", 2) == "a" and _disp_width(_pad_cols("한글", 5)) == 5
    with tempfile.TemporaryDirectory() as td:
        live_pcap = os.path.join(td, "live300.pcap")
        with closing(capture.PcapWriter(live_pcap)) as w:
            live300 = LiveCapture(_FakeSock([samples[4][1]] * 300), types.SimpleNamespace(proto=None, host=None, port=None, count=300), writer=w)
            live300.start()
            deadline = time.time() + 2.0
            while not live300.done and time.time() < deadline:
                time.sleep(0.01)
            live300.stop()
            st300 = TuiState("LIVE", "fake0", opts)
            live300.drain_to(st300, limit=256)
            live300.drain_to(st300)
        assert st300.stats.captured == len(read_pcap(live_pcap)) == 300
    print("tui selfcheck: all checks passed")

def build_parser():
    ap = argparse.ArgumentParser(description="wirefish 3-패널 TUI (curses 표준 라이브러리)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("-i", dest="iface", help="실시간 캡처 인터페이스 (Linux, root/CAP_NET_RAW 필요)")
    g.add_argument("-r", dest="read_pcap", metavar="PCAP", help="분석할 .pcap 파일 경로")
    g.add_argument("--demo", action="store_true", help="샘플 패킷 데모 모드로 실행 (기본값)")
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
                stack.callback(live.drain_to, state)
                stack.callback(live.stop)
            else:
                if opts.read_pcap:
                    mode, label, notice, frames = "PCAP", os.path.basename(opts.read_pcap), "", read_pcap(opts.read_pcap)
                else:
                    mode, label, notice, frames = "DEMO", "sample frames", "샘플 데모 모드 (-i/-r 지정 가능)", demo_frames()
                state = TuiState(mode, label, opts, notice=notice)
                for ts, raw in frames:
                    pkt = parse(ts, raw)
                    if not output.match(pkt, opts, exclude_ssh=False):
                        continue
                    state.add_packet(ts, raw, pkt)
                    if writer:
                        writer.write(ts, raw)
                    if opts.count and state.stats.captured >= opts.count:
                        break
            try:
                curses.wrapper(CursesApp(state, live=live).run)
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
