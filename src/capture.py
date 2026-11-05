#!/usr/bin/env python3
"""Linux 수신 전용 캡처·pcap·CLI. 무인자는 OS 무관 자체 점검."""
import argparse, socket, struct, sys, time
from contextlib import ExitStack, closing
import output
from parse import esc, parse
class PcapWriter:
    def __init__(self, path):
        self.f = open(path, "wb")                   # 캡처 전에 열어 저장 실패를 먼저 드러낸다
        try:
            self.f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        except OSError:
            self.f.close()
            raise
    def write(self, ts, raw):
        self.f.write(struct.pack("<IIII", int(ts), int(ts % 1 * 1_000_000), len(raw), len(raw)))
        self.f.write(raw)
    def close(self):
        self.f.close()
def open_socket(iface):
    if not sys.platform.startswith("linux"):
        raise OSError("실시간 캡처는 Linux에서만 지원합니다")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))  # ETH_P_ALL
    try:
        s.bind((iface, 0))
    except OSError:
        s.close()
        raise
    return s
def sniff(sock):
    while True:
        try:
            frame, _ = sock.recvfrom(65535)
        except InterruptedError:                    # EINTR — 시그널로 깨면 재시도
            continue
        yield time.time(), frame

def main():
    ap = argparse.ArgumentParser(description="패킷 캡처·계층별 분석 (Linux, root 필요)")
    ap.add_argument("-i", dest="iface", help="캡처할 인터페이스. 없으면 자체 점검만 실행")
    ap.add_argument("-c", dest="count", type=int, help="필터를 통과한 패킷 N개만 캡처")
    ap.add_argument("-p", dest="proto", choices=("tcp", "udp", "icmp", "arp"))
    ap.add_argument("--host", help="IPv4 src/dst 또는 ARP spa/tpa")
    ap.add_argument("--port", type=int, help="TCP/UDP sport/dport")
    ap.add_argument("-v", dest="verbose", action="store_true", help="계층별 상세 출력")
    ap.add_argument("-w", dest="pcap", help="필터를 통과한 패킷을 pcap으로 저장")
    opts = ap.parse_args()
    if not opts.iface:
        import selfcheck
        return selfcheck.run()
    stats = output.Stats()
    try:
        with ExitStack() as stack:
            writer = stack.enter_context(closing(PcapWriter(opts.pcap))) if opts.pcap else None
            sock = stack.enter_context(closing(open_socket(opts.iface)))
            if opts.port is None:
                print("22번 포트(SSH)는 기본 제외됩니다. --port 로 지정하면 해제됩니다.", file=sys.stderr)
            try:
                for ts, raw in sniff(sock):
                    pkt = parse(ts, raw)
                    if not output.match(pkt, opts):
                        continue
                    stats.add(pkt)                 # 화면·pcap·-c·통계는 같은 통과분
                    output.show(pkt, opts.verbose)
                    if writer:
                        writer.write(ts, raw)
                    if opts.count and stats.captured >= opts.count:
                        break
            except KeyboardInterrupt:
                pass
    except OSError as e:
        sys.exit("캡처 실패 (Linux·인터페이스·권한·파일 확인): %s" % esc(str(e)))
    print(stats.line())

if __name__ == "__main__":
    main()
