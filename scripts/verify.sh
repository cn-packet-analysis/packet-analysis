#!/usr/bin/env bash
# 리눅스 실기 검증. docs/01-func/01-requirements.md 완료 정의와 필터·통계·장애 주입을 한 번에 돌린다.
#   ./scripts/verify.sh [iface]      root로 실행하지 말 것 — 비-root 실패 경로를 확인한다.
# 정답지는 tshark. 기대값의 사본은 여기 하나뿐이다 — 문서로 옮겨 적지 않는다.
# ponytail: set -e 대신 검사마다 && 체인. -e는 if 조건 안에서 어차피 꺼져 헛된 안심만 준다.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1                   # 어디서 실행해도 프로젝트 루트를 기준으로 검사한다

T=$(mktemp -d)
# kill "${TRAFFIC:-0}" 로 쓰면 미설정 시 0 = 프로세스 그룹 전체를 죽인다.
stop_traffic() {
  if [ -n "${TRAFFIC:-}" ]; then
    kill "$TRAFFIC" 2>/dev/null || :
    wait "$TRAFFIC" 2>/dev/null || :
    TRAFFIC=''
  fi
}
trap 'stop_traffic; rm -rf "$T"' EXIT

pass=0 fail=0 skip=0
say() { printf '\n%s\n' "$1"; }
ok()  { printf '  PASS  %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL  %s\n' "$1"; fail=$((fail + 1)); }
meh() { printf '  SKIP  %s — %s\n' "$1" "$2"; skip=$((skip + 1)); }   # 미확인. 실패가 아니다
try() { local n=$1; shift; if "$@"; then ok "$n"; else bad "$n"; fi; }

# 캡처한 값과 tshark 값을 비교한다. 한쪽이라도 비면 그 시점 트래픽이 없었다는 뜻 → 미확인.
compare() {
  if [ ! -s "$T/mine" ] || [ ! -s "$T/ref" ]; then meh "$1" '대조할 트래픽이 없었다'
  elif diff "$T/mine" "$T/ref"; then ok "$1"
  else bad "$1"; fi
}

# 메시지 1줄 + 종료 코드 1, 트레이스백 없음.
exits1_clean() {
  local rc=0
  "$@" >/dev/null 2>"$T/err" || rc=$?
  test "$rc" -eq 1 && test "$(wc -l < "$T/err")" -eq 1 && ! grep -q Traceback "$T/err"
}

say '정적 검사 (OS 무관)'

no_send() {   # '! grep'은 파일 없음(코드 2)까지 통과로 뒤집는다. 코드를 받아 판정한다.
  local rc=0
  grep -nE '\.(send|sendall|sendto)\(' ./src/*.py || rc=$?
  test "$rc" -eq 1                                  # 0=송신 호출 발견, 2=읽기 오류, 1=없음
}
selfcheck() { python3 src/capture.py >/dev/null; }
missing_tools() {
  local tool
  for tool in "$@"; do command -v "$tool" >/dev/null || printf '%s ' "$tool"; done
}
try '완료정의5  소켓 송신 호출 없음' no_send
try '완료정의4  무인자 자체 점검' selfcheck
local_checks() {
  PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}" python3 - <<'PY'
import contextlib, io, os, pathlib, struct, subprocess, sys, tempfile
from unittest.mock import Mock, patch
import capture, selfcheck
from parse import parse

# DNS: CNAME/AAAA 등 미지원 레코드는 건너뛰고 IN/A만 모은다.
def dns_packet(records, question=None, qd=1):
    question = selfcheck.dns()[12:] if question is None else question
    return selfcheck.ip4(17, selfcheck.udp(struct.pack('!6H', 1, 0x8180, qd, len(records), 0, 0)
                                        + question + b''.join(records)))

def rr(typ=1, cls=1, body=b'\x01\x02\x03\x04', size=None, name=b'\xc0\x0c'):
    return name + struct.pack('!HHIH', typ, cls, 60, len(body) if size is None else size) + body

for records, expected in (([rr(5, body=b'\xc0\x0c'), rr()], ['1.2.3.4']),
                          ([rr(28, body=b'\0' * 16), rr(cls=3)], []), ([], [])):
    p = parse(0, dns_packet(records))
    assert p['error'] is None and p['dns']['answers'] == expected, p
for record in (rr(size=3, body=b'abc'), rr(size=5), rr()[:5], rr(name=b'\xc0\xff'),
               rr(name=b'\xc0\x1d')):  # 29 = 응답 시작 위치, 자기 자신을 가리키는 포인터
    assert parse(0, dns_packet([record]))['error'], record
question = selfcheck.dns()[12:]
p = parse(0, dns_packet([rr()], question * 2, qd=2))
assert p['error'] is None and p['dns']['answers'] == ['1.2.3.4'], p
assert parse(0, dns_packet([], question[:-1], qd=1))['error']

sources = [pathlib.Path('src') / n for n in ('capture.py', 'parse.py', 'output.py', 'selfcheck.py')]
assert sum(len(p.read_text().splitlines()) for p in sources) <= 500

def run(args, sock):
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with patch('sys.argv', ['capture.py', '-i', 'test0', *args]), \
         patch('capture.open_socket', return_value=sock), \
         contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            capture.main()
        except SystemExit as e:
            code = 1
            assert isinstance(e.code, str) and len(e.code.splitlines()) == 1
    sock.close.assert_called_once()
    if 'malformed=ipv4' in out.getvalue():
        assert err.getvalue().count('[ERROR] ipv4: truncated\n') == 1
    return code, out.getvalue()

with tempfile.TemporaryDirectory() as d:
    path = str(pathlib.Path(d) / 'test.pcap')
    sock = Mock()
    frames = [selfcheck.ip4(6, selfcheck.tcp(sport=22)), selfcheck.TRUNCATED, selfcheck.TCP_SYN]
    sock.recvfrom.side_effect = [InterruptedError(), *((f, None) for f in frames)]
    code, out = run(['-c', '2', '-w', path], sock)
    assert code == 0 and len(out.splitlines()) == 3 and 'captured 2' in out
    assert 'malformed=ipv4' in out and 'truncated' not in out
    data = pathlib.Path(path).read_bytes()
    assert struct.unpack('<IHHiIII', data[:24]) == (0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    offset = 24
    for frame in frames[1:]:
        sec, usec, size, original = struct.unpack_from('<IIII', data, offset)
        assert 0 <= usec < 1000000 and size == original == len(frame)
        assert data[offset + 16:offset + 16 + size] == frame
        offset += 16 + size
    assert offset == len(data)

for failure, expected in ((KeyboardInterrupt(), 0), (OSError('receive failed'), 1)):
    sock = Mock()
    sock.recvfrom.side_effect = failure
    code, out = run([], sock)
    assert code == expected and (expected or 'captured 0' in out)

writer, sock = Mock(), Mock()
sock.recvfrom.return_value = (selfcheck.TCP_SYN, None)
writer.write.side_effect = OSError('disk full\nmessage')
with patch('capture.PcapWriter', return_value=writer):
    assert run(['-w', 'unused'], sock)[0] == 1
writer.close.assert_called_once()

writer = Mock()
with patch('sys.argv', ['capture.py', '-i', 'bad0', '-w', 'unused']), \
     patch('capture.PcapWriter', return_value=writer), \
     patch('capture.open_socket', side_effect=OSError('open failed')):
    try:
        capture.main()
    except SystemExit as e:
        assert isinstance(e.code, str) and len(e.code.splitlines()) == 1
    else:
        raise AssertionError('socket open must fail')
writer.close.assert_called_once()

sock = Mock()
sock.bind.side_effect = OSError('bad interface')
with patch('capture.sys.platform', 'linux'), patch('capture.socket.AF_PACKET', 17, create=True), \
     patch('capture.socket.socket', return_value=sock):
    try:
        capture.open_socket('bad0')
    except OSError:
        pass
    else:
        raise AssertionError('bind must fail')
sock.close.assert_called_once()

f = Mock()
f.write.side_effect = OSError('header write failed')
with patch('builtins.open', return_value=f):
    try:
        capture.PcapWriter('unused')
    except OSError:
        pass
    else:
        raise AssertionError('header write must fail')
f.close.assert_called_once()

# 네트워크 없이 수집·명령어 실패 보존·캡처 실패·덮어쓰기 방지를 검사한다.
with tempfile.TemporaryDirectory() as d:
    folder = pathlib.Path(d)
    binaries = folder / 'bin'
    binaries.mkdir()
    stubs = {
        'uname': 'echo Linux', 'ip': 'exit 0', 'date': 'echo 2026-11-04T00:00:00+00:00',
        'sudo': 'if [ "$1" = -v ]; then exit 0; fi; shift; exec "$@"',
        'nslookup': 'echo "Name: example.com"; exit "${MOCK_LOOKUP_EXIT:-0}"',
        'curl': 'echo "HTTP/1.1 200 OK"', 'netstat': 'echo "tcp session"',
        'traceroute': 'echo "1 192.0.2.1"',
        'sleep': 'exec /bin/sleep 0.01', 'tshark': 'echo 0',
        'timeout': '''if [ "$1" != -s ]; then shift; exec "$@"; fi
if [ "${MOCK_CAPTURE_FAILURE:-0}" = 1 ]; then echo "capture failed" >&2; exit 1; fi
while [ "$#" -gt 0 ]; do
  if [ "$1" = -w ]; then shift; printf pcap > "$1"; fi
  shift
done
echo '22번 포트(SSH)는 기본 제외됩니다.' >&2
echo 'captured 1'
''',
    }
    for name, body in stubs.items():
        script = binaries / name
        script.write_text('#!/bin/bash\n' + body + '\n')
        script.chmod(0o755)
    env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ['PATH'])
    def collect(destination, **extra):
        return subprocess.run(['bash', 'scripts/collect-analysis.sh', 'test0', str(destination)],
                              env=dict(env, **extra), capture_output=True, text=True, timeout=10)
    result = folder / 'result'
    completed = collect(result)
    assert completed.returncode == 0, completed.stderr
    for name in ('dns', 'http', 'trace'):
        assert (result / (name + '.pcap')).read_bytes() == b'pcap'
        assert (result / (name + '.packets.txt')).is_file()
    assert (result / 'http.stream.txt').is_file() and (result / 'netstat.txt').is_file()
    assert (result / 'nslookup.exit').read_text().strip() == '0'
    assert collect(result).returncode != 0
    assert (result / 'dns.pcap').read_bytes() == b'pcap'
    failed_command = folder / 'failed-command'
    assert collect(failed_command, MOCK_LOOKUP_EXIT='2').returncode == 0
    assert (failed_command / 'nslookup.exit').read_text().strip() == '2'
    assert collect(folder / 'failed-capture', MOCK_CAPTURE_FAILURE='1').returncode != 0

    # 실기 판정도 합성 pcap으로 통과·주소 불일치·ICMP 누락을 구분한다.
    evidence = folder / 'evidence'
    evidence.mkdir()
    def pcap(name, frames):
        with contextlib.closing(capture.PcapWriter(evidence / (name + '.pcap'))) as writer:
            for frame in frames:
                writer.write(0, frame)
    pcap('dns', [selfcheck.DNS_QUERY, dns_packet([rr()])])
    pcap('http', [selfcheck.TCP_SYN,
                  selfcheck.ip4(6, selfcheck.tcp(flags=0x18, body=b'GET / HTTP/1.1\r\n')),
                  selfcheck.ip4(6, selfcheck.tcp(sport=80, dport=52134, flags=0x18,
                                               body=b'HTTP/1.1 200 OK\r\n')),
                  selfcheck.ip4(6, selfcheck.tcp(flags=0x11))])
    probe = selfcheck.ip4(17, selfcheck.udp(b'probe', dport=33434))
    reply = selfcheck.ip4(1, struct.pack('!BBHI', 11, 0, 0, 0) + probe[14:42])
    pcap('trace', [probe, reply])
    for name in ('nslookup', 'curl', 'traceroute'):
        (evidence / (name + '.exit')).write_text('0\n')
    (evidence / 'nslookup.txt').write_text('example.com 1.2.3.4\n')
    (evidence / 'http.stream.txt').write_text('GET / HTTP/1.1\nHTTP/1.1 200 OK\n')
    session = evidence / 'netstat.txt'
    session.write_text('tcp 0 0 192.168.0.5:52134 8.8.8.8:80 TIME_WAIT\n')
    verifier = pathlib.Path('scripts/verify.sh').read_text().split('python3 - "$T/analysis" <<\'PY\'\n')[1].split('\nPY\n')[0]
    def judge():
        return subprocess.run([sys.executable, '-', str(evidence)], input=verifier,
                              env=env, capture_output=True, text=True, timeout=10)
    checked = judge()
    assert checked.returncode == 0, checked.stderr
    session.write_text('tcp 0 0 192.168.0.5:9999 8.8.8.8:80 TIME_WAIT\n')
    assert judge().returncode != 0
    session.write_text('tcp 0 0 192.168.0.5:52134 8.8.8.8:80 ESTABLISHED\n')
    assert judge().returncode == 0  # TIME_WAIT만 정답으로 강제하지 않는다.
    pcap('trace', [probe])
    assert judge().returncode != 0
PY
}
try '소스 500줄·모의 캡처·pcap·오류 정리·분석 수집/판정' local_checks
try '분석 수집 스크립트 문법' bash -n scripts/collect-analysis.sh

IFACE=${1:-$(ip route 2>/dev/null | awk '/^default/{print $5; exit}')}
GW=$(ip route 2>/dev/null | awk '/^default/{print $3; exit}')
lack=$(missing_tools tshark dig curl arping ping)

if [ -z "$IFACE" ] || [ -n "$lack" ]; then
  say '실기 검증 생략'
  [ -z "$IFACE" ] && echo '  인터페이스를 못 찾았다. ip -br link 로 확인 후 ./scripts/verify.sh <iface>'
  [ -n "$lack" ] && echo "  없는 도구: $lack"
  meh '실기 검증 전체' '리눅스 환경이 아니거나 도구가 없다'
else
  say "실기 검증 — iface=$IFACE gw=${GW:-없음}"
  sudo -v || { echo '  sudo 실패. setcap cap_net_raw+ep $(which python3) 도 가능'; exit 1; }

  # 검증 내내 트래픽을 흘린다. ponytail: 종료 시 kill만. 자식 ping·curl은 -W1/-m2로 알아서 끝난다.
  traffic() { while :; do
      ping -c1 -W1 8.8.8.8
      dig +short @8.8.8.8 example.com
      curl -s -m2 -o /dev/null http://example.com
    done; } >/dev/null 2>&1
  # 여기서 sudo 금지. 백그라운드 sudo(use_pty)가 전경 cap의 sudo와 겹치면 터미널 raw 모드
  # 저장·복원이 엇갈려 raw가 남고 출력이 계단처럼 밀린다. ARP는 c3의 sudo 안에서 만든다.
  traffic & TRAFFIC=$!

  # 모든 캡처에 시간 제한. -s INT면 capture.py가 KeyboardInterrupt로 정상 종료해 통계까지 찍고,
  # --preserve-status가 timeout의 124 대신 capture.py의 종료 코드를 그대로 넘긴다.
  cap() { local s=$1; shift
    sudo timeout -s INT --preserve-status "$s" python3 src/capture.py -i "$IFACE" "$@"; }

  c1() { cap 30 -c 50 -w "$T/c1.pcap" > "$T/c1.txt" &&
         awk '/^[0-9][0-9]:[0-9][0-9]:[0-9][0-9][.]/{n++} END {exit(n != 50)}' "$T/c1.txt" &&
         grep -q '^captured 50 ' "$T/c1.txt" &&
         test "$(tshark -r "$T/c1.pcap" | wc -l)" -eq 50; }
  try '완료정의1  캡처 50개 = pcap 50개' c1

  # 필드 대조는 한 번 잡아 두 번 본다. 필터 없이, IPv4 비단편 트래픽으로.
  cap 30 -c 20 -v -w "$T/f.pcap" > "$T/f.txt"

  # ① /\[IPv4\]/의 대괄호가 Ethernet 줄의 (IPv4)를 걸러낸다. 빼면 대조가 조용히 깨진다.
  awk '/\[IPv4\]/ {gsub(/ttl=|proto=/, ""); print $2, $4, $5, $6}' "$T/f.txt" > "$T/mine"
  tshark -r "$T/f.pcap" -Y 'eth.type == 0x0800' -T fields -E occurrence=f \
    -e ip.src -e ip.dst -e ip.ttl -e ip.proto | tr '\t' ' ' > "$T/ref"
  compare '완료정의2①  IPv4 src·dst·ttl·proto'

  # ② 재조립을 끄고 최외곽 헤더만 본다(ICMP 안에 인용된 내부 헤더 제외).
  awk '/\[TCP\]/ {gsub(/seq=|ack=/, ""); print $2, $4, $5, $8}' "$T/f.txt" > "$T/mine"
  tshark -r "$T/f.pcap" -o tcp.desegment_tcp_streams:FALSE \
    -Y 'eth.type == 0x0800 and ip.proto == 6 and ip.frag_offset == 0 and ip.flags.mf == 0' \
    -T fields -E occurrence=f -e tcp.srcport -e tcp.dstport -e tcp.seq_raw -e tcp.ack_raw | tr '\t' ' ' > "$T/ref"
  compare '완료정의2②  TCP sport·dport·원본 seq·ack'

  # 종료 요약을 라벨로 읽는다(위치가 아니라). captured N | TCP n UDP n ICMP n ARP n other n
  # ARP는 캡처와 같은 sudo 안에서 만든다(위 traffic 주석). arping은 20초 뒤 스스로 끝난다.
  c3() { sudo sh -c '[ -n "$2" ] && arping -c 20 -I "$1" "$2" </dev/null >/dev/null 2>&1 &
           exec timeout -s INT --preserve-status 45 python3 src/capture.py -i "$1" -c 60' \
           sh "$IFACE" "$GW" > "$T/c3.txt" &&
         tail -1 "$T/c3.txt" | awk '{for (i = 1; i < NF; i++) v[$i] = $(i + 1)}
           END {exit !(v["TCP"] > 0 && v["UDP"] > 0 && v["ICMP"] > 0 && v["ARP"] > 0)}'; }
  try '완료정의3  TCP·UDP·ICMP·ARP 네 카운터 모두 >0' c3

  say '필터 · 통계'
  cap 30 -p tcp -c 10 -w "$T/ftr.pcap" > "$T/ftr.txt"
  # 거른 것과 남긴 것을 함께 센다. 한쪽만 보면 캡처가 0건이어도 통과한다.
  TS='$1 ~ /^[0-9][0-9]:[0-9][0-9]:[0-9][0-9][.]/'
  no_icmp() { awk "$TS"' && $6 == "ICMP" {n++} END {exit(n + 0 != 0)}' "$T/ftr.txt"; }
  ten_tcp() { awk "$TS"' && $6 == "TCP"  {n++} END {exit(n + 0 != 10)}' "$T/ftr.txt"; }
  pcap_ftr() { test -s "$T/ftr.pcap" && test "$(tshark -r "$T/ftr.pcap" -Y 'not tcp' | wc -l)" -eq 0; }
  dns_seen() { cap 45 -c 40 -v > "$T/dns.txt" && grep -q 'example.com' "$T/dns.txt"; }
  counted()  { cap 20 -c 5 | tail -1 | grep -q '^captured 5 '; }
  try '필터  -p tcp 출력에 ICMP 없음' no_icmp
  try '필터  -p tcp 출력에 TCP 10개' ten_tcp
  try '필터  -w는 통과분만 기록' pcap_ftr
  try '통계  -v 출력에 DNS qname example.com' dns_seen
  try '통계  -c 5 종료 요약이 captured 5' counted

  say '장애 주입'
  sigint() { cap 5 > "$T/int.txt" 2>"$T/int.err" &&
             grep -q '^captured ' "$T/int.txt" && ! grep -q Traceback "$T/int.err"; }
  try '장애  -i nosuch0' exits1_clean sudo timeout 10 python3 src/capture.py -i nosuch0
  try '장애  -w /nosuchdir/x.pcap (캡처 시작 전)' \
      exits1_clean sudo timeout 10 python3 src/capture.py -i "$IFACE" -w /nosuchdir/x.pcap
  try '장애  Ctrl-C 후 통계 출력 + 종료 코드 0' sigint
  if [ "$(id -u)" -eq 0 ]; then meh '장애  비-root 권한 실패' 'root로 실행 중이다'
  else try '장애  비-root 권한 실패' exits1_clean timeout 10 python3 src/capture.py -i "$IFACE"; fi
fi

stop_traffic
say '과제 명령어 연계 검증'
analysis_tools=$(missing_tools nslookup curl netstat traceroute tshark timeout ip sudo)
if [ "$(uname -s)" != Linux ] || [ -z "$IFACE" ] || [ -n "$analysis_tools" ]; then
  meh 'nslookup·curl·netstat·traceroute 실기' "Linux·인터페이스 또는 도구 부족:$analysis_tools"
else
  analysis_checks() {
    ./scripts/collect-analysis.sh "$IFACE" "$T/analysis" || return 1
    PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}" python3 - "$T/analysis" <<'PY'
import pathlib, re, struct, subprocess, sys
from parse import parse

root = pathlib.Path(sys.argv[1])
def packets(name):
    data = (root / (name + '.pcap')).read_bytes()
    assert len(data) >= 24 and data[:4] == b'\xd4\xc3\xb2\xa1', name
    offset, result = 24, []
    while offset < len(data):
        _, _, size, _ = struct.unpack_from('<IIII', data, offset)
        raw = data[offset + 16:offset + 16 + size]
        assert len(raw) == size
        p = parse(0, raw)
        assert not p['error'], p['error']
        result.append(p)
        offset += 16 + size
    return result

for name in ('nslookup', 'curl', 'traceroute'):
    assert (root / (name + '.exit')).read_text().strip() == '0', name + ' failed'
dns = [p['dns'] for p in packets('dns') if 'dns' in p and p['dns']['qname'] == 'example.com']
assert any(not d['flags'] & 0x8000 for d in dns), 'DNS query missing'
answers = [a for d in dns if d['flags'] & 0x8000 for a in d['answers']]
assert answers and all(a in (root / 'nslookup.txt').read_text() for a in answers), 'DNS answer mismatch'
http = [p for p in packets('http') if 'tcp' in p and 80 in (p['tcp']['sport'], p['tcp']['dport'])]
assert any('SYN' in p['tcp']['flags'] for p in http), 'TCP SYN missing'
assert any(set(p['tcp']['flags']) & {'FIN', 'RST'} for p in http), 'TCP termination missing'
assert any(p.get('http', {}).get('line', '').startswith('GET ') for p in http), 'HTTP request missing'
assert any(p.get('http', {}).get('line', '').startswith('HTTP/') for p in http), 'HTTP response missing'
sessions = (root / 'netstat.txt').read_text()
assert any(re.search(r'\b' + re.escape(p['ipv4']['src'] + ':' + str(p['tcp']['sport'])) + r'\s+'
                     + re.escape(p['ipv4']['dst'] + ':' + str(p['tcp']['dport']))
                     + r'\s+(ESTABLISHED|TIME_WAIT|CLOSE_WAIT|FIN_WAIT1|FIN_WAIT2|LAST_ACK|CLOSING)\b', sessions)
           for p in http if p['tcp']['dport'] == 80), 'matching netstat session missing'
assert (root / 'http.stream.txt').is_file(), 'HTTP stream export missing'
trace = packets('trace')
assert any(p.get('ipv4', {}).get('dst') == '8.8.8.8' and
           33434 <= p.get('udp', {}).get('dport', 0) <= 33534 for p in trace), 'traceroute UDP probe missing'
assert any(p.get('icmp', {}).get('type') == 11 for p in trace), 'ICMP Time Exceeded missing'
quoted = subprocess.run(['tshark', '-r', str(root / 'trace.pcap'), '-Y',
                         'icmp.type == 11 && ip.dst == 8.8.8.8 && udp.dstport >= 33434 && udp.dstport <= 33534',
                         '-T', 'fields', '-e', 'frame.number'], capture_output=True, text=True, check=True)
assert quoted.stdout.strip(), 'ICMP response quoting traceroute probe missing'
PY
  }
  try '명령어 출력·DNS 응답·HTTP 흐름·세션 상태·traceroute' analysis_checks
fi

say "PASS $pass   FAIL $fail   SKIP $skip"
[ "$skip" -gt 0 ] && echo 'SKIP은 미확인이다. 실패가 아니니 사유를 보고 재실행한다.'
exit $((fail > 0))
