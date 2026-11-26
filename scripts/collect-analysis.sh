#!/usr/bin/env bash
# 5종 명령어(nslookup·curl·netstat·ping·traceroute) 증거를 새 디렉터리에 보존한다.
# 결과 판정은 verify.sh에서 수행한다.
set -euo pipefail
if [ "${1:-}" = '--help' ]; then
  echo '사용법: [PING_TARGET=... TRACE_TARGET=... TRACE_HOPS=15 TRACE_PROBES=3] ./scripts/collect-analysis.sh <인터페이스> <새 결과 디렉터리>'
  exit 0
fi
[ "$#" -eq 2 ] || { echo '인터페이스와 새 결과 디렉터리가 필요합니다.' >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo 'Linux 실습 환경에서 실행하세요.' >&2; exit 1; }
for tool in python3 ip nslookup curl netstat ping traceroute tshark timeout sudo; do
  command -v "$tool" >/dev/null || { echo "필요한 도구가 없습니다: $tool" >&2; exit 1; }
done
cd "$(dirname "$0")/.."
iface=$1 out=$2
: "${DNS_TARGET:=example.com}" "${DNS_SERVER:=8.8.8.8}" "${HTTP_URL:=http://example.com/}" \
  "${HTTP_HOST:=example.com}" "${PING_TARGET:=8.8.8.8}" "${TRACE_TARGET:=8.8.8.8}" \
  "${TRACE_HOPS:=5}" "${TRACE_PROBES:=1}" "${CAPTURE_SEC:=12}"

ip link show dev "$iface" >/dev/null
sudo -v
mkdir -- "$out"  # 기존 자료 덮어쓰기 방지
out=$(cd "$out" && pwd)
capture_pid='' curl_pid=''
# 실패 시에도 timeout이 캡처를 종료할 때까지 기다려 파일과 소켓을 닫는다.
trap 'for pid in "$capture_pid" "$curl_pid"; do [ -n "$pid" ] && wait "$pid" || :; done' EXIT

{ date -Is; uname -a; python3 -V; ip -br addr; ip route; cat /etc/resolv.conf; } > "$out/environment.txt"

run_command() {
  local name=$1 code=0; shift
  printf '%q ' "$@" > "$out/$name.command"; printf '\n' >> "$out/$name.command"
  "$@" > "$out/$name.txt" 2>&1 || code=$?
  echo "$code" > "$out/$name.exit"
}

start_capture() {
  local name=$1
  sudo -n timeout -s INT --preserve-status "$CAPTURE_SEC" python3 src/capture.py \
    -i "$iface" -v -w "$out/$name.pcap" > "$out/$name.capture.txt" 2> "$out/$name.capture.err" &
  capture_pid=$!
  for ((i=0; i<100; i++)); do
    grep -q '22번 포트' "$out/$name.capture.err" && return
    kill -0 "$capture_pid" 2>/dev/null || break
    sleep 0.05
  done
  cat "$out/$name.capture.err" >&2
  echo '캡처를 시작하지 못했습니다.' >&2
  return 1
}

finish_capture() {
  local name=$1
  wait "$capture_pid"; capture_pid=''
  tshark -r "$out/$name.pcap" > "$out/$name.packets.txt" 2> "$out/$name.tshark.err"
}

capture_run() {
  local cap=$1 cmd=$2; shift 2
  start_capture "$cap"
  run_command "$cmd" "$@"
  finish_capture "$cap"
}

capture_run dns nslookup timeout 8 nslookup -type=A "$DNS_TARGET" "$DNS_SERVER"

start_capture http
# 연결 중과 종료 후를 기록한다. netstat 자체는 패킷을 생성하지 않는다.
run_command curl timeout 8 curl --noproxy '*' -4 -v --max-time 6 "$HTTP_URL" &
curl_pid=$!
for ((i=0; i<80; i++)); do
  { date -Is; netstat -an; } >> "$out/netstat.txt"
  sleep 0.1
done
wait "$curl_pid"; curl_pid=''
finish_capture http
stream=$(tshark -r "$out/http.pcap" -Y "http.host == \"$HTTP_HOST\"" -T fields -e tcp.stream 2>> "$out/http.tshark.err" | sort -nu | sed -n '1p')
[ -n "$stream" ] && tshark -r "$out/http.pcap" -q -z "follow,tcp,ascii,$stream" > "$out/http.stream.txt" 2>> "$out/http.tshark.err"

capture_run ping ping timeout 8 ping -4 -c 5 -i 0.5 "$PING_TARGET"
capture_run trace traceroute timeout 10 traceroute -4 -n -m "$TRACE_HOPS" -q "$TRACE_PROBES" -w 1 "$TRACE_TARGET"

printf '분석 자료: %s\n' "$out"
