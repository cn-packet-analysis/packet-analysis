# 테스트 명세

완료 기준: [요구사항](../01-func/01-requirements.md) · 구조·남은 작업: [기술 구조](../03-tech/01-architecture.md) · 실행: [루트 README](../../README.md#테스트)

## 검증 전략

CI는 무인자 자체 점검(`capture.py`), TUI 자체 점검(`tui.py --selfcheck`), 오프라인 정적·모의 검사(`verify.sh --offline`)를 실행하며, 캡처 권한·외부 트래픽·`tshark`·Wireshark가 필요한 실기 검사는 Linux에서 별도 수행한다.

### OS 공통 검사

[README 테스트](../../README.md#테스트) 명령으로 코드 500줄 상한, 송신 호출 부재, 고정·경계 프레임 파싱(ICMP Echo `id`/`seq` 및 Type 3/11 내부 인용 IPv4·UDP 포함), DNS 압축 이름·다중 응답·미지원 타입·절단 레코드, 모의 수신·pcap 저장·5종 분석 수집/판정, `stdout/stderr` 분리, 자원 정리를 검사한다(비-Linux는 실기 항목 SKIP).

TUI는 `python3 src/tui.py --selfcheck`로 `.pcap` 리더(리틀/빅 엔디언·µs/ns·절단/오류 검출), 샘플 데모 적재, 3-패널(목록·상세·Hex/ASCII) 렌더링·스크롤·검색 필터·일시정지·pcap 저장 동작을 비-TTY 환경에서도 자동 검증한다.

### Linux 실기 검사

1. [시작하기](../../README.md#시작하기)로 Python 버전과 인터페이스를 확인한다(`lo`는 MAC 대조 제외).
2. `tshark`, `wireshark`, `dig`, `curl`, `arping`, `ping`, `nslookup`, `netstat`, `traceroute`, `timeout`을 준비한다.
3. 일반 사용자 셸에서 `sudo -v && ./scripts/verify.sh eth0`를 실행한다(비-root 캡처 실패 검사를 위해 root 직접 실행 금지).
4. 자체 프로그램의 `-v` 출력 및 저장 `.pcap`을 Wireshark와 대조해 5종 명령어의 정상 동작을 검증한다.

| 대상 | Wireshark·자체 출력 대조 항목 |
| --- | --- |
| `nslookup` | UDP 53 질의·응답, DNS 헤더·`qname`·IN/A `answers` 및 `-v`의 `[Wire] hex=...` |
| `curl` | TCP 3-way handshake(원본 `seq`·`ack`), HTTP 요청·응답 첫 줄, FIN/RST 종료 |
| `netstat` | `netstat -an`의 로컬·원격 주소·포트·상태와 `curl` TCP 스트림 일치 여부 |
| `ping` | ICMP Echo Request(`type=8`)·Reply(`type=0`) 쌍의 `csum`·`id`·`seq`·IPv4 `ttl`·`[Payload]` |
| `traceroute` | 송신 UDP(`ttl`, IPv4 `id`, `dport` 33434~)와 ICMP `type=11/0`·`type=3/3`의 `[Quoted]` 원본 IPv4·UDP 포트 및 `--host`/`--port` 필터 일치 여부 |

스크립트가 트래픽을 발생시켜 [완료 기준](../01-func/01-requirements.md#완료-기준), 필터·통계, 장애 4종을 [verify.sh](../../scripts/verify.sh) 기준으로 대조한다.

### 결과 판정

FAIL은 0이어야 하며, 도구·트래픽 부족으로 발생한 필수 SKIP은 환경을 갖춰 재실행해 해소해야 완료 기준을 충족한다.

- **최신 Linux 실기 판정**: Ubuntu Linux(`wlo1`)에서 `TRACE_HOPS=12 ./scripts/verify.sh wlo1` 실행 결과 `PASS 19 / FAIL 0 / SKIP 0`(정적 5, 실기 `tshark` 대조 4, 필터·통계 5, 장애 주입 4, 5종 명령어 연계 1)을 확인했다. `python3 src/capture.py`, `python3 src/tui.py --selfcheck`, PTY 렌더링·2,021프레임 퍼징, `check_docs.py`(0건)도 모두 통과했다.
