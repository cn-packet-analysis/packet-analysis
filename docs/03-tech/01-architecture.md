# 기술 구조 및 설계 — wirefish

[요구사항](../01-func/01-requirements.md)을 구현하는 아키텍처·소스 구조와 남은 작업을 관리한다. 검증은 [테스트 명세](../04-test/01-verification.md), 실행 명령은 [README](../../README.md)를 따른다.

## 아키텍처와 경계

`AF_PACKET/SOCK_RAW` 수신(`EINTR` 재시도) → `(ts, raw)` → `struct` 파싱 → 필터 → 출력·통계·pcap 순으로 처리한다(REST API 미제공, pcap 파일은 소켓보다 먼저 오픈).

- 예외·정리: `parse()`는 `struct.error`, `IndexError`, `ValueError`(미지원 ARP 포함), `OSError`를 잡아 `pkt["error"]`에 기록한다. `ExitStack`으로 파일·소켓을 정리하며 치명적 실행 오류는 메시지 1줄과 종료 코드 1로 종료한다.
- 변경 원칙: CLI·`pkt` 키·파서 시그니처·출력 필드 위치·오류 처리를 유지한다. 명세 공백 결정은 `# DECISION: ...` 주석으로 남긴다.

## 소스 구조

| 파일 | 책임·계약 |
| --- | --- |
| [capture.py](../../src/capture.py) | CLI, 소켓 수신(`AF_PACKET`은 `open_socket` 내부 한정), pcap 저장(`PcapWriter`) |
| [parse.py](../../src/parse.py) | 공유 `pkt` 딕셔너리, 계층별 디스패치, `_header` 길이·DNS 경계 검증 |
| [output.py](../../src/output.py) | 요약·상세 출력(`show`), 필터(`match`), 통계(`Stats`) |
| [selfcheck.py](../../src/selfcheck.py) | 고정 프레임, 길이·단편·DNS 경계, `KEYS`, 출력 필드 자체 점검 |
| [tui.py](../../src/tui.py) | `curses` 기반 3-패널 TUI(실시간 캡처·`.pcap` 읽기·샘플 데모), 기존 파서·필터·통계 재사용 |
| [verify.sh](../../scripts/verify.sh) | 실기 `tshark` 대조 및 PASS/FAIL/SKIP 판정 |
| [collect-analysis.sh](../../scripts/collect-analysis.sh) | Linux 명령어 출력·자체 캡처·pcap·외부 해석 일괄 수집 |

### 파싱과 출력

- MAC은 `bytes.hex(":")`로 변환한다. DNS `wire`는 UDP 페이로드 전체 hex(상세 출력 전용), `answers`는 압축 이름·길이를 검증한 IN/A 주소 목록이다.
- IPv4 상세 출력의 `id`와 TCP 상세 출력의 원본 `ack`는 기존 필드 뒤에 배치해 검증 `awk` 필드 위치를 유지한다([페이로드 규칙](../01-func/01-requirements.md#출력과-오류-처리)).
- ICMP는 `type`·`code`·`csum`을 기본 파싱하며, 8B 이상 Echo(`type` 8/0)는 `id`·`seq`를, 오류 메시지(`type` 3/11)는 내부 인용 IPv4(`src`, `dst`, `ttl`, `proto`, `id`)와 원본 L4 포트(`sport`, `dport`)를 `quoted`에 기록해 `-v`에서 `[Quoted]` 줄로 출력한다. `--host`·`--port` 필터도 `quoted`를 함께 대조한다.
- 손상 패킷은 완성 계층까지 화면에 출력하고 `show()`가 오류 원인을 `stderr`에 기록한다.

### TUI 구조

- [tui.py](../../src/tui.py)는 기존 CLI 4파일(`capture`·`parse`·`output`·`selfcheck`)을 그대로 임포트해 파싱·필터·통계·pcap 저장 계약을 공유한다. 실시간 캡처(`-i`)에서는 `--port` 생략 시 SSH(22번)를 제외하고, 오프라인 분석(`-r`)·데모(`--demo`)에서는 전체 패킷을 표시한다.
- 입력 소스는 세 가지로 나뉜다. 실시간 캡처(`-i`)는 `open_socket()`에 짧은 타임아웃을 걸고 백그라운드 스레드에서 프레임을 수신해 큐로 전달하며, 종료 시 잔여 큐를 모두 비워 pcap과 통계 수량을 일치시킨다. 오프라인 분석(`-r`)은 표준 Ethernet(`.pcap`, 리틀·빅 엔디언 및 µs·ns 매직) 레코드를 순차 파싱한다. 인자 생략(`--demo`) 시 `selfcheck` 기반 샘플 패킷 세트를 적재해 OS·권한과 무관하게 3-패널을 탐색할 수 있다.
- 화면은 상단 헤더, 3-패널(패킷 목록·계층별 상세·Hex/ASCII 덤프), 하단 통계·단축키 바로 구성한다. `Tab`으로 포커스를 전환해 각 패널을 독립 스크롤하며, 실시간 모드에서는 `Space`로 일시정지, `f`로 최신 패킷 자동 추적을 제어하고 `/`로 화면 내 검색·필터를 적용한다.

## 남은 작업과 리스크

현재 남은 미확인 작업은 없다(Linux 실기 `PASS 19 / FAIL 0 / SKIP 0` 확인 완료, [테스트 명세](../04-test/01-verification.md#결과-판정)).

| 위험 요인 | 점검 방법 |
| --- | --- |
| 권한·수신 중단 / 수량 불일치 | `-i`·권한 전제 및 `parse()` 예외 처리 / pcap 엔디언·링크타입 및 `match()` 후 단일 카운트 확인 |
| 실기 `tshark`·Wireshark 필드 불일치 | 동일 필터·비단편·최외곽 `occurrence=f` 대조 후 실패 프레임 자체 점검 추가 |
| `traceroute` 중간 라우터·목적지 차단 | `ICMP Type 11/0` 및 최종 목적지 `Type 3/3`이 정상 응답하는 대상 서버를 `TRACE_TARGET`으로 지정해 확인 |

참고: [RFC 791](https://datatracker.ietf.org/doc/html/rfc791) · [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html) · [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)

[분류 기준](../../README.md#문서-분류-기준) · [기능 명세](../01-func/01-requirements.md) · [테스트 명세](../04-test/01-verification.md)
