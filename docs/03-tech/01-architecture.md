# 기술 구조 및 설계 — 패킷 캡처 프로그램

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
| [verify.sh](../../scripts/verify.sh) | 실기 `tshark` 대조 및 PASS/FAIL/SKIP 판정 |
| [collect-analysis.sh](../../scripts/collect-analysis.sh) | Linux 명령어 출력·자체 캡처·pcap·외부 해석 일괄 수집 |

### 파싱과 출력

- MAC은 `bytes.hex(":")`로 변환한다. DNS `wire`는 UDP 페이로드 전체 hex(상세 출력 전용), `answers`는 압축 이름·길이를 검증한 IN/A 주소 목록이다.
- TCP 상세 출력의 원본 `ack`는 기존 필드 뒤에 배치해 검증 필드 위치를 유지한다([페이로드 규칙](../01-func/01-requirements.md#출력과-오류-처리)).
- 손상 패킷은 완성 계층까지 화면에 출력하고 `show()`가 오류 원인을 `stderr`에 기록한다.

## 남은 작업과 리스크

| 항목 | 대기 이유 | 재개 조건·작업 |
| --- | --- | --- |
| Linux 실기 대조 | 캡처 권한·실제 트래픽·`tshark` 필요 | Linux에서 [검증 전략](../04-test/01-verification.md#검증-전략) 실행 및 필수 SKIP 해소 |
| 분석 증거·결과서 | 실습 환경의 출력·pcap·스트림 필요 | [분석 가이드](../analysis-guide.md)·[제출 요건](../assignment-summary.md#제출-요건)에 따라 작성 |
| 3차 과제 대비 | 세부 일정·형식 미공지 | [과제 요약](../assignment-summary.md#예시와-미정-사항)을 후속 공지와 대조 |

| 위험 요인 | 점검 방법 |
| --- | --- |
| 권한·수신 중단 / 수량 불일치 | `-i`·권한 전제 및 `parse()` 예외 처리 / pcap 엔디언·링크타입 및 `match()` 후 단일 카운트 확인 |
| 실기 `tshark` 필드 불일치 | 동일 필터·비단편·최외곽 `occurrence=f` 대조 후 실패 프레임 자체 점검 추가 |

참고: [RFC 791](https://datatracker.ietf.org/doc/html/rfc791) · [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html) · [tshark](https://www.wireshark.org/docs/man-pages/tshark.html)

[분류 기준](../../README.md#문서-분류-기준) · [기능 명세](../01-func/01-requirements.md) · [테스트 명세](../04-test/01-verification.md)
