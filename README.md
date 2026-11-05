# 패킷 캡처 프로그램

네트워크 프레임의 캡슐화와 계층별 프로토콜을 분석하는 수신 전용 CLI다. Ethernet·IPv4·ARP·TCP·UDP·ICMP 파싱, 포트 기반 HTTP·DNS 식별, pcap 저장을 지원한다([소스 구조](docs/03-tech/01-architecture.md#소스-구조)).

## 기술 스택

Python 3.10 이상 표준 라이브러리만 사용하며, 실시간 캡처는 Linux `AF_PACKET/SOCK_RAW` 기반이다([실행 환경과 제약](docs/01-func/01-requirements.md#실행-환경과-제약)).

## 시작하기

루트에서 버전과 무인자 자체 점검을 확인한다(외부 패키지 불필요). 실시간 캡처는 Linux와 root(또는 `CAP_NET_RAW`) 권한이 필요하며 `ip -br link`로 인터페이스를 확인한다.

```bash
python3 -V
python3 src/capture.py
python3 src/capture.py --help
```

## 사용 방법

```bash
sudo python3 src/capture.py -i eth0 -c 50 -v -w capture.pcap
sudo python3 src/capture.py -i eth0 -p tcp --port 80 -c 20
```

| 옵션 | 의미 |
| --- | --- |
| `-i` | 캡처 인터페이스(생략 시 자체 점검만 실행) |
| `-c` | 필터 통과 패킷 수 제한 |
| `-p` | `tcp`, `udp`, `icmp`, `arp` 프로토콜 필터 |
| `--host` | IPv4 송수신 주소 또는 ARP 프로토콜 주소 필터 |
| `--port` | TCP·UDP 송수신 포트 필터(생략 시 SSH 22번 제외) |
| `-v` | 계층별 상세 출력(DNS 전체 hex 포함) |
| `-w` | 필터 통과 패킷의 pcap 저장 경로 |

기본 출력은 패킷당 1줄이며 `Ctrl-C` 종료 시 통계를 출력한다([출력과 오류 처리](docs/01-func/01-requirements.md#출력과-오류-처리)). Linux에서 명령어별 분석 증거를 수집할 때는 다음 스크립트를 실행한다([분석 가이드](docs/analysis-guide.md)).

```bash
./scripts/collect-analysis.sh eth0 /tmp/com-net-analysis-01
```

## 테스트

일반 사용자 셸에서 실행한다(비-root 캡처 실패도 검증하므로 스크립트 자체를 root로 실행하지 않는다; 상세는 [검증 전략](docs/04-test/01-verification.md#검증-전략)).

```bash
./scripts/verify.sh
sudo -v && ./scripts/verify.sh eth0
```

## 관련 문서

- [작업 지침](AGENTS.md): 작업 순서와 문서 관리 규칙.
- [과제 핵심 정리](docs/assignment-summary.md): 2차 분석 과제의 제출·분석 요건과 3차 예고.
- [분석 가이드](docs/analysis-guide.md): 명령어별 증거 수집, Wireshark 대조, 결과서·발표 작성 틀.

### 문서 분류 기준

<!-- doc-standard:start — doc-standard에서 동기화한다. 이 구간은 직접 고치지 않는다. -->
| 위치 | 담는 내용 |
| --- | --- |
| [`docs/01-func/`](docs/01-func/01-requirements.md) | 범위, 역할별 기능, 업무 정책, 완료 기준 |
| [`docs/03-tech/`](docs/03-tech/01-architecture.md) | 아키텍처, 소스 구조, 데이터 모델, REST/IPC 계약 |
| [`docs/04-test/`](docs/04-test/01-verification.md) | 검증 방법, 판정 기준, 최신 판정과 증거 |
| `docs/` 루트·주제 폴더 | 비명세 자료(과제 안내, 보고서, 발표, 협업 규칙, 자료 수집 기록) |
| 코드 저장소 루트 README | 로컬 설치·실행·테스트 명령 |

API 상세 원본은 OpenAPI·라우터·DTO이며 명세에는 원본 위치와 한계만 적는다. 배포 절차는 `05-ops/`(없으면 기술 명세)에 두고 로컬 실행 명령은 README를 링크한다.
<!-- doc-standard:end -->
