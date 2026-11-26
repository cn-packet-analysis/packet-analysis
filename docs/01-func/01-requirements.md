# 요구사항

## 개요

원시 프레임의 캡슐화·프로토콜을 분석하는 3차 과제 패킷 수집·분석 CLI(`wirefish`)와 표준 라이브러리 기반 3-패널 TUI 구현 요구사항이다. `nslookup`, `curl`, `netstat`, `ping`, `traceroute` 5종 명령어의 패킷 수집과 프로토콜 파싱을 지원한다.

## 범위

- 제외: 물리 신호, IPv6, GUI, 송신·주입·변조·재전송, IP 단편·TCP 스트림 재조립, 체크섬 검증, 무차별 모드, 페이로드 시그니처 식별.
- IPv4 단편은 IPv4까지, TCP DNS는 TCP까지만 분석하며 체크섬은 원본 정수로 보존한다.
- 선택 인터페이스인 터미널 3-패널 TUI(`src/tui.py`)는 기존 CLI 4파일과 분리해 제공하며, 실시간 캡처(Linux)·`.pcap` 파일 열기·샘플 데모 모드를 지원한다.

## 실행 환경과 제약

- Python ≥3.10 표준 라이브러리만 사용한다(`scapy`·`libpcap`·`dpkt` 금지, TUI도 `curses` 표준 라이브러리만 사용; `Wireshark`·`tcpdump`·`tshark`는 외부 검증 전용).
- 실시간 캡처는 Linux에서 root 또는 `CAP_NET_RAW` 권한으로 실행하며, 무인자 자체 점검과 TUI의 `.pcap` 읽기·샘플 데모 모드는 OS 무관하게 동작한다.
- 기존 CLI Python 소스 4파일(`capture.py`·`parse.py`·`output.py`·`selfcheck.py`)은 총 500줄 이하로 유지하되 길이 검증·자체 점검·오류 처리·CLI·패킷 딕셔너리·질문/응답별 DNS 오류 메시지와 완성 계층 보존 동작을 유지한다.
- 소스 코드와 실행·검증 스크립트만 유지하며 빌드·실행 생성 파일(`__pycache__`, `*.pcap` 등)은 포함하지 않는다.

## 기능 요구사항

- 필수(F-1~6): 인터페이스 실시간 수신 → Ethernet 헤더·타입 → IPv4·ARP → TCP·UDP·ICMP(`type`·`code`·`csum`, Echo `id`·`seq`, Type 3/11 내부 인용 IPv4·UDP/TCP 헤더) 파싱 → 포트 기반 HTTP·DNS 식별·요약 → 프로토콜·주소·포트 필터(ICMP 인용 IPv4·포트 포함).
- 권장(F-7~8): 종료 시 프로토콜별 통계 출력 및 pcap 저장.
- 확장(TUI): Wireshark 스타일 3-패널(패킷 목록·계층별 상세·Hex/ASCII 덤프) 화면에서 실시간 캡처(`-i`)·저장된 `.pcap` 파일(`-r`)·샘플 데모 패킷을 탐색하고 기존 필터·통계·pcap 저장 기능을 함께 사용한다.

## 출력과 오류 처리

- 출력: 기본 패킷당 1줄, `-v`는 계층별 들여쓰기(IPv4 `id`, TCP 원본 `seq`·`ack`, ICMP `csum`·Echo `id`/`seq`·오류 `[Quoted]` 인용 IPv4/UDP, DNS UDP 페이로드 전체 hex 포함). 패킷·통계는 `stdout`, 안내·오류는 `stderr`로 분리하며 `Ctrl-C` 시 통계 출력 후 종료한다.
- 페이로드(빈 페이로드 제외, 목적지 포트 우선): TCP 80/8080은 HTTP 첫 줄, UDP 53은 DNS 첫 질문(이름·타입·flags)과 응답 IN/A 주소 목록(이름·고정 헤더·길이 검증, 비-A 레코드는 길이만큼 건너뜀), TCP 443은 암호화 표시, 그 외(ICMP 8B 헤더 이후 데이터 포함)는 16B hex를 출력한다.
- 필터·오류: `--port` 생략 시 SSH(22번)를 제외하며 `--host`·`--port`는 ICMP 인용 IPv4·UDP/TCP 포트도 함께 대조한다. 화면·pcap·`-c`·통계는 동일 필터 통과분을 사용한다. 손상된 프레임도 필터 통과 시 완성 계층 출력·pcap·통계에 포함하고 원인을 `stderr`에 1줄 기록 후 계속한다([소스 구조](../03-tech/01-architecture.md#소스-구조)).

## 완료 기준

[verify.sh](../../scripts/verify.sh)와 [collect-analysis.sh](../../scripts/collect-analysis.sh), 그리고 Wireshark 대조로 다음을 검증한다([검증 전략](../04-test/01-verification.md#검증-전략)).

1. 화면 캡처와 pcap 저장 패킷 수가 각 50개로 일치한다.
2. `-v`의 IPv4·TCP 필드가 `tshark -T fields`와 일치한다.
3. `ping`, `curl`, `dig`, `arping` 트래픽을 ICMP, TCP, UDP, ARP로 분류하고 필터·통계·장애 주입 4종을 통과한다.
4. 무인자 자체 점검이 통과하고 소켓 송신 호출이 없다.
5. Linux에서 3차 과제 대상 5종(`nslookup`, `curl`, `netstat -an`, `ping`, `traceroute`)의 명령어 출력과 자체 캡처·pcap을 수집해 연동 동작(ICMP Echo `id`/`seq` 쌍, `traceroute` 인용 IPv4·UDP 포함)을 확인한다.
6. 자체 프로그램의 `-v` 출력과 저장 `.pcap`을 Wireshark와 대조해 정상 동작을 검증한다.

[분류 기준](../../README.md#문서-분류-기준) · [기술 명세](../03-tech/01-architecture.md) · [테스트 명세](../04-test/01-verification.md)
