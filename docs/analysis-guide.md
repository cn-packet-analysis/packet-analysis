# 명령어와 패킷 연동 분석

실습 수집 절차와 결과서 작성 틀이다(제출 요건·배점은 [과제 요약](assignment-summary.md)). 빈칸은 실제 관찰값으로 채우며 예시 값을 복사하지 않는다.

## 자료 수집

1. Linux 환경에서 [도구·권한](04-test/01-verification.md#linux-실기-검사)과 인터페이스(`ip -br addr`)를 확인한다.
2. **Wireshark 실시간 캡처를 먼저 시작**한 뒤 일반 사용자 셸에서 실행한다(새 출력 경로 지정).

```bash
sudo -v
./scripts/verify.sh eth0
./scripts/collect-analysis.sh eth0 /tmp/com-net-analysis-01
```

3. 수집 종료 후 Wireshark 캡처를 `pcapng`로 저장한다(지정 도메인이 있으면 `nslookup -type=A`와 `curl -4 -v http://도메인/`을 추가 수집).

스크립트는 DNS(`8.8.8.8` 직접 질의)·HTTP(`example.com`)·traceroute를 각 12초간 수집해 환경 정보, 명령어·종료 코드(`*.command`, `*.exit`), 출력, `netstat` 스냅샷, 자체 캡처·pcap, `tshark` 요약, `http.stream.txt`를 보존한다. 외부 차단·응답 누락 시 사유를 기록하고 환경을 조정해 재수집한다.

## DNS: 원문에서 이름·주소로

- 증거: `nslookup.txt`, `dns.pcap`, `dns.capture.txt`, Wireshark(`dns.qry.name == "example.com"`, Follow → UDP Stream, Packet Bytes, `-v`의 `[Wire] hex=...`).
- 확인: 첫 12B 헤더(ID·flags·질문/레코드 수), 라벨 길이 바이트+문자열+`00`(예: `07`+`example`+`03`+`com`+`00`), QTYPE·QCLASS, 압축 포인터(예: `c0 0c` → offset 12), IN/A RDATA 4바이트와 반환 IPv4 대조(네임서버 IP 및 CNAME/AAAA와 구분).
- 기록: 조회 이름 [ ], 네임서버 [ ], DNS ID [ ], 질의/응답 번호 [ ], 이름 인코딩 hex [ ], 응답 IP와 RDATA [ ].

## TCP·HTTP: 연결에서 종료까지

- 증거: `curl.txt`, `http.pcap`, `http.capture.txt`, `http.stream.txt`, Wireshark(`http.request`, Follow → TCP Stream).
- 확인: `tcp.stream` 번호, SYN → SYN+ACK → ACK(양측 IP·포트 및 원본 `tcp.seq_raw`·`tcp.ack_raw`), HTTP 요청(메서드·경로·Host)·응답(상태·헤더·본문)과 `curl -v` 대조, FIN/ACK 또는 RST 종료 흐름.
- 기록: 스트림 번호 [ ], 클라이언트/서버 주소·포트 [ ], 연결 패킷 번호 [ ], 요청/응답 내용 [ ], 종료 패킷 번호와 방식 [ ].

## netstat: 세션과 TCP 흐름 연결

- 증거: `netstat.txt`와 위 `curl` TCP 스트림(소켓 상태 조회이므로 별도 패킷은 없음).
- 확인: 스냅샷 시각·로컬/원격 주소·포트·상태(`TIME_WAIT` 등)를 TCP 연결·종료 패킷과 대응(누락 시 `curl` 실행 중·직후 재수집).
- 기록: 스냅샷 시각 [ ], 해당 행 [ ], 일치하는 TCP 스트림 [ ], 상태와 종료 흐름의 관계 [ ].

## ping·traceroute: 3차 예고 대비

- `ping`: [실기 검증](04-test/01-verification.md#linux-실기-검사) 및 명령 출력과 ICMP Echo Request/Reply 번호·주소·type/code 대응.
- `traceroute` (`traceroute.txt`, `trace.pcap`): UDP probe의 TTL 증가(최대 5홉)·목적지 포트와 ICMP Time Exceeded(type 11) 내부 인용 IP·UDP 헤더 대응(`*`는 응답 미수신).
- 기록: probe TTL·목적지 포트 [ ], 대응 ICMP 번호·인용 헤더 [ ], 홉 주소 [ ], 미응답·제한 [ ].

## 결과서와 발표에 반영

[권장 구성](assignment-summary.md#결과서-권장-구성)과 [제출 요건](assignment-summary.md#제출-요건)에 맞춰 명령어 출력·패킷/스트림 캡처·연동 설명을 본문으로 작성한다. 발표(12분 이내)는 환경·목적(1분) → DNS(3분) → TCP·HTTP(4분) → 세션(2분) → 차이·결론(1분) 순으로 구성한다.
