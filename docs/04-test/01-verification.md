# 테스트 명세

완료 기준: [요구사항](../01-func/01-requirements.md) · 구조·남은 작업: [기술 구조](../03-tech/01-architecture.md) · 실행: [루트 README](../../README.md#테스트)

## 검증 전략

CI는 무인자 자체 점검을 실행하며, 캡처 권한·외부 트래픽·`tshark`가 필요한 실기 검사는 Linux에서 별도 수행한다.

### OS 공통 검사

[README 테스트](../../README.md#테스트) 명령으로 코드 500줄 상한, 송신 호출 부재, 고정·경계 프레임 파싱, DNS 압축 이름·다중 응답·미지원 타입·절단 레코드, 모의 수신·pcap 저장, `stdout/stderr` 분리, 자원 정리를 검사한다(비-Linux는 실기 항목 SKIP).

### Linux 실기 검사

1. [시작하기](../../README.md#시작하기)로 Python 버전과 인터페이스를 확인한다(`lo`는 MAC 대조 제외).
2. `tshark`, `dig`, `curl`, `arping`, `nslookup`, `netstat`, `traceroute`, `timeout`을 준비한다.
3. 일반 사용자 셸에서 `sudo -v && ./scripts/verify.sh eth0`를 실행한다(비-root 캡처 실패 검사를 위해 root 직접 실행 금지).

스크립트가 트래픽을 발생시켜 [완료 기준](../01-func/01-requirements.md#완료-기준), 필터·통계, 장애 4종을 [verify.sh](../../scripts/verify.sh) 기준으로 대조한다.

### 결과 판정

FAIL은 0이어야 하며, 도구·트래픽 부족으로 발생한 필수 SKIP은 환경을 갖춰 재실행해 해소해야 완료 기준을 충족한다.
