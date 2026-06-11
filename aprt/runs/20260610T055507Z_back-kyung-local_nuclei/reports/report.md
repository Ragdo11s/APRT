# 보안 점검 보고서 — back-kyung

- 생성 시각: 2026-06-10 16:06 대한민국 표준시
- Run ID: `20260610T055507Z_back-kyung-local_nuclei`

## 1. 점검 개요

자동화 점검 도구를 사용해 대상 자산에 대한 비침투(safe) 스캔을 수행했습니다. 총 21건의 탐지 결과가 14개 항목으로 정리되었습니다.

## 2. 점검 범위

허용 호스트:
- https://can-fly.shop

대상:
- `back-kyung-local` — https://can-fly.shop

- 최대 위험 강도: safe
- Active scan 허용: False

## 3. 사용 도구

nuclei

## 4. 주요 결과 요약

| 심각도 | 건수 |
| --- | ---: |
| info | 21 |

> 즉시 조치가 필요한 high/critical 항목은 발견되지 않았습니다. 탐지된 항목은 대부분 자산·기술 식별(정보성) 결과입니다.

## 5. 취약점 목록

| # | 심각도 | 카테고리 | 항목 | 위치 | 탐지수 |
| ---: | --- | --- | --- | --- | ---: |
| 1 | info | crypto | Detect SSL Certificate Issuer | `can-fly.shop:443` | 1 |
| 2 | info | crypto | SSL DNS Names | `can-fly.shop:443` | 1 |
| 3 | info | crypto | TLS Version - Detect | `can-fly.shop:443` | 1 |
| 4 | info | header | HTTP Missing Security Headers | `https://can-fly.shop` | 8 |
| 5 | info | misconfiguration | SSH SHA-1 HMAC Algorithms Enabled | `can-fly.shop:22` | 1 |
| 6 | info | unknown | CAA Record | `can-fly.shop` | 1 |
| 7 | info | unknown | Java Spring Detection | `https://can-fly.shop/error` | 1 |
| 8 | info | unknown | NS Record Detection | `can-fly.shop` | 1 |
| 9 | info | unknown | OpenSSH Service - Detect | `can-fly.shop:22` | 1 |
| 10 | info | unknown | RDAP WHOIS | `https://rdap.gmoregistry.net/rdap/domain/can-fly.shop` | 1 |
| 11 | info | unknown | SSH Auth Methods - Detection | `can-fly.shop:22` | 1 |
| 12 | info | unknown | SSH Server Software Enumeration | `can-fly.shop:22` | 1 |
| 13 | info | unknown | WAF Detection | `https://can-fly.shop` | 1 |
| 14 | info | unknown | Wappalyzer Technology Detection | `https://can-fly.shop` | 1 |

## 6. 상세 결과

### 1. Detect SSL Certificate Issuer

- 심각도: **info**  |  카테고리: crypto  |  탐지: 1건
- 위치: `can-fly.shop:443`
- 설명: Extract the issuer's organization from the target's certificate. Issuers are entities which sign and distribute certificates.
- 매칭: `Let's Encrypt`

### 2. SSL DNS Names

- 심각도: **info**  |  카테고리: crypto  |  탐지: 1건
- 위치: `can-fly.shop:443`
- 설명: Extract the Subject Alternative Name (SAN) from the target's certificate. SAN facilitates the usage of additional hostnames with the same certificate.
- 매칭: `can-fly.shop, www.can-fly.shop`

### 3. TLS Version - Detect

- 심각도: **info**  |  카테고리: crypto  |  탐지: 1건
- 위치: `can-fly.shop:443`
- 설명: TLS version detection is a security process used to determine the version of the Transport Layer Security (TLS) protocol used by a computer or server.
It is important to detect the TLS version in order to ensure secure communication between two computers or servers.
- 매칭: `tls13`

### 4. HTTP Missing Security Headers

- 심각도: **info**  |  카테고리: header  |  탐지: 8건
- 위치: `https://can-fly.shop`
- CWE: CWE-693
- 설명: This template searches for missing HTTP security headers. The impact of these missing headers can vary.
- 탐지 세부 (8개):
  - `referrer-policy`
  - `cross-origin-embedder-policy`
  - `cross-origin-opener-policy`
  - `cross-origin-resource-policy`
  - `strict-transport-security`
  - `content-security-policy`
  - `permissions-policy`
  - `x-permitted-cross-domain-policies`

증적 (응답 일부):
```
HTTP/1.1 500 
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Content-Type: application/json
Date: Wed, 10 Jun 2026 05:57:41 GMT
Expires: 0
Pragma: no-cache
Server: nginx/1.28.3 (Ubuntu)
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

... (생략, 총 524자)
```

### 5. SSH SHA-1 HMAC Algorithms Enabled

- 심각도: **info**  |  카테고리: misconfiguration  |  탐지: 1건
- 위치: `can-fly.shop:22`
- 설명: The SSH server at the remote end is set up to allow the use of SHA-1 HMAC algorithms.

증적 (응답 일부):
```
{
  "Banner": "",
  "ServerID": {
    "Raw": "SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2",
    "ProtoVersion": "2.0",
    "SoftwareVersion": "OpenSSH_10.2p1",
    "Comment": "Ubuntu-2ubuntu3.2"
  },
  "ClientID": null,
  "ServerKex": {"cookie":"u9DIQzmqpTO50keuafkQVQ==","kex_algorithms":["mlkem768x25519-sha256","sntrup761x25519-sha512","sntrup761x25519-sha512@openssh.com","curve25519-sha256","curve2
... (생략, 총 3225자)
```

### 6. CAA Record

- 심각도: **info**  |  카테고리: unknown  |  탐지: 1건
- 위치: `can-fly.shop`
- CWE: CWE-200
- 설명: A CAA record was discovered. A CAA record is used to specify which certificate authorities (CAs) are allowed to issue certificates for a domain.

증적 (응답 일부):
```
;; opcode: QUERY, status: NOERROR, id: 33640
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232

;; QUESTION SECTION:
;can-fly.shop.	IN	 CAA

;; AUTHORITY SECTION:
can-fly.shop.	86400	IN	SOA	ns.gabia.co.kr. hosting.gabia.com. 2026052117 1800 600 1209600 86400

```

### 7. Java Spring Detection

- 심각도: **info**  |  카테고리: unknown  |  탐지: 1건
- 위치: `https://can-fly.shop/error`

증적 (응답 일부):
```
HTTP/1.1 500 
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Content-Type: application/json
Date: Wed, 10 Jun 2026 05:57:38 GMT
Expires: 0
Pragma: no-cache
Server: nginx/1.28.3 (Ubuntu)
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

... (생략, 총 496자)
```

### 8. NS Record Detection

- 심각도: **info**  |  카테고리: unknown  |  탐지: 1건
- 위치: `can-fly.shop`
- CWE: CWE-200
- 설명: An NS record was detected. An NS record delegates a subdomain to a set of name servers.
- 매칭: `ns.gabia.co.kr., ns1.gabia.co.kr., ns.gabia.net.`

증적 (응답 일부):
```
;; opcode: QUERY, status: NOERROR, id: 39853
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags:; udp: 1232

;; QUESTION SECTION:
;can-fly.shop.	IN	 NS

;; ANSWER SECTION:
can-fly.shop.	86400	IN	NS	ns.gabia.co.kr.
can-fly.shop.	86400	IN	NS	ns1.gabia.co.kr.
can-fly.shop.	86400	IN	NS	ns.gabia.net.

```

### 9. OpenSSH Service - Detect

- 심각도: **info**  |  카테고리: unknown  |  탐지: 1건
- 위치: `can-fly.shop:22`
- CWE: CWE-200
- 설명: OpenSSH service was detected.
- 매칭: `SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2`

증적 (응답 일부):
```
SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2

```

### 10. RDAP WHOIS

- 심각도: **info**  |  카테고리: unknown  |  탐지: 1건
- 위치: `https://rdap.gmoregistry.net/rdap/domain/can-fly.shop`
- CWE: CWE-200
- 설명: RDAP (Registration Data Access Protocol) is a standard defined by the IETF to replace the whois protocol
in queries for information about Internet resource records such as domain names, IP addresses, and ASNs.
- 매칭: `244`

증적 (응답 일부):
```
HTTP/1.1 200 OK
Connection: close
Accept-Ranges: bytes
Access-Control-Allow-Origin: *
Cache-Control: public, max-age=14400
Cf-Cache-Status: MISS
Cf-Ray: a0962414ce86322a-ICN
Content-Language: en
Content-Type: application/rdap+json
Date: Wed, 10 Jun 2026 05:57:51 GMT
Etag: e340fcae5e84fc385f605ea379f6f9050cb3a449
Expires: Wed, 10 Jun 2026 09:57:51 GMT
Server: cloudflare
Strict-Transpor
... (생략, 총 4969자)
```

### 11. SSH Auth Methods - Detection

- 심각도: **info**  |  카테고리: unknown  |  탐지: 1건
- 위치: `can-fly.shop:22`
- 설명: SSH (Secure Shell) authentication modes are methods used to verify the identity of users and ensure secure access to remote systems. Common SSH authentication modes include password-based authentication, which relies on a secret passphrase, and public key authentication, which uses cryptographic keys for a more secure and convenient login process. Additionally, multi-factor authentication (MFA) can be employed to enhance security by requiring users to provide multiple forms of authentication, such as a password and a one-time code.
- 매칭: `["publickey"]`

증적 (응답 일부):
```
{
  "Banner": "",
  "ServerID": {
    "Raw": "SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2",
    "ProtoVersion": "2.0",
    "SoftwareVersion": "OpenSSH_10.2p1",
    "Comment": "Ubuntu-2ubuntu3.2"
  },
  "ClientID": null,
  "ServerKex": {"cookie":"u9DIQzmqpTO50keuafkQVQ==","kex_algorithms":["mlkem768x25519-sha256","sntrup761x25519-sha512","sntrup761x25519-sha512@openssh.com","curve25519-sha256","curve2
... (생략, 총 3225자)
```

### 12. SSH Server Software Enumeration

- 심각도: **info**  |  카테고리: unknown  |  탐지: 1건
- 위치: `can-fly.shop:22`
- 매칭: `SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2`

증적 (응답 일부):
```
{
  "Banner": "",
  "ServerID": {
    "Raw": "SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2",
    "ProtoVersion": "2.0",
    "SoftwareVersion": "OpenSSH_10.2p1",
    "Comment": "Ubuntu-2ubuntu3.2"
  },
  "ClientID": null,
  "ServerKex": {"cookie":"u9DIQzmqpTO50keuafkQVQ==","kex_algorithms":["mlkem768x25519-sha256","sntrup761x25519-sha512","sntrup761x25519-sha512@openssh.com","curve25519-sha256","curve2
... (생략, 총 3225자)
```

### 13. WAF Detection

- 심각도: **info**  |  카테고리: unknown  |  탐지: 1건
- 위치: `https://can-fly.shop`
- CWE: CWE-200
- 설명: A web application firewall was detected.
- 매칭: `nginxgeneric`

증적 (응답 일부):
```
HTTP/1.1 500 
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Content-Type: application/json
Date: Wed, 10 Jun 2026 05:55:51 GMT
Expires: 0
Pragma: no-cache
Server: nginx/1.28.3 (Ubuntu)
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

... (생략, 총 524자)
```

### 14. Wappalyzer Technology Detection

- 심각도: **info**  |  카테고리: unknown  |  탐지: 1건
- 위치: `https://can-fly.shop`
- 매칭: `nginx`

증적 (응답 일부):
```
HTTP/1.1 500 
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Content-Type: application/json
Date: Wed, 10 Jun 2026 05:58:03 GMT
Expires: 0
Pragma: no-cache
Server: nginx/1.28.3 (Ubuntu)
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-Frame-Options: DENY

... (생략, 총 524자)
```

## 7. 우선 조치 항목

해당 없음. (high/critical 미발견)

## 8. 추가 확인 필요 사항

아래는 취약점은 아니지만 공격 표면(attack surface) 관점에서 수동 확인이 권장되는 항목입니다.

- Detect SSL Certificate Issuer (can-fly.shop:443)
- SSL DNS Names (can-fly.shop:443)
- TLS Version - Detect (can-fly.shop:443)
- 보안 헤더 누락 (https://can-fly.shop) — 8개 헤더 미설정. 헤더 추가 검토
- SSH 서비스 노출 (can-fly.shop:22) — 외부에서 22번 포트 접근 가능 여부 및 접근통제 확인 권장
- 도메인/DNS 등록정보 노출 (CAA Record) — 정상적 공개 정보이나 정찰에 활용될 수 있음
- Spring 기반 확인 (https://can-fly.shop/error) — actuator 등 관리 엔드포인트 노출 여부 별도 점검 권장
- 도메인/DNS 등록정보 노출 (NS Record Detection) — 정상적 공개 정보이나 정찰에 활용될 수 있음
- 도메인/DNS 등록정보 노출 (RDAP WHOIS) — 정상적 공개 정보이나 정찰에 활용될 수 있음
- WAF 탐지 (https://can-fly.shop) — 우회 가능성은 별도 검증 필요
- Wappalyzer Technology Detection (https://can-fly.shop)

---

> 본 보고서는 자동 생성되었으며, 모든 항목은 수동 검증 전까지 미확인(not_tested) 상태입니다. 정보성(info) 항목은 그 자체로 취약점을 의미하지 않습니다.