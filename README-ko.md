<div align="center">
  <img src="img/icon.png" alt="YAS-Web" width="128" />
  <h1>YAS-Web</h1>
  <b><p>영지식(Zero-Knowledge) 암호화 키 저장소 및 양자내성 암호화(PQC) 플랫폼</p></b>
  <p>
    <a href="https://github.com/k-atusa/Yas-Web/releases"><img src="https://img.shields.io/github/v/release/k-atusa/Yas-Web?style=for-the-badge&color=30b065" alt="Release"></a> 
    <a href="https://github.com/k-atusa/Yas-Web/blob/main/LICENSE"><img src="https://img.shields.io/github/license/k-atusa/Yas-Web?style=for-the-badge&color=b0305f" alt="License"></a> 
    <a href="https://hub.docker.com/r/d3vle0/yas-web"><img src="https://img.shields.io/docker/pulls/d3vle0/yas-web?style=for-the-badge&color=00a8fc" alt="Docker Pulls"></a> 
    <a href="https://github.com/k-atusa/Yas-Web/stargazers"><img src="https://img.shields.io/github/stars/k-atusa/Yas-Web?style=for-the-badge&color=ffd700" alt="Stars"></a> 
  </p>

  <p>
    <a href="README.md">🇺🇸 English</a> | <a href="README-ko.md">🇰🇷 한국어</a>
  </p>
</div>

## 키 구조 및 보안 경계

YAS-Web은 **계정 인증 수단**과 **암호화 키 보호 수단**을 분리하여 설계되었습니다. 따라서 서버나 로그인 계정이 탈취되더라도 사용자의 개인키는 복호화할 수 없습니다.

| 키 / 비밀값 | 용도 | 서버 노출 여부 | 보호 및 사용 방식 |
| --- | --- | --- | --- |
| **일반 계정 키 (계정 비밀번호)** | 계정 로그인, 세션 인증(JWT), 계정 탈퇴 및 `R0` 파생 | **노출됨** (인증 시 전송) | `/api/auth/*`로 전송되어 서버에서 `arg2st`(Argon2id + HMAC-SHA3-512)로 해싱 후 `password_hash`로 저장됩니다. PQC 개인키를 직접 복호화할 수는 없습니다. |
| **마스터키** | PQC 개인키 암·복호화 | **노출 안 됨** (클라이언트 전용) | 브라우저에서만 유지되는 하이픈(`-`) 구분 5단어 패스프레이즈입니다. `arg2st`로 AES-256-GCM 키를 파생해 로컬에서 PQC 개인키를 암호화/복호화합니다. |
| **PQC 키 쌍 (공개키 / 개인키)** | 종단간 암호화 및 전자서명 (`pqc1`) | 공개키: **노출됨**<br>개인키: **암호문만 저장** | 공개키는 상대방이 조회할 수 있도록 평문으로 저장됩니다. 개인키는 업로드 전 마스터키로 암호화되며 브라우저 메모리에서만 복호화됩니다. |

### 1. 일반 계정 키 (계정 비밀번호) — 서버 노출
- **인증 및 API 접근**: 회원가입, 로그인, 비밀번호 재확인, 계정 탈퇴 시 계정 비밀번호가 백엔드로 전송됩니다 (`/api/auth/signup`, `/api/auth/login`, `/api/auth/verify-password`, `/api/auth/delete-account`).
- **서버 측 저장**: 백엔드는 `arg2st`(Argon2id: `m=262144` KiB, `t=3`, `p=6` + HMAC-SHA3-512)로 해싱해 `password_hash`와 사용자별 32바이트 `r0Salt`를 저장합니다.
- **보관함 접근 권한일 뿐 복호화 키가 아님**: 로그인에 성공하면 암호화된 개인키 보관함(`GET /api/accounts/me/vault`)을 내려받을 수 있는 JWT가 발급되지만, **서버와 계정 비밀번호만으로는 PQC 개인키를 복호화할 수 없습니다.**
- **클라이언트 측 `R0` 파생**: 로그인 또는 비밀번호 재확인 시 브라우저는 서버가 내려준 `r0Salt`와 비밀번호를 사용해 메모리 내에서만 32바이트 결정적 비밀값 `R0 = arg2st(password, r0Salt)`를 파생합니다(서버로 재전송되지 않음). `R0`는 패스키 기반 마스터키 래핑/언래핑에만 사용됩니다.

### 2. 마스터키 — 클라이언트 전용 (영지식)
- **브라우저 외부로 유출되지 않음**: 마스터키는 클라이언트에서 생성되는 5단어 하이픈 구분 패스프레이즈로, **평문 상태로 서버에 전송되거나 저장되지 않습니다.**
- **개인키의 루트 비밀값**: 브라우저는 `arg2st`(`iterations=3`, `memoryCost=262144`, `parallelism=6`, `keyLength=32`, `hash="SHA3-512"`)로 마스터키에서 AES-256-GCM 키를 파생해 로컬에서 PQC 개인키를 암·복호화합니다. 서버에는 `{ cipherText, iv }`와 `kdf` 메타데이터만 업로드되며, 서버에는 복호화 엔드포인트 자체가 존재하지 않습니다.
- **침해 시 영향 범위**: 서버 데이터베이스, TLS 종단, 혹은 계정 비밀번호와 JWT가 모두 탈취되더라도 공격자는 마스터키 없이 저장된 PQC 개인키를 복호화할 수 없습니다.
- **멀티 디바이스 WebAuthn 패스키 연동 (`R0 + Ri`)**: 매번 마스터키를 입력하지 않고 개인키를 잠금 해제하려면 `prf` 확장을 지원하는 WebAuthn 패스키를 등록할 수 있습니다. 브라우저는 계정 비밀번호 기반의 `R0`와 하드웨어 인증기의 WebAuthn PRF 출력값 `Ri`를 결합해 `arg2st`로 AES-256-GCM 래핑 키를 파생하고, 마스터키를 암호화한 값(`encryptedMasterKey: { cipherText, iv, salt }`)만 서버에 저장합니다. 이 값을 풀려면 계정 비밀번호(`R0`)와 물리적 패스키(`Ri`) **두 가지 모두**가 필요합니다.

### 3. PQC 키 쌍 (공개키 & 개인키)
- **공개키**: 다른 사용자가 나에게 메시지나 파일을 암호화해 보내거나 서명을 검증할 수 있도록 서버에 평문으로 저장됩니다 (`GET /api/accounts/username/{username}`).
- **개인키**: 서버에서 받아온 암호화 보관함에서 브라우저 메모리 내로만 복호화되며, 60초가 지나거나 탭을 전환하거나 창이 비활성화되면 자동으로 메모리에서 지워집니다.

## 설치 및 실행

### 1. Docker Compose (권장)
사전 요구 사항: Docker 및 Docker Compose v2

`d3vle0/yas-web:latest`는 경량 Alpine 기반 멀티 아키텍처(`linux/amd64`, `linux/arm64`) 이미지이며, SQLite 데이터베이스를 `./data` 경로에 영구 저장합니다.

1. `docker-compose.yml` 파일을 생성합니다.
   ```yaml
   services:
     yas-web:
       image: d3vle0/yas-web:latest
       container_name: yas-web
       restart: unless-stopped
       ports:
         - "4000:4000"
       environment:
         # WebAuthn 패스키용 도메인 (운영 환경에서는 example.com 등 실제 도메인 지정)
         DOMAIN: localhost
         # 선택 사항: 미지정 시 서버 시작마다 메모리에 32바이트 랜덤 시크릿을 자동 생성합니다.
         # JWT_SECRET: change-this-to-a-random-secret-key
       volumes:
         - ./data:/app/data
   ```

2. 서비스를 시작합니다 (기본 접속 주소: `http://localhost:4000`):
   ```bash
   docker compose up -d
   ```

### 2. 사전 빌드된 바이너리 실행

1. [GitHub Releases](https://github.com/k-atusa/YAS-web/releases) 페이지에서 사용 중인 OS 및 아키텍처에 맞는 바이너리를 다운로드합니다.

2. 실행 권한을 부여합니다 (Linux / macOS):
   ```bash
   chmod +x yas-web*
   ```

3. 바이너리를 실행합니다 (백엔드 API와 내장 프론트엔드가 기본 `http://localhost:4000`에서 함께 실행됩니다):
   ```bash
   # Linux / macOS (와일드카드로 다운로드한 버전 자동 실행)
   ./yas-web-*

   # Windows (PowerShell / 명령 프롬프트)
   .\yas-web-*.exe
   ```

   *(선택)* 포트나 도메인 등의 설정을 변경하려면 바이너리와 같은 경로에 `.env` 파일을 생성하세요 ([`.env.example`](.env.example) 참고).

### 3. 소스 코드에서 직접 빌드
사전 요구 사항: Go 1.26+ 및 Node.js 18+

빌드된 프론트엔드(`index.html`, JS, CSS)는 `embed.FS`를 통해 Go 단일 바이너리 내부에 직접 임베딩됩니다.

```bash
# 1. 프론트엔드 빌드
cd frontend && npm install && npm run build && cd ..

# 2. 프론트엔드가 내장된 Go 단일 바이너리 빌드
cd backend && CGO_ENABLED=0 go build -ldflags="-s -w" -o ../yas-web-$(go env GOOS)-$(go env GOARCH) ./cmd/server && cd ..

# 3. 현재 OS 및 아키텍처용으로 빌드된 바이너리 실행
./yas-web-*
```

*(선택)* 포트나 도메인 등의 설정을 변경하려면 프로젝트 루트에 `.env` 파일을 생성하세요 ([`.env.example`](.env.example) 참고).

*(SQLite 데이터베이스는 `./data/yas-web.db`에 자동 저장됩니다)*
