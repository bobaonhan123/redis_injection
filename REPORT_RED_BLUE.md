# Attack/Defense Report - Redis Injection Lab

## Scope

This report documents a local lab simulation for the kill-chain:

1. SSRF abuse in web service
2. Redis queue poisoning
3. pickle deserialization RCE in vulnerable worker pod
4. Blue-team controls in secure worker and Kubernetes network policy
5. Optional lateral blast to an internal pod before NetworkPolicy

The lab is for local security education only.

## Status Checklist

### Implementation Status (done in this workspace)

- [x] Added vulnerable SSRF web service (`web/app_vulnerable.py`)
- [x] Added vulnerable worker with unsafe pickle deserialization (`worker/worker_vulnerable.py`)
- [x] Added secure worker with JSON + HMAC validation (`worker/worker_secure.py`)
- [x] Added red-team attack script (`scripts/red_team_attack.py`)
- [x] Added blue-team verification script (`scripts/blue_team_verify.py`)
- [x] Added Minikube manifests (`k8s/minikube-lab.yaml`)
- [x] Added blast target service for lateral demo (`blast-target`)
- [x] Added Kubernetes NetworkPolicy rules (`k8s/network-policies.yaml`)
- [x] Added runbook with commands (`RUNBOOK_MINIKUBE.md`)

### Runtime Execution Status - Local Docker Compose (verified)

- [x] Local compose stack started (`docker-compose.vulnerable.yml`)
- [x] Red-team attack executed end-to-end
- [x] RCE marker found in vulnerable worker (`/tmp/redteam_owned.txt`)
- [x] Blue-team verification executed (compose mode)
- [x] Secure worker rejected malicious payload
- [x] Secure worker accepted valid signed payload
- [x] Secure worker did not create malicious marker (`/tmp/secure_worker_broken.txt`)

### Runtime Execution Status - Default Safe Stack (verified)

- [x] Default stack started with `docker compose up -d --build`
- [x] `scripts/security_test.py` completed successfully
- [x] Invalid email input was blocked
- [x] Signed job was accepted and processed
- [x] Tampered job was injected and rejected by worker logic
- [x] `SECURITY_TEST_EXIT=0`

### Runtime Execution Status - Minikube (verified)

Note: `minikube` was installed but not on PATH in this terminal. Verification used full binary path: `C:\Program Files\Kubernetes\Minikube\minikube.exe`.

- [x] Minikube cluster started
- [x] Images built and loaded into Minikube
- [x] Pods running in namespace `redis-injection-lab`
- [x] Red-team attack executed end-to-end
- [x] RCE marker found in vulnerable worker (`/tmp/redteam_owned.txt`)
- [x] Blue-team verification executed
- [x] Secure worker rejected malicious payload
- [x] Secure worker accepted valid signed payload
- [x] NetworkPolicy objects detected and enforced

## Evidence from Local Verification

Red-team evidence:

```text
[red-team] SSRF request status: 200
[red-team] Queue depth query status: 200
REDTEAM_OWNED
```

Blue-team evidence:

```text
Blue Team Checklist
[x] Rejected malicious payload
[x] Accepted valid signed payload
[x] Malicious marker was NOT created in secure worker
SCRIPT_EXIT=0
MARKER_ABSENT
```

Default safe stack evidence:

```text
[test] queue depth before: 0
[test] invalid email blocked: True
[test] pushed valid signed job
[test] pushed tampered job
[test] queue depth after: 0
SECURITY_TEST_EXIT=0
```

Kubernetes evidence:

```text
minikube
type: Control Plane
host: Running
kubelet: Running
apiserver: Running
kubeconfig: Configured

Kubernetes control plane is running at https://127.0.0.1:60190

[red-team] SSRF request status: 200
[red-team] Marker file detected at /tmp/redteam_owned.txt: REDTEAM_OWNED
RED_TEAM_K8S_EXIT=0

Blue Team Checklist
[x] Rejected malicious payload
[x] Accepted valid signed payload
[x] Malicious marker was NOT created in secure worker
[x] NetworkPolicy objects found
BLUE_TEAM_K8S_EXIT=0
```

## Architecture Summary

- `web-vulnerable`: intentionally vulnerable SSRF endpoint `/fetch?url=gopher://...`
- `redis`: message transport queue
- `worker-vulnerable`: uses `pickle.loads()` on attacker-controlled bytes
- `worker-secure`: accepts only UTF-8 JSON envelope signed with HMAC
- `blast-target`: internal HTTP echo service for lateral blast demo (pre-policy)

This demonstrates that Redis is the transport medium, while code execution occurs in the consumer.

## Attack Commands (Red Team)

### 1) Deploy lab

```powershell
kubectl apply -f k8s/minikube-lab.yaml
kubectl -n redis-injection-lab get pods
```

### 2) Port-forward vulnerable web

```powershell
kubectl -n redis-injection-lab port-forward svc/web-vulnerable 5000:5000
```

### 3) Trigger SSRF -> Redis LPUSH + blast lateral (pre-policy)

```powershell
python scripts/red_team_attack.py --web-base-url http://localhost:5000 --redis-host redis --queue mail_jobs_vuln --blast-host blast-target --blast-port 8080 --blast-path /
```

### 4) Confirm RCE marker in vulnerable worker

```powershell
kubectl -n redis-injection-lab exec deploy/worker-vulnerable -- cat /tmp/redteam_owned.txt
```

## Defense Commands (Blue Team)

### 1) Apply NetworkPolicy

```powershell
kubectl apply -f k8s/network-policies.yaml
kubectl -n redis-injection-lab get networkpolicy
```

### 2) Verify blast is blocked after policy

```powershell
python scripts/red_team_attack.py --web-base-url http://localhost:5000 --blast-host blast-target --blast-port 8080 --blast-path / --blast-only
```

### 3) Push malicious and valid signed jobs to secure queue, then inspect behavior

```powershell
python scripts/blue_team_verify.py --web-base-url http://localhost:5000 --redis-host redis --secure-queue mail_jobs_secure --namespace redis-injection-lab
```

### 4) Confirm secure worker logs

```powershell
kubectl -n redis-injection-lab logs deploy/worker-secure --tail=200
```

Expected log patterns:
- `[secure-worker] Dropped non-UTF8 job` or `[secure-worker] Dropped invalid JSON job`
- `[secure-worker] Accepted signed job for blue-team@example.com`

### 3) Check network policy controls

```powershell
kubectl -n redis-injection-lab get networkpolicy
```

## Key Findings

1. Redis itself is not the execution target; it is a delivery channel.
2. The vulnerable consumer (`pickle.loads`) is the RCE trigger.
3. HMAC-signed JSON plus strict parsing blocks this injection path.
4. NetworkPolicy reduces blast radius by restricting pod-to-pod traffic.

## Recommended Next Hardening Steps

1. Remove or lock SSRF endpoint in production.
2. Ban unsafe serializers (`pickle`, `yaml.load` without safe loader) for untrusted input.
3. Enforce `automountServiceAccountToken: false` where not required.
4. Add admission policies to block insecure pod specs.
5. Add SIEM alerts for suspicious queue payload sizes and worker deserialization errors.
