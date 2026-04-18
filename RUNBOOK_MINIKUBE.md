# Minikube Red Team / Blue Team Runbook

This runbook deploys a local security lab that demonstrates:
- SSRF in web service
- Redis queue poisoning
- pickle deserialization RCE in vulnerable worker
- defensive validation in secure worker

## 1) Start Minikube

```powershell
minikube start --cpus=4 --memory=4096
kubectl version --short
```

If `minikube` is not recognized on Windows, run with full path:

```powershell
& "C:\Program Files\Kubernetes\Minikube\minikube.exe" start --driver=docker --cpus=4 --memory=4096
```

## 1.1) Install local script dependencies

```powershell
python -m pip install -r requirements-dev.txt
```

## 2) Build images inside Minikube

```powershell
minikube image build -t redis-injection/web-vulnerable:latest -f web/Dockerfile.vulnerable web
minikube image build -t redis-injection/web-safe:latest -f web/Dockerfile web
minikube image build -t redis-injection/worker-vulnerable:latest -f worker/Dockerfile.vulnerable worker
minikube image build -t redis-injection/worker-secure:latest -f worker/Dockerfile.secure worker
```

## 3) Deploy Kubernetes resources

```powershell
kubectl apply -f k8s/minikube-lab.yaml
kubectl apply -f k8s/network-policies.yaml
kubectl -n redis-injection-lab get pods
```

Wait until all pods are Running.

## 4) Expose vulnerable web endpoint locally

Open a dedicated terminal:

```powershell
kubectl -n redis-injection-lab port-forward svc/web-vulnerable 5000:5000
```

## 5) Red Team Attack Details (Step by Step)

Attack chain objective:
- Exploit SSRF on `web-vulnerable`
- Push malicious payload into Redis queue
- Trigger RCE when `worker-vulnerable` deserializes pickle data

Open a second terminal (keep the port-forward terminal from step 4 running), then execute the commands below one by one.

### 5.1) Confirm local access to web-vulnerable

```powershell
python -c "import requests; print(requests.get('http://127.0.0.1:5000', timeout=5).status_code)"
```

Explanation:
- This command confirms the `port-forward` tunnel is alive.
- Expected result: `200`.

### 5.2) Remove old marker to avoid false positives

```powershell
kubectl -n redis-injection-lab exec deploy/worker-vulnerable -- sh -c "rm -f /tmp/redteam_owned.txt"
```

Explanation:
- Ensures any marker found later was created by the current attack run.

### 5.3) Launch SSRF -> Redis poisoning

```powershell
python scripts/red_team_attack.py --web-base-url http://127.0.0.1:5000 --redis-host redis --queue mail_jobs_vuln
```

Explanation:
- The script generates a malicious pickle payload.
- The SSRF flaw in web-vulnerable forwards payload bytes to Redis.
- `worker-vulnerable` consumes from queue with BRPOP and triggers `pickle.loads()`.
- Expected output includes:
  - `SSRF request status: 200`
  - `Queue depth query status: 200`

### 5.4) Verify marker via script (automatic)

```powershell
python scripts/red_team_attack.py --web-base-url http://127.0.0.1:5000 --redis-host redis --queue mail_jobs_vuln --verify-k8s --namespace redis-injection-lab
```

Explanation:
- The script replays the attack and checks marker file existence inside the vulnerable pod.
- Expected output includes: `Marker file detected`.

### 5.5) Verify marker manually (proof)

```powershell
kubectl -n redis-injection-lab exec deploy/worker-vulnerable -- cat /tmp/redteam_owned.txt
```

Explanation:
- Final proof that RCE executed in `worker-vulnerable`.
- Expected output: `REDTEAM_OWNED`.

### 5.6) Check worker-vulnerable logs (supporting evidence)

```powershell
kubectl -n redis-injection-lab logs deploy/worker-vulnerable --tail=120
```

Explanation:
- Use this to correlate queue consumption timing and deserialization behavior.

## 6) Blue Team Verification Details (Step by Step)

Defense objective:
- Secure worker must reject malicious payload
- Secure worker must accept valid HMAC-signed payload
- NetworkPolicy objects must exist

### 6.1) Run verification script in Kubernetes mode

```powershell
python scripts/blue_team_verify.py --mode k8s --web-base-url http://127.0.0.1:5000 --namespace redis-injection-lab --wait-seconds 8
```

Explanation:
- The script pushes two jobs into `mail_jobs_secure`:
  - one malicious payload (pickle)
  - one valid payload (JSON + HMAC)
- It then reads secure worker logs and checks for NetworkPolicy resources.
- Expected checklist:
  - `[x] Rejected malicious payload`
  - `[x] Accepted valid signed payload`
  - `[x] Malicious marker was NOT created in secure worker`
  - `[x] NetworkPolicy objects found`

### 6.2) Manually confirm worker-secure logs

```powershell
kubectl -n redis-injection-lab logs deploy/worker-secure --tail=200
```

Explanation:
- Expected to see reject lines (`Dropped ...`) and accept lines (`Accepted signed job ...`).

### 6.3) Confirm policy resources exist

```powershell
kubectl -n redis-injection-lab get networkpolicy
```

Explanation:
- Confirms the namespace has the expected deny/allow network rules.

## 7) Optional local Docker Compose red/blue verification

This mode is useful when Minikube is not available. It verifies the same attack and defense logic locally.

```powershell
docker compose -f docker-compose.vulnerable.yml up -d --build
python scripts/red_team_attack.py --web-base-url http://localhost:5001 --redis-host redis --queue mail_jobs_vuln
docker compose -f docker-compose.vulnerable.yml exec -T worker-vulnerable cat /tmp/redteam_owned.txt
python scripts/blue_team_verify.py --mode compose --web-base-url http://localhost:5001 --redis-host redis --secure-queue mail_jobs_secure --compose-file docker-compose.vulnerable.yml --compose-service worker-secure
```

Notes:
- In compose mode, network policy checks are skipped by design.
- For defense logs: `docker compose -f docker-compose.vulnerable.yml logs worker-secure --tail=200`

Optional safe pipeline regression test (separate stack):

```powershell
docker compose up -d --build
python scripts/security_test.py
```

## 8) Cleanup

```powershell
kubectl delete -f k8s/network-policies.yaml
kubectl delete -f k8s/minikube-lab.yaml
minikube stop
```
