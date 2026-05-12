# Redis Queue Mail Lab (Manual redis-cli)

Demo lab gom cac thanh phan:
- Web form de nhap email admin
- Redis queue thao tac bang lenh `redis-cli` thu cong
- Scheduler tao job dinh ky
- Worker BRPOP job va gui email qua MailHog
- Script kiem thu an toan

## Red Team / Blue Team Minikube Lab

Bo file mo rong cho mo phong tan cong va phong thu tren Minikube:

- `RUNBOOK_MINIKUBE.md`: huong dan tung buoc setup -> attack -> defend -> cleanup
- `REPORT_RED_BLUE.md`: report checklist trang thai va lenh tai hien
- `k8s/minikube-lab.yaml`: namespace + deployments/services cho web-vulnerable, redis, worker-vulnerable, worker-secure, blast-target
- `k8s/network-policies.yaml`: network policy cho namespace lab
- `scripts/red_team_attack.py`: script red team SSRF -> Redis poison -> pickle RCE (+ blast lateral tuy chon)
- `scripts/blue_team_verify.py`: script blue team verify payload reject/accept + network policy

Neu muon chay nhanh local bang Docker Compose:

```powershell
docker compose -f docker-compose.vulnerable.yml up -d --build
python scripts/red_team_attack.py --web-base-url http://localhost:5001 --redis-host redis --queue mail_jobs_vuln
python scripts/blue_team_verify.py --mode compose --web-base-url http://localhost:5001 --redis-host redis --secure-queue mail_jobs_secure --compose-file docker-compose.vulnerable.yml --compose-service worker-secure
```

## 1) Chay he thong

```powershell
docker compose up -d --build
```

## 2) Truy cap

- Web form: http://localhost:5000
- MailHog: http://localhost:8025

## 3) Kiem tra logs

```powershell
docker compose logs -f worker
```

## 4) Chay script kiem thu

Can Python local + package requests.

```powershell
python -m pip install -r requirements-dev.txt
python scripts/security_test.py
```

## 5) Redis command thu cong de quan sat queue

```powershell
# xem do dai queue
docker compose exec redis redis-cli LLEN mail_jobs

# xem 1 phan tu dau queue
docker compose exec redis redis-cli LRANGE mail_jobs 0 0
```

## Luu y

- Lab nay khong tao lo hong khai thac that, nhung van minh hoa ro luong du lieu queue va cac buoc bao ve.
- Worker chi chap nhan job co HMAC hop le.
