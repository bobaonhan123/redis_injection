# Runbook Minikube dễ hiểu - Redis Injection Lab

Runbook này dành cho lab local trên Minikube. Chỉ chạy trong namespace
`redis-injection-lab`, không dùng các lệnh tấn công này với hệ thống không được phép kiểm thử.

## Mục tiêu

Bạn sẽ kiểm tra 2 chuyện:

1. Red team: `web-vulnerable` bị SSRF, đẩy payload vào Redis, `worker-vulnerable` deserialize bằng `pickle` và tạo marker `/tmp/redteam_owned.txt`.
2. Blue team: `worker-secure` không chạy payload độc hại, chỉ nhận job JSON có HMAC hợp lệ, và NetworkPolicy chặn lateral blast.

Kết quả red team được xem là thành công khi thấy:

```text
[red-team] SSRF request status: 200
[red-team] Marker file detected at /tmp/redteam_owned.txt: REDTEAM_OWNED
```

Kết quả blue team được xem là thành công khi thấy:

```text
Blue Team Checklist
[x] Rejected malicious payload
[x] Accepted valid signed payload
[x] Malicious marker was NOT created in secure worker
[x] NetworkPolicy objects found
```

## 1. Chuẩn bị

Cài dependency cho script local:

```powershell
python -m pip install -r requirements-dev.txt
```

Khởi động Minikube:

```powershell
minikube start --cpus=4 --memory=4096
```

Nếu Windows không nhận `minikube` trong PATH, dùng đường dẫn đầy đủ:

```powershell
& "C:\Program Files\Kubernetes\Minikube\minikube.exe" start --driver=docker --cpus=4 --memory=4096
```

Kiểm tra cluster:

```powershell
minikube status
kubectl version
```

## 2. Build image vào Minikube

Chạy 4 lệnh này từ thư mục repo:

```powershell
minikube image build -t redis-injection/web-vulnerable:latest -f web/Dockerfile.vulnerable web
minikube image build -t redis-injection/web-safe:latest -f web/Dockerfile web
minikube image build -t redis-injection/worker-vulnerable:latest -f worker/Dockerfile.vulnerable worker
minikube image build -t redis-injection/worker-secure:latest -f worker/Dockerfile.secure worker
```

## 3. Deploy lab

```powershell
kubectl apply -f k8s/minikube-lab.yaml
kubectl -n redis-injection-lab get pods
```

Chờ tất cả pod ở trạng thái `Running`:

```text
redis
web-vulnerable
web-safe
worker-vulnerable
worker-secure
blast-target
```

## 4. Mở port-forward đúng service

Script red team cần gọi đúng service `web-vulnerable`, vì endpoint `/fetch` chỉ có ở bản vulnerable.

Mở một terminal riêng và giữ lệnh này chạy:

```powershell
kubectl -n redis-injection-lab port-forward svc/web-vulnerable 5000:5000
```

Kiểm tra đúng service:

```powershell
python -c "import requests; r=requests.get('http://127.0.0.1:5000/?format=json', timeout=5); print(r.status_code); print(r.text)"
```

Kỳ vọng có chữ:

```text
web-vulnerable-ssrf
```

Nếu port `5000` đang bị dùng bởi `web-safe` hoặc process khác, dùng port khác, ví dụ `5001`:

```powershell
kubectl -n redis-injection-lab port-forward svc/web-vulnerable 5001:5000
```

Khi đó thay mọi URL `http://127.0.0.1:5000` bên dưới thành `http://127.0.0.1:5001`.

## 5. Chạy red team attack

Xóa marker cũ để tránh nhìn nhầm kết quả từ lần chạy trước:

```powershell
kubectl -n redis-injection-lab exec deploy/worker-vulnerable -- sh -c "rm -f /tmp/redteam_owned.txt"
```

Chạy attack chính:

```powershell
python scripts/red_team_attack.py --web-base-url http://127.0.0.1:5000 --redis-host redis --queue mail_jobs_vuln --verify-k8s --namespace redis-injection-lab
```

Nếu thành công, output sẽ có:

```text
[red-team] SSRF request status: 200
[red-team] Queue depth query status: 200
[red-team] Marker file detected at /tmp/redteam_owned.txt: REDTEAM_OWNED
```

Kiểm tra marker thủ công:

```powershell
kubectl -n redis-injection-lab exec deploy/worker-vulnerable -- cat /tmp/redteam_owned.txt
```

Kỳ vọng:

```text
REDTEAM_OWNED
```

## 6. Chạy lateral blast nếu muốn xem blast radius

Lệnh này thử dùng SSRF để gọi service nội bộ `blast-target`.

```powershell
python scripts/red_team_attack.py --web-base-url http://127.0.0.1:5000 --redis-host redis --queue mail_jobs_vuln --blast-host blast-target --blast-port 8080 --blast-path / --verify-k8s --namespace redis-injection-lab
```

Nếu chưa áp dụng NetworkPolicy, kỳ vọng trong `reply_preview` có:

```text
BLAST_OK
```

Nếu NetworkPolicy đã áp dụng, blast sẽ bị chặn. Khi đó output có thể là:

```text
[red-team] Blast probe status: 502
Network failure
```

Điều này không có nghĩa là RCE fail. Hãy nhìn marker `REDTEAM_OWNED` để kết luận exploit chính có thành công không.

Muốn quay lại trạng thái trước phòng thủ để demo `BLAST_OK`, chỉ làm trong lab local:

```powershell
kubectl delete -f k8s/network-policies.yaml --ignore-not-found
```

Sau đó chạy lại lệnh blast ở trên.

## 7. Áp dụng phòng thủ

Áp NetworkPolicy:

```powershell
kubectl apply -f k8s/network-policies.yaml
kubectl -n redis-injection-lab get networkpolicy
```

Lưu ý quan trọng: `kubectl get networkpolicy` chỉ chứng minh policy object đã tồn tại. NetworkPolicy chỉ chặn traffic thật nếu Minikube đang dùng CNI có hỗ trợ enforce policy, ví dụ `calico` hoặc `cilium`.

Kiểm tra CNI hiện tại:

```powershell
kubectl -n kube-system get pods
minikube profile list
```

Nếu không thấy pod kiểu Calico/Cilium/Antrea, rất có thể NetworkPolicy không được enforce. Khi đó blast tới `blast-target` vẫn có thể trả `200` dù policy object đã tồn tại.

Muốn demo chặn blast thật, tạo lại cluster với CNI hỗ trợ NetworkPolicy:

```powershell
minikube delete
minikube start --driver=docker --cni=calico --cpus=4 --memory=4096
```

Sau đó build image, deploy lab và apply NetworkPolicy lại từ đầu.

Kiểm tra blast bị chặn:

```powershell
python scripts/red_team_attack.py --web-base-url http://127.0.0.1:5000 --blast-host blast-target --blast-port 8080 --blast-path / --blast-only
```

Kỳ vọng:

```text
ok: false
```

hoặc:

```text
Network failure
```

## 8. Kiểm tra worker secure

Chạy script verify blue team:

```powershell
python scripts/blue_team_verify.py --mode k8s --web-base-url http://127.0.0.1:5000 --namespace redis-injection-lab --wait-seconds 8
```

Kỳ vọng:

```text
Blue Team Checklist
[x] Rejected malicious payload
[x] Accepted valid signed payload
[x] Malicious marker was NOT created in secure worker
[x] NetworkPolicy objects found
```

Xem log secure worker:

```powershell
kubectl -n redis-injection-lab logs deploy/worker-secure --tail=200
```

Kỳ vọng có các dòng tương tự:

```text
[secure-worker] Dropped non-UTF8 job
[secure-worker] Accepted signed job for blue-team@example.com
```

## 9. Troubleshooting nhanh

Nếu script red team trả `404`:

- Bạn đang gọi nhầm `web-safe` hoặc service khác.
- Kiểm tra lại port-forward phải là `svc/web-vulnerable`.
- Gọi `/?format=json` và xác nhận có `web-vulnerable-ssrf`.

Nếu marker không xuất hiện:

- Kiểm tra pod `worker-vulnerable` đang `Running`.
- Kiểm tra queue đúng là `mail_jobs_vuln`.
- Chạy lại port-forward tới `web-vulnerable`.
- Xem log pod:

```powershell
kubectl -n redis-injection-lab logs deploy/worker-vulnerable --tail=120
```

Nếu blast không ra `BLAST_OK`:

- Kiểm tra NetworkPolicy có đang tồn tại không:

```powershell
kubectl -n redis-injection-lab get networkpolicy
```

- Nếu NetworkPolicy đã tồn tại, blast bị chặn là kết quả đúng ở Phase phòng thủ.

Nếu port `5000` đã bị chiếm:

```powershell
Get-NetTCPConnection -LocalPort 5000 -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
```

Dùng port khác, ví dụ:

```powershell
kubectl -n redis-injection-lab port-forward svc/web-vulnerable 5001:5000
```

## 10. Dọn dẹp

```powershell
kubectl delete -f k8s/network-policies.yaml
kubectl delete -f k8s/minikube-lab.yaml
minikube stop
```
