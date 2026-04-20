# Runbook Red Team / Blue Team Trên Minikube

Tài liệu này được tổ chức theo 3 phase rõ ràng:

- **Phase 1 – Cài đặt (Setup):** Khởi động môi trường lab
- **Phase 2 – Tấn công (Red Team):** Khai thác SSRF → Redis poisoning → RCE
- **Phase 3 – Phòng thủ (Blue Team):** Xác minh worker an toàn + NetworkPolicy

**Mục tiêu mô phỏng:**
- SSRF trên web service
- Redis queue poisoning
- Pickle deserialization RCE trong worker dễ bị tổn thương
- Cơ chế phòng thủ bằng worker bảo mật + NetworkPolicy

---

## Phase 1 – Cài Đặt (Setup)

### 1.1) Cài dependency cho script local

```powershell
python -m pip install -r requirements-dev.txt
```

**Mục đích:**
Đảm bảo các script red/blue team chạy được trên máy local.

---

### 1.2) Khởi động Minikube

```powershell
minikube start --cpus=4 --memory=4096
kubectl version
```

Nếu Windows chưa nhận `minikube` trong PATH:

```powershell
& "C:\Program Files\Kubernetes\Minikube\minikube.exe" start --driver=docker --cpus=4 --memory=4096
```

**Mục đích:**
Khởi tạo Kubernetes cluster local để deploy lab.

---

### 1.3) Build image vào Minikube

```powershell
minikube image build -t redis-injection/web-vulnerable:latest -f web/Dockerfile.vulnerable web
minikube image build -t redis-injection/web-safe:latest -f web/Dockerfile web
minikube image build -t redis-injection/worker-vulnerable:latest -f worker/Dockerfile.vulnerable worker
minikube image build -t redis-injection/worker-secure:latest -f worker/Dockerfile.secure worker
```

**Mục đích:**
Nạp image đúng phiên bản local vào node Minikube.

---

### 1.4) Deploy tài nguyên Kubernetes

```powershell
kubectl apply -f k8s/minikube-lab.yaml
kubectl apply -f k8s/network-policies.yaml
kubectl -n redis-injection-lab get pods
```

**Mục đích:**
Tạo namespace, deployment, service và network policy cho lab.

> ⚠️ Chỉ chuyển sang Phase 2 khi tất cả pod đã ở trạng thái `Running`.

---

### 1.5) Mở kênh truy cập web-vulnerable từ local

Mở một terminal riêng và giữ tiến trình này chạy nền:

```powershell
kubectl -n redis-injection-lab port-forward svc/web-vulnerable 5000:5000
```

**Mục đích:**
Mở endpoint local `http://127.0.0.1:5000` để script tấn công sử dụng.

---

## Phase 2 – Tấn Công (Red Team)

**Mục tiêu phase này:**
- Tiêm payload độc qua SSRF vào Redis queue
- Buộc worker dễ bị tổn thương thực thi payload qua `pickle.loads()`

---

### 2.1) Kiểm tra endpoint web-vulnerable hoạt động

```powershell
python -c "import requests; print(requests.get('http://127.0.0.1:5000', timeout=5).status_code)"
```

**Kỳ vọng:** In ra `200`.

---

### 2.2) Xóa marker cũ

```powershell
kubectl -n redis-injection-lab exec deploy/worker-vulnerable -- sh -c "rm -f /tmp/redteam_owned.txt"
```

**Mục đích:**
Tránh false positive khi xác minh kết quả tấn công.

---

### 2.3) Chạy tấn công SSRF → Redis poisoning

```powershell
python scripts/red_team_attack.py --web-base-url http://127.0.0.1:5000 --redis-host redis --queue mail_jobs_vuln
```

**Giải thích:**
- Script tạo payload pickle độc hại.
- Endpoint SSRF gửi payload đến Redis.
- Worker dễ bị tổn thương BRPOP queue và deserialize payload.

**Kỳ vọng output:**
- `SSRF request status: 200`
- `Queue depth query status: 200`

---

### 2.4) Xác minh marker tự động

```powershell
python scripts/red_team_attack.py --web-base-url http://127.0.0.1:5000 --redis-host redis --queue mail_jobs_vuln --verify-k8s --namespace redis-injection-lab
```

**Kỳ vọng output:** Có dòng `Marker file detected`.

---

### 2.5) Xác minh marker thủ công

```powershell
kubectl -n redis-injection-lab exec deploy/worker-vulnerable -- cat /tmp/redteam_owned.txt
```

**Kỳ vọng output:** `REDTEAM_OWNED`

---

### 2.6) Thu thập log worker-vulnerable

```powershell
kubectl -n redis-injection-lab logs deploy/worker-vulnerable --tail=120
```

**Mục đích:**
Lưu bằng chứng bổ trợ về thời điểm consume queue và hành vi deserialize.

---

## Phase 3 – Phòng Thủ (Blue Team)

**Mục tiêu phase này:**
- Từ chối payload độc hại
- Chấp nhận payload hợp lệ (JSON + HMAC)
- Xác nhận NetworkPolicy tồn tại và hoạt động đúng

---

### 3.1) Chạy script xác minh ở chế độ K8s

```powershell
python scripts/blue_team_verify.py --mode k8s --web-base-url http://127.0.0.1:5000 --namespace redis-injection-lab --wait-seconds 8
```

**Kỳ vọng checklist:**
- `[x] Rejected malicious payload`
- `[x] Accepted valid signed payload`
- `[x] Malicious marker was NOT created in secure worker`
- `[x] NetworkPolicy objects found`

---

### 3.2) Kiểm tra log worker-secure

```powershell
kubectl -n redis-injection-lab logs deploy/worker-secure --tail=200
```

**Kỳ vọng:**
- Có dòng từ chối (`Dropped ...`)
- Có dòng chấp nhận (`Accepted signed job ...`)

---

### 3.3) Kiểm tra NetworkPolicy

```powershell
kubectl -n redis-injection-lab get networkpolicy
```

**Mục đích:**
Xác nhận namespace có đủ rule deny/allow đã được thiết kế.

---

### 3.4) Regression test cho pipeline an toàn (tuỳ chọn)

```powershell
docker compose up -d --build
python scripts/security_test.py
```

**Mục đích:**
Kiểm tra nhanh luồng an toàn mặc định của hệ thống ngoài K8s lab.

---

## Phụ Lục – Chế Độ Local Compose (Khi Không Dùng Minikube)

Nếu không dùng Minikube, có thể mô phỏng nhanh bằng Docker Compose:

```powershell
docker compose -f docker-compose.vulnerable.yml up -d --build
python scripts/red_team_attack.py --web-base-url http://localhost:5001 --redis-host redis --queue mail_jobs_vuln
docker compose -f docker-compose.vulnerable.yml exec -T worker-vulnerable cat /tmp/redteam_owned.txt
python scripts/blue_team_verify.py --mode compose --web-base-url http://localhost:5001 --redis-host redis --secure-queue mail_jobs_secure --compose-file docker-compose.vulnerable.yml --compose-service worker-secure
```

**Lưu ý:**
- Ở chế độ compose, script blue-team sẽ bỏ qua kiểm tra NetworkPolicy.
- Xem log phòng thủ:

```powershell
docker compose -f docker-compose.vulnerable.yml logs worker-secure --tail=200
```

---

## Dọn Dẹp (Cleanup)

```powershell
kubectl delete -f k8s/network-policies.yaml
kubectl delete -f k8s/minikube-lab.yaml
minikube stop
```
