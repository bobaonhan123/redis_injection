# Red Team Presentation Script (EN + VI)

Scope: red-team only slides in the current deck. The script is detailed and safe for a controlled lab demo.

## Slide: Red Team: Attack Path

**EN - Speaker notes**
We now shift to the offensive path, but still inside a controlled lab. The point is not to exploit a real system; it is to show how a small web flaw can be chained into a larger impact.

This chain has three visible steps: SSRF access, Redis queue poisoning, and unsafe deserialization. Notice that Redis itself is not the execution target; it is the transport layer. The execution happens in the worker that consumes the queue.

So our goal in this red-team section is to identify the entry point, trace the delivery path, and highlight the exact execution point where code runs.

**EN - Cues**
- Point to the phrase “SSRF → Redis poisoning → pickle RCE.”
- Emphasize “lab only, controlled environment.”
- Key message: execution happens in the worker, not in Redis.

**VI - Ghi chu thuyet trinh**
Giờ mình chuyển sang tuyến Red Team nhưng vẫn trong phạm vi lab có kiểm soát. Mục tiêu không phải khai thác hệ thống thật, mà là cho thấy một lỗi web nhỏ có thể nối chuỗi thành tác động lớn.

Chuỗi tấn công có ba bước rõ ràng: SSRF truy cập, đầu độc queue Redis, và deserialization không an toàn. Lưu ý Redis không phải là nơi thực thi; Redis chỉ là kênh vận chuyển. Điểm thực thi nằm ở worker khi nó tiêu thụ queue.

Vì vậy, phần Red Team sẽ tập trung vào điểm vào, đường vận chuyển, và điểm thực thi cuối cùng.

**VI - Goi y**
- Trỏ vào cụm “SSRF → Redis poisoning → pickle RCE.”
- Nhấn mạnh “lab, có kiểm soát.”
- Thông điệp chính: thực thi nằm ở worker, không phải Redis.

## Slide: Attack Focus Map

**EN - Speaker notes**
This diagram shows exactly which components the attacker touches. The entry point is the vulnerable web service. The delivery mechanism is the Redis queue. The execution happens inside the vulnerable worker when it deserializes untrusted bytes.

Also note the safe path in green. It exists for contrast: the secure flow uses JSON and HMAC, while the vulnerable flow trusts the queue content and uses `pickle.loads`.

If you remember only one thing from this slide, remember this: the attacker never needs to directly access the worker. The queue does the delivery for them.

**EN - Cues**
- Point to web-vulnerable, then Redis, then worker-vulnerable.
- Call out the queue name `mail_jobs_vuln` as the delivery channel.
- Contrast with the green safe path.

**VI - Ghi chu thuyet trinh**
Sơ đồ này cho thấy chính xác các thành phần bị tác động. Điểm vào là web-vulnerable. Kênh chuyển là Redis queue. Điểm thực thi nằm trong worker-vulnerable khi nó deserialize dữ liệu không tin cậy.

Đường xanh là luồng an toàn để so sánh: sử dụng JSON và HMAC. Còn đường đỏ tin dữ liệu queue và gọi `pickle.loads`.

Thông điệp quan trọng: attacker không cần truy cập trực tiếp worker. Queue tự trở thành “người đưa thư.”

**VI - Goi y**
- Chỉ lần lượt vào web-vulnerable → Redis → worker-vulnerable.
- Nhấn mạnh queue `mail_jobs_vuln` là kênh chuyển.
- So sánh nhanh với đường xanh an toàn.

## Slide: Attack Steps (What Gets Hit)

**EN - Speaker notes**
Step one: the SSRF endpoint at `/fetch` accepts a URL and fetches it on behalf of the user. We abuse this to send a gopher payload that speaks the Redis protocol directly.

Step two: that payload issues `LPUSH` into the vulnerable queue `mail_jobs_vuln`. At this point, the attacker has successfully written arbitrary bytes into the queue.

Step three: the vulnerable worker performs `BRPOP` and then deserializes with `pickle.loads`. That deserialization is the execution point where malicious code runs.

**EN - Cues**
- Emphasize SSRF as the entry point (not direct Redis access).
- Highlight the `LPUSH` and `BRPOP` pairing.
- Point to “deserialize” as the execution point.

**VI - Ghi chu thuyet trinh**
Bước một: endpoint SSRF `/fetch` cho phép nhập URL và server sẽ fetch thay. Chúng ta lợi dụng để gửi gopher payload nói chuyện trực tiếp với Redis.

Bước hai: payload thực hiện `LPUSH` vào queue `mail_jobs_vuln`. Ở bước này, attacker đã ghi được dữ liệu tùy ý vào hàng đợi.

Bước ba: worker gọi `BRPOP` rồi deserialize bằng `pickle.loads`. Đây là điểm thực thi nơi mã độc được chạy.

**VI - Goi y**
- Nhấn mạnh SSRF là điểm vào (không phải truy cập Redis trực tiếp).
- Nói rõ cặp `LPUSH` và `BRPOP`.
- Chỉ vào phần “deserialize” như điểm thực thi.

### Code Walkthrough: SSRF Endpoint (web/app_vulnerable.py)

**EN - Speaker notes**
This SSRF endpoint accepts a `url` query parameter and only allows `gopher://` URLs. The handler parses the URL, extracts the host and port, then strips the `/_` prefix to get raw bytes.

The key function is `send_raw_tcp()`: it opens a TCP socket to the target host and port, sends the raw payload, and returns a short response preview. This is what lets us speak the Redis protocol directly without a Redis client.

The JSON response shows how many bytes were sent and a small reply preview, which helps validate that Redis actually received the command.

**EN - Cues**
- Point to `fetch_url()` and the `gopher://` restriction.
- Call out `send_raw_tcp()` as the raw socket SSRF primitive.
- Emphasize the `/_` prefix rule for gopher payloads.

**VI - Ghi chu thuyet trinh**
Endpoint SSRF này nhận tham số `url` và chỉ cho phép URL dạng `gopher://`. Handler sẽ parse URL, lấy host/port, rồi cắt prefix `/_` để thu được raw bytes.

Hàm quan trọng là `send_raw_tcp()`: nó mở socket TCP đến host/port, gửi payload thô, và trả về một đoạn preview phản hồi. Nhờ vậy ta nói chuyện trực tiếp với Redis mà không cần client.

JSON response trả lại số bytes đã gửi và một phần phản hồi, giúp xác nhận Redis nhận lệnh.

**VI - Goi y**
- Chỉ vào `fetch_url()` và giới hạn `gopher://`.
- Nhấn mạnh `send_raw_tcp()` là primitive SSRF qua socket.
- Nhắc quy tắc prefix `/_` cho payload gopher.

## Slide: K8s Pod Blast Visualization

**EN - Speaker notes**
This slide shows the blast path inside Kubernetes. Even if the web pod is compromised, its outbound traffic is restricted by NetworkPolicy.

Direct pod-to-pod probing is blocked, so the attacker cannot simply pivot to other services. The only reliable path left is Redis, which is explicitly allowed for queue operations.

This explains why the attack still works: the queue is the approved channel, so the malicious payload rides through a legitimate data flow.

**EN - Cues**
- Point to blocked red dashed lines between pods.
- Point to the allowed Redis egress path.
- Emphasize “attack uses allowed flow, not direct lateral movement.”

**VI - Ghi chu thuyet trinh**
Slide này mô tả đường bắn phá trong Kubernetes. Dù web pod bị chiếm, outbound traffic vẫn bị NetworkPolicy hạn chế.

Các thử nghiệm đi ngang sang pod khác bị chặn, nên attacker không thể pivot trực tiếp. Con đường còn lại là Redis, vì đây là luồng hợp lệ cho queue.

Vì thế chuỗi tấn công vẫn chạy: payload đi theo luồng dữ liệu được cho phép.

**VI - Goi y**
- Chỉ vào các mũi tên đỏ nét đứt bị chặn.
- Chỉ vào đường egress hợp lệ sang Redis.
- Nhấn mạnh “tấn công đi theo luồng hợp lệ, không phải lateral.”

## Slide: Lateral Blast Attempts (K8s)

**EN - Speaker notes**
Here we zoom in on lateral movement attempts. The compromised pod tries to probe other pods, but NetworkPolicy blocks those connections.

The only permitted egress is Redis on port 6379. So even though lateral movement is stopped, the queue remains a viable delivery mechanism.

This is a key red-team lesson: if a single allowed channel exists, it can still be abused if downstream consumers are unsafe.

**EN - Cues**
- Highlight blocked probes to web-safe and workers.
- Call out “only Redis egress allowed.”
- Message: downstream safety matters as much as network policy.

**VI - Ghi chu thuyet trinh**
Ở đây là phần phóng to các nỗ lực lateral movement. Pod bị chiếm cố gắng truy cập các pod khác nhưng đều bị NetworkPolicy chặn.

Chỉ còn đường egress sang Redis ở port 6379. Vì vậy dù lateral bị khóa, queue vẫn là kênh chuyển payload.

Bài học: chỉ cần còn một kênh được cho phép thì vẫn có thể bị lạm dụng nếu consumer phía sau không an toàn.

**VI - Goi y**
- Chỉ vào các probe bị chặn tới web-safe/worker.
- Nhấn mạnh “chỉ Redis egress được phép.”
- Thông điệp: an toàn ở consumer quan trọng như policy mạng.

## Slide: Kill Chain (Red Team)

**EN - Speaker notes**
This slide summarizes the kill chain in a single line: SSRF entry, queue poisoning, pickle deserialization, and an RCE marker.

The marker is a simple file created inside the vulnerable worker. It proves that code executed in the container, and it makes the result easy to verify without any destructive action.

The central takeaway is still the same: Redis is only the transport. The real vulnerability is unsafe deserialization in the consumer.

**EN - Cues**
- Read the chain left to right.
- Emphasize “marker file = proof of execution.”
- Restate “Redis is transport, worker is execution.”

**VI - Ghi chu thuyet trinh**
Slide này tóm tắt kill chain trong một dòng: SSRF vào, đầu độc queue, pickle deserialization, và marker RCE.

Marker là một file được tạo trong worker-vulnerable. Nó chứng minh có thực thi mã trong container, và là bằng chứng an toàn, không gây phá hoại.

Thông điệp chính vẫn vậy: Redis chỉ là kênh vận chuyển, lỗ hổng nằm ở consumer.

**VI - Goi y**
- Đọc chuỗi từ trái sang phải.
- Nhấn mạnh “marker file = bằng chứng thực thi.”
- Nhắc lại “Redis chỉ là transport, worker mới là execution.”

## Slide: Red Team Demo

**EN - Speaker notes**
This demo follows three steps: open access to the vulnerable web, run the attack script, and verify the marker file in the worker.

Step 1: port-forward the service so the script can reach it locally. Step 2: run `scripts/red_team_attack.py`, which performs SSRF to `LPUSH` the malicious payload into the queue. Step 3: verify the marker file in the vulnerable worker with `kubectl exec`.

If `REDTEAM_OWNED` is present, the chain executed end to end. This is intentionally minimal and safe: it only writes a marker file, not a destructive action.

**EN - Cues**
- Call out the three commands shown.
- Point to the marker file path.
- Remind: “lab proof only.”

**VI - Ghi chu thuyet trinh**
Demo có ba bước: mở kênh truy cập web-vulnerable, chạy script tấn công, rồi xác minh marker trong worker.

Bước 1: port-forward service để script gọi được local. Bước 2: chạy `scripts/red_team_attack.py`, SSRF sẽ `LPUSH` payload độc vào queue. Bước 3: `kubectl exec` vào worker-vulnerable để đọc marker file.

Nếu thấy `REDTEAM_OWNED` thì chuỗi tấn công đã chạy end-to-end. Demo này tối giản và an toàn, chỉ ghi marker chứ không phá hoại.

**VI - Goi y**
- Nêu rõ ba lệnh trên slide.
- Chỉ vào đường dẫn marker.
- Nhắc “chỉ là bằng chứng trong lab.”

### Code Walkthrough: Attack Script (scripts/red_team_attack.py)

**EN - Speaker notes**
The attack script creates a malicious pickle payload via the `RCEPayload` class. Its `__reduce__` method returns a call to `eval`, which executes `os.system(...)` when unpickled.

Next, `build_resp_command()` formats the Redis command using RESP, the Redis wire protocol. We build `LPUSH <queue> <pickle_bytes>` so Redis stores the malicious bytes.

Then `send_redis_via_ssrf()` turns the RESP bytes into a gopher URL and calls the SSRF endpoint `/fetch`. This is how Redis receives the payload without direct access.

Finally, the script optionally verifies the marker via `kubectl exec` when `--verify-k8s` is enabled. This keeps the demo observable but safe.

**EN - Cues**
- Point to `RCEPayload.__reduce__()` as the execution trigger.
- Point to `build_resp_command()` as raw Redis protocol.
- Call out `send_redis_via_ssrf()` and the gopher URL.

**VI - Ghi chu thuyet trinh**
Script tấn công tạo payload pickle độc qua lớp `RCEPayload`. Hàm `__reduce__` trả về lời gọi `eval`, và khi unpickle sẽ chạy `os.system(...)`.

Tiếp theo, `build_resp_command()` đóng gói lệnh Redis theo chuẩn RESP. Nó dựng `LPUSH <queue> <pickle_bytes>` để Redis lưu payload độc.

Sau đó `send_redis_via_ssrf()` biến RESP bytes thành gopher URL và gọi endpoint `/fetch`. Đây là cách Redis nhận payload mà không cần truy cập trực tiếp.

Cuối cùng, script có thể xác minh marker bằng `kubectl exec` khi bật `--verify-k8s`. Như vậy demo quan sát được nhưng vẫn an toàn.

**VI - Goi y**
- Chỉ vào `RCEPayload.__reduce__()` như điểm kích hoạt.
- Chỉ vào `build_resp_command()` là giao thức Redis thô.
- Nhấn mạnh `send_redis_via_ssrf()` và gopher URL.

### Code Walkthrough: Vulnerable Worker (worker/worker_vulnerable.py)

**EN - Speaker notes**
The vulnerable worker uses `BRPOP` to read from the queue. Once it receives raw bytes, it calls `pickle.loads()` directly.

This is the core vulnerability: `pickle.loads()` executes attacker-controlled instructions during deserialization. There is no validation or signature check in this path.

The worker then logs the object type, but at that point the code has already executed. This is why the queue is dangerous if it carries untrusted bytes.

**EN - Cues**
- Point to `brpop()` as the consumer entry.
- Point to `pickle.loads()` as the execution line.
- Emphasize “no validation” in the vulnerable path.

**VI - Ghi chu thuyet trinh**
Worker dễ bị tổn thương dùng `BRPOP` để lấy dữ liệu từ queue. Khi nhận raw bytes, nó gọi `pickle.loads()` trực tiếp.

Đây là lỗ hổng cốt lõi: `pickle.loads()` có thể thực thi lệnh do attacker kiểm soát trong quá trình deserialization. Không có kiểm tra hay chữ ký nào trước đó.

Sau đó worker mới log kiểu dữ liệu, nhưng lúc này mã đã chạy rồi. Vì vậy queue chứa dữ liệu không tin cậy là rất nguy hiểm.

**VI - Goi y**
- Chỉ vào `brpop()` là điểm nhận dữ liệu.
- Chỉ vào `pickle.loads()` là dòng thực thi.
- Nhấn mạnh “không có validation” trong luồng vulnerable.

## Slide: Evidence

**EN - Speaker notes**
The evidence output confirms each step. We see successful SSRF, queue interaction, and finally the RCE marker. This is a controlled proof that the attack chain is real.

In a real environment we would not do this, but in the lab it helps us validate defenses and measure risk.

**EN - Cues**
- Read the three lines in order.
- Close with “controlled validation only.”

**VI - Ghi chu thuyet trinh**
Phần evidence xác nhận từng bước: SSRF thành công, queue được thao tác, và marker RCE xuất hiện. Đây là bằng chứng trong môi trường mô phỏng.

Trong môi trường thật chúng ta không làm như vậy, nhưng trong lab điều này giúp kiểm chứng phòng thủ và đánh giá rủi ro.

**VI - Goi y**
- Đọc ba dòng theo thứ tự.
- Kết bằng “chỉ kiểm chứng trong lab.”
