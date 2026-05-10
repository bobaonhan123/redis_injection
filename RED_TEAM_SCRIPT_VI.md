# Giai thich script red team (tieng Viet)

## Tong quan
Script `scripts/red_team_attack.py` mo phong chuoi tan cong trong lab:
1) SSRF tu web noi bo -> 2) Gui lenh Redis bang giao thuc RESP -> 3) Worker giai ma pickle bi dau doc dan den RCE.

Muc tieu la minh hoa lo hong tu duong SSRF den thuc thi lenh trong container worker.

## Cac phan chinh trong code
- `RCEPayload`: Tao doi tuong pickle co `__reduce__` de thuc thi lenh he thong khi bi `pickle.loads()`.
- `build_resp_command()`: Dong goi lenh Redis theo giao thuc RESP, de co the gui truc tiep qua TCP.
- `send_redis_via_ssrf()`: Tao URL gopher va goi endpoint `/fetch` cua web-vulnerable de gui lenh Redis thong qua SSRF.
- `verify_marker_with_kubectl()`: Kiem tra file danh dau trong pod worker-vulnerable (tuy chon).
- `main()`: Tao pickle doc, LPUSH vao hang doi Redis, kiem tra LLEN va (neu chon) verify bang kubectl.

## Diem vulnerable o dau?
1) **Web SSRF qua gopher**
   - Endpoint `/fetch` chap nhan URL gopher va gui payload thuan ra TCP, cho phep truy cap dich vu noi bo (Redis).

2) **Redis mo trong mang noi bo, khong xac thuc**
   - Web pod co the ket noi Redis va gui lenh LPUSH/LLEN tu SSRF.

3) **Worker giai ma pickle khong tin cay**
   - `worker_vulnerable.py` dung `pickle.loads()` tren du lieu lay tu Redis.
   - Pickle co the thuc thi ma tuy y khi giai ma, dan den RCE.

## Luu y an toan
- Day la lab co chu dich. Khong su dung kich ban nay ngoai moi truong kiem thu duoc cap phep.
- Nen chuyen sang worker an toan (khong dung pickle tu du lieu khong tin cay) va chan SSRF o web.
