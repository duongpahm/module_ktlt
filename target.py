# target.py - Tiến trình mục tiêu đơn giản, chờ 10 phút
import os
import time
print(f"[TARGET] PID = {os.getpid()}")
print("[TARGET] Đang chờ... (Ctrl+C để thoát)")
time.sleep(600)
