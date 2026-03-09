# CHƯƠNG 3: THỰC NGHIỆM, PHÂN TÍCH VÀ BIỆN PHÁP PHÒNG THỦ

## 3.1. Kịch bản thực nghiệm

### 3.1.2. Kịch bản 1 – Classic DLL Injection

Trong kịch bản đầu tiên, kỹ thuật Classic DLL Injection được sử dụng để tiến hành thực nghiệm. Đây là phương pháp nền tảng và phổ biến nhất để tiêm một thư viện liên kết động (DLL) vào một tiến trình đang chạy. Toàn bộ mã nguồn thực thi được xây dựng trực tiếp trên phía máy victim.

Để quan sát trực quan rủi ro thực thi mã tùy ý, thực nghiệm sử dụng một tập tin Custom DLL được xây dựng chuyên biệt. Khi được nạp thành công vào tiến trình mục tiêu, hàm `DllMain()` của thư viện này sẽ ngay lập tức được kích hoạt và hiển thị một hộp thoại cảnh báo (MessageBox).

Quy trình tiêm DLL được triển khai trên máy victim thông qua 4 bước cốt lõi:

**Bước 1: Lấy quyền truy cập tiến trình mục tiêu**
Chương trình Injector sử dụng các Windows API (`CreateToolhelp32Snapshot`, `Process32FirstW/NextW`) để dò tìm Process ID (PID) của tiến trình đích. Sau đó, hàm `OpenProcess()` với cờ đặc quyền `PROCESS_ALL_ACCESS` được gọi bằng quyền Quản trị viên để thiết lập kênh giao tiếp toàn quyền.

**Bước 2: Phân bổ không gian bộ nhớ ảo**
Hàm `VirtualAllocEx()` được sử dụng để cấp phát một vùng nhớ ảo bên trong tiến trình đích với quyền đọc/ghi (`PAGE_READWRITE`). Vùng nhớ này dùng để lưu trữ dữ liệu chuỗi đường dẫn của Custom DLL.

**Bước 3: Ghi dữ liệu vào không gian bộ nhớ đích**
Đường dẫn tuyệt đối của Custom DLL (ví dụ: `C:\Payloads\messagebox.dll`) được định dạng thành chuỗi byte kết thúc bằng null. Hàm `WriteProcessMemory()` sẽ sao chép và ghi chuỗi này xuyên qua ranh giới tiến trình, lưu trực tiếp vào vùng nhớ đã cấp phát ở Bước 2.

**Bước 4: Thiết lập luồng thực thi từ xa**
Injector lấy địa chỉ tĩnh của hàm `LoadLibraryA` (thuộc cấu phần `kernel32.dll`) thông qua `GetModuleHandleA()` và `GetProcAddress()`. Cuối cùng, hàm `CreateRemoteThread()` được gọi để tạo một luồng thực thi mới bên trong tiến trình đích, khởi chạy từ `LoadLibraryA` và truyền tham số chính là địa chỉ vùng nhớ chứa chuỗi đường dẫn DLL.

**Kết quả:**
Tiến trình mục tiêu bị ép gọi hàm `LoadLibraryA` để nạp tập tin Custom DLL. Ngay tại thời điểm đó, hàm `DllMain()` thuộc thư viện được kích hoạt, hiển thị một MessageBox, xác nhận mã thực thi tùy ý đã hoạt động thành công dưới vỏ bọc vòng đời của một tiến trình hợp lệ.
