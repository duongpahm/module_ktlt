## Trích xuất thông tin từ Server với Shodan

- Shodan (https://www.shodan.io) là từ viết tắt của Sentient Hyper-Optimized Data Access Network (System Shock 2).
- Shodan cố gắng thu thập dữ liệu từ các cổng và dịch vụ mở.
- Shodan là một công cụ tìm kiếm chịu trách nhiệm kiểm tra và giám sát các thiết bị được kết nối internet và các loại thiết bị khác nhau (ví dụ: camera IP) và trích xuất thông tin về các dịch vụ đang chạy trên các nguồn đó.

- Truy cập Shodan:
    + Thông qua giao diện web mà Shodan cung cấp
    + Thông qua một RESTful API
    + Lập trình từ Python bằng module shodan


## Nmap với module python-nmap 
Chế độ scan trong python-nmap module có thể sử dụng:
    - Chế độ đồng bộ: mỗi lần quét được thực hiện trên một cổng, nó phải kết thúc để chuyển sang cổng tiếp theo.
    - Chế độ không đồng bộ: chúng ta có thể thực hiện quét trên các cổng khác nhau đồng thời và chúng ta có thể xác định một hàm gọi lại sẽ thực thi khi quá trình quét kết thúc trên một cổng cụ thể.

