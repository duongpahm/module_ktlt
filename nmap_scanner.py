import nmap
import time

class MyNmapScanner:
    def __init__(self):
        self.sync_scanner = nmap.PortScanner()
        self.async_scanner = nmap.PortScannerAsync()

    def scan_synchronous(self, ip, ports):
        print(f"\n[!] Bắt đầu quét ĐỒNG BỘ cho {ip}...")
        for port in ports:
            print(f" [+] Đang quét cổng: {port}")
            try:
                self.sync_scanner.scan(ip, port)
                print(f"     Lệnh thực thi: {self.sync_scanner.command_line()}")
                
                # Get the scanned host (could be IP or domain)
                scanned_host = list(self.sync_scanner.all_hosts())[0] if self.sync_scanner.all_hosts() else ip
                state = self.sync_scanner[scanned_host]['tcp'][int(port)]['state']
                print(f"     Trạng thái: {state}")
            except Exception as e:
                print(f"     Lỗi quét cổng {port}: {e}")


    def scan_asynchronous(self, ip, ports):
        print(f"\n[!] Bắt đầu quét KHÔNG ĐỒNG BỘ cho {ip}...")
        
        def my_callback(host, scan_result):
            print(f"\n [+] Kết quả cho {host}:")
            print(scan_result)

        for port in ports:
            self.async_scanner.scan(hosts=ip, arguments=f'-p {port}', callback=my_callback)
        
        while self.async_scanner.still_scanning():
            print(" Quét đang chạy ngầm (Asynchronous) >>>")
            self.async_scanner.wait(2) 

def main():
    scanner = MyNmapScanner()
    
    target = input("Nhập IP hoặc Domain (Ví dụ: scanme.nmap.org): ").strip()
    if not target:
        target = "scanme.nmap.org"
    
    list_ports = ["21", "22", "80", "443"]
    
    print("\nChọn chế độ quét:")
    print("1. Đồng bộ (Synchronous)")
    print("2. Không đồng bộ (Asynchronous)")
    choice = input("Lựa chọn của bạn (1/2): ")

    if choice == "1":
        scanner.scan_synchronous(target, list_ports)
    elif choice == "2":
        scanner.scan_asynchronous(target, list_ports)
    else:
        print("Lựa chọn không hợp lệ!")

if __name__ == "__main__":
    main()