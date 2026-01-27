import shodan
import os
import requests as request

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
if not SHODAN_API_KEY:
    print("Error: SHODAN_API_KEY environment variable not set")
    print("Please set it with: export SHODAN_API_KEY='your_api_key'")
    exit(1)

api = shodan.Shodan(SHODAN_API_KEY)

def ShodanInfo(ip_addr):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip_addr}?key={SHODAN_API_KEY}&minify=true"
        result = request.get(url).json()
        return result
    except Exception as e:
        return {"error": f"Information not available: {e}"}

if __name__ == "__main__":
    print("=== SHODAN RECON TOOL ===")
    
    target_ip = input("Nhập địa chỉ IP cần kiểm tra (Nhấn Enter để dùng 1.1.1.1): ").strip()
    if not target_ip:
        target_ip = "1.1.1.1"

    print(f"\n[+] Đang truy vấn thông tin host: {target_ip}")
    info = ShodanInfo(target_ip)
    
    if "error" in info:
        print(f"Lỗi: {info['error']}")
    else:
        print(f" - Tổ chức: {info.get('org', 'N/A')}")
        print(f" - Các cổng mở: {info.get('ports', 'N/A')}")


    print("\n--- Tìm kiếm từ khóa 'nginx' ---")
    try:
        resultados = api.search("nginx")
        print(f"Tổng số kết quả tìm thấy: {resultados['total']}")
    except Exception as e:
        print(f"Error: {e}")


    print("\n--- Tìm kiếm 'port: 21 Anonymous user logged in' ---")
    try:
        servers = []
        results = api.search("port: 21 Anonymous user logged in")
        print(f"Số lượng host hớ hênh tìm thấy: {len(results['matches'])}")
        
        for result in results['matches']:
            if result['ip_str'] is not None:
                servers.append(result['ip_str'])
        

        for server in servers:
            print(f" -> Tìm thấy IP: {server}")
            
    except Exception as e:
        print(f"Error: {e}")
       