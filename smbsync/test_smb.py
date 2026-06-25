import socket
import getpass
from nmb.NetBIOS import NetBIOS
from smb.SMBConnection import SMBConnection

def run_smb_test():
    print("--- SMB Connection CLI Test ---")
    
    # دریافت اطلاعات از کاربر
    server_ip = input("Server IP: ").strip()
    username = input("Username: ").strip()
    # استفاده از getpass برای امنیت بیشتر (هنگام تایپ پسورد نمایش داده نمی‌شود)
    password = getpass.getpass("Password: ")
    share_name = input("Share Name: ").strip()
    domain = input("Domain: ").strip()

    client_machine_name = socket.gethostname()
    
    # پیدا کردن نام NetBIOS سرور
    print(f"\n[*] Resolving NetBIOS name for {server_ip}...")
    try:
        nb = NetBIOS()
        server_names = nb.queryIPForName(server_ip, timeout=3)
        remote_name = server_names[0] if server_names else server_ip
        print(f"[+] Remote Name: {remote_name}")
    except Exception:
        print("[!] NetBIOS query failed, using IP as remote name.")
        remote_name = server_ip

    # ایجاد اتصال
    conn = SMBConnection(
        username, 
        password, 
        client_machine_name, 
        remote_name, 
        domain=domain, 
        use_ntlm_v2=True
    )

    try:
        print(f"[*] Attempting to connect to {server_ip} on port 445...")
        # ابتدا پورت 445 (استاندارد جدید) تست می‌شود
        connected = conn.connect(server_ip, 445)
        
        if not connected:
            print("[*] Port 445 failed, trying port 139...")
            connected = conn.connect(server_ip, 139)

        if connected:
            print("[SUCCESS] Connection established and authenticated!")
            
            print(f"[*] Verifying share: \\\\{server_ip}\\{share_name} ...")
            try:
                files = conn.listPath(share_name, "/")
                print(f"[+] Successfully listed {len(files)} items in share.")
                for f in files[:5]: # فقط 5 مورد اول برای شلوغ نشدن کنسول
                    print(f"  - {f.filename}")
                if len(files) > 5:
                    print("  - ...")
            except Exception as e:
                print(f"[!] Connected, but could not access share: {e}")
            
            conn.close()
            print("\n[+] Test completed. Connection closed.")
        else:
            print("\n[FAILURE] Connection failed: Check credentials, domain, or server permissions.")

    except Exception as e:
        print(f"\n[ERROR] An exception occurred: {str(e)}")

if __name__ == "__main__":
    try:
        run_smb_test()
    except KeyboardInterrupt:
        print("\n\n[!] Test cancelled by user.")
