from netmiko import ConnectHandler
# تغییر مسیر import برای نسخه‌های جدید netmiko
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

def get_connection(device_info):
    """
    سعی در برقراری ارتباط با SSH. در صورت شکست، تلاش با Telnet.
    """
    # کپی دیکشنری برای جلوگیری از تغییر داده‌های اصلی
    dev = device_info.copy()
    
    # تلاش برای اتصال SSH
    dev['device_type'] = 'cisco_ios' 
    try:
        conn = ConnectHandler(**dev)
        return conn
    except (NetmikoTimeoutException, NetmikoAuthenticationException, ConnectionRefusedError, Exception):
        pass # رفتن به مرحله بعد در صورت خطا در SSH

    # تلاش برای اتصال Telnet
    dev['device_type'] = 'cisco_ios_telnet'
    try:
        conn = ConnectHandler(**dev)
        return conn
    except Exception as e:
        # مدیریت کلیدهای مختلف host یا ip
        target = dev.get('host', dev.get('ip'))
        print(f"Connection failed (Both SSH & Telnet) for {target}: {e}")
        return None