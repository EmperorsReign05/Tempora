import uuid
import random
from datetime import datetime, timedelta
import os

def main():
    os.makedirs("sample_logs", exist_ok=True)
    
    with open("sample_logs/advanced_tampering.log", "w") as f:
        current_time = datetime(2024, 10, 15, 8, 0, 0)
        
        for i in range(80):
            current_time += timedelta(seconds=random.randint(1, 4))
            tx_id = uuid.uuid4().hex
            ip = f"192.168.1.{random.randint(10, 250)}"
            f.write(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [INFO] TLS connection established IP={ip} TX_ID={tx_id} cipher=ECDHE-RSA-AES256-GCM context=OK\n")
            
        for i in range(20):
            current_time += timedelta(seconds=2)
            f.write(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [INFO] system running ok system running ok system running ok system running ok\n")
            
        current_time -= timedelta(minutes=10) 
        f.write(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [CRIT] Unauth root shell spawned via SSH payload.\n")
        
        current_time += timedelta(minutes=30) 
        f.write(f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} [WARN] Service recovered from temporary execution stall.\n")

if __name__ == "__main__":
    main()
