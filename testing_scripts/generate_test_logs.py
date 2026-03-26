import os
from datetime import datetime, timedelta

def main():
    base_dir = os.path.dirname(__file__)
    sample_dir = os.path.join(base_dir, "sample_logs")
    os.makedirs(sample_dir, exist_ok=True)
    
    start_time = datetime(2024, 10, 14, 10, 0, 0)
    
    with open(os.path.join(sample_dir, "clean.log"), "w") as f:
        curr_time = start_time
        for i in range(100):
            f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} INFO [ModuleA] Normal operation {i}\n")
            curr_time += timedelta(seconds=2)
            
    with open(os.path.join(sample_dir, "gaps.log"), "w") as f:
        curr_time = start_time
        for i in range(10):
            f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} INFO normal {i}\n")
            curr_time += timedelta(seconds=2)
            
        curr_time += timedelta(seconds=80)
        f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} WARN connection reset\n")
        
        for i in range(5):
             curr_time += timedelta(seconds=2)
             f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} INFO recovering...\n")
             
        curr_time += timedelta(seconds=500)
        f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} ERROR timeout occurred\n")

        for i in range(5):
             curr_time += timedelta(seconds=2)
             f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} INFO back online\n")

        curr_time += timedelta(seconds=4000)
        f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} CRITICAL system crash recovery\n")

    with open(os.path.join(sample_dir, "malformed.log"), "w") as f:
        curr_time = start_time
        f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} INFO start\n")
        
        curr_time += timedelta(seconds=5)
        f.write(f"{curr_time.strftime('%b %d %H:%M:%S')} INFO alternative format\n")
        
        curr_time += timedelta(seconds=3500)
        
        f.write("This line has no timestamp and should be skipped\n")
        f.write("\n") 
        f.write("ERROR 10:00:00 invalid formatting no date\n")
        
        f.write(f"{curr_time.strftime('%y%m%d %H:%M:%S')} INFO resume after large gap and malformed lines\n")
        
    print("Sample logs generated.")

if __name__ == "__main__":
    main()
