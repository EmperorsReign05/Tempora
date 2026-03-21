import os
from datetime import datetime, timedelta

def main():
    base_dir = os.path.dirname(__file__)
    sample_dir = os.path.join(base_dir, "sample_logs")
    os.makedirs(sample_dir, exist_ok=True)
    
    start_time = datetime(2024, 10, 14, 10, 0, 0)
    
    # 1. Clean log (no gaps)
    with open(os.path.join(sample_dir, "clean.log"), "w") as f:
        curr_time = start_time
        for i in range(100):
            f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} INFO [ModuleA] Normal operation {i}\n")
            curr_time += timedelta(seconds=2)
            
    # 2. Logs with gaps (mixed severities)
    with open(os.path.join(sample_dir, "gaps.log"), "w") as f:
        curr_time = start_time
        # Write some normal
        for i in range(10):
            f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} INFO normal {i}\n")
            curr_time += timedelta(seconds=2)
            
        # LOW severity gap (80 seconds)
        curr_time += timedelta(seconds=80)
        f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} WARN connection reset\n")
        
        for i in range(5):
             curr_time += timedelta(seconds=2)
             f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} INFO recovering...\n")
             
        # MEDIUM severity gap (500 seconds)
        curr_time += timedelta(seconds=500)
        f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} ERROR timeout occurred\n")

        for i in range(5):
             curr_time += timedelta(seconds=2)
             f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} INFO back online\n")

        # HIGH severity gap (4000 seconds)
        curr_time += timedelta(seconds=4000)
        f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} CRITICAL system crash recovery\n")

    # 3. Malformed logs + mixed formats
    with open(os.path.join(sample_dir, "malformed.log"), "w") as f:
        curr_time = start_time
        f.write(f"{curr_time.strftime('%Y-%m-%d %H:%M:%S')} INFO start\n")
        
        # valid but different format
        curr_time += timedelta(seconds=5)
        # Using %b %d %H:%M:%S (e.g. Oct 14 10:00:05)
        f.write(f"{curr_time.strftime('%b %d %H:%M:%S')} INFO alternative format\n")
        
        # add a gap
        curr_time += timedelta(seconds=3500)
        
        # completely malformed line
        f.write("This line has no timestamp and should be skipped\n")
        f.write("\n") # empty line
        f.write("ERROR 10:00:00 invalid formatting no date\n")
        
        # valid line resuming
        f.write(f"{curr_time.strftime('%y%m%d %H:%M:%S')} INFO resume after large gap and malformed lines\n")
        
    print("Sample logs generated.")

if __name__ == "__main__":
    main()
