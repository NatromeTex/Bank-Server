import asyncio
import aiohttp
import time
import random
import json
import socket
import threading
from pathlib import Path

BASE_URL = "http://localhost:8000"
ACCOUNTS_FILE = Path("accounts.json")

# Global variables for background worker
bg_worker_running = False
bg_worker_thread = None
bg_worker_tpm = 60

def spoof_ip():
    """Generate a random IP address for spoofing."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

async def create_account(session, name, pin):
    async with session.post(f"{BASE_URL}/accounts", json={"name": name, "pin": pin}) as resp:
        if resp.status != 200:
            # print(f"Error creating account: {await resp.text()}")
            return None
        return await resp.json()

async def deposit(session, account_id, amount):
    async with session.post(f"{BASE_URL}/deposit", json={"account_id": account_id, "amount": amount}) as resp:
        return resp.status

async def transfer(session, from_id, to_id, pin, amount, spoofed_ip=None):
    headers = {}
    if spoofed_ip:
        headers["X-Forwarded-For"] = spoofed_ip
        
    try:
        async with session.post(
            f"{BASE_URL}/transfer", 
            json={"from_account_id": from_id, "to_account_id": to_id, "pin": pin, "amount": amount},
            headers=headers
        ) as resp:
            return resp.status
    except Exception:
        return 500

async def init_accounts(count):
    print(f"Initializing {count} accounts...")
    async with aiohttp.ClientSession() as session:
        accounts = []
        batch_size = 20
        
        # Create accounts
        for i in range(0, count, batch_size):
            batch_tasks = []
            current_batch_size = min(batch_size, count - i)
            for j in range(current_batch_size):
                name = f"User_{time.time()}_{i+j}" # Unique name
                batch_tasks.append(create_account(session, name, "1234"))
            
            results = await asyncio.gather(*batch_tasks)
            accounts.extend([acc for acc in results if acc])
            print(f"Created {len(accounts)}/{count} accounts...")
            
        # Deposit money
        print("Adding funds...")
        deposit_tasks = [deposit(session, acc['id'], random.randrange(10000, 500000)) for acc in accounts]
        await asyncio.gather(*deposit_tasks)
        
        # Save to file
        with open(ACCOUNTS_FILE, "w") as f:
            json.dump(accounts, f)
            
        print(f"Initialization complete. Saved {len(accounts)} accounts to {ACCOUNTS_FILE}")

def load_accounts():
    if not ACCOUNTS_FILE.exists():
        print(f"Error: {ACCOUNTS_FILE} not found. Please run initialization first.")
        return []
    with open(ACCOUNTS_FILE, "r") as f:
        return json.load(f)

async def run_background_traffic_loop(tpm):
    global bg_worker_running
    accounts = load_accounts()
    if not accounts or len(accounts) < 2:
        print("Not enough accounts for background traffic.")
        bg_worker_running = False
        return

    print(f"Background traffic started at {tpm} TPM...")
    async with aiohttp.ClientSession() as session:
        while bg_worker_running:
            start_time = time.time()
            interval = 60.0 / tpm
            
            # Send transaction
            from_acc = random.choice(accounts)
            to_acc = random.choice(accounts)
            while to_acc['id'] == from_acc['id']:
                 to_acc = random.choice(accounts)
            
            # Use random spoofed IP
            await transfer(session, from_acc['id'], to_acc['id'], "1234", random.randrange(10, 100), spoof_ip())
            
            elapsed = time.time() - start_time
            sleep_time = interval - elapsed
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

def start_background_worker():
    global bg_worker_running, bg_worker_thread, bg_worker_tpm
    if bg_worker_running:
        print("Background worker is already running.")
        return
    
    try:
        tpm_input = input(f"Enter TPM [current={bg_worker_tpm}]: ")
        if tpm_input.strip():
            bg_worker_tpm = int(tpm_input)
    except ValueError:
        print("Invalid TPM, using previous value.")

    bg_worker_running = True
    
    def worker_entry():
        asyncio.run(run_background_traffic_loop(bg_worker_tpm))
        
    bg_worker_thread = threading.Thread(target=worker_entry, daemon=True)
    bg_worker_thread.start()
    print("Worker thread started.")

def stop_background_worker():
    global bg_worker_running, bg_worker_thread
    if not bg_worker_running:
        print("Background worker is not running.")
        return
    
    bg_worker_running = False
    if bg_worker_thread:
        bg_worker_thread.join()
    print("Background worker stopped.")

async def send_alert(alert_type, message, level="info"):
    async with aiohttp.ClientSession() as session:
        try:
            alert_data = {
                "alert": message,
                "type": alert_type, # 'critical', 'warning', 'info'
                "details": {
                    "source": f"AI Detection: Confidence {random.randint(85,99)}%",
                    "threat_level": level # 'HIGH', 'MED', 'LOW'
                }
            }
            async with session.post(f"{BASE_URL}/sys/admin/inject", json=alert_data) as resp:
                if resp.status == 200:
                    pass
                else:
                    pass
        except Exception as e:
            print("Exception", e)

async def run_ddos_attack(target_url, thread_count, spoofed_ip, start_time, duration):
    print(f"Starting DDoS thread from {spoofed_ip}...")
    headers = {"X-Forwarded-For": spoofed_ip}
    alert_triggered = False
    
    async with aiohttp.ClientSession() as session:
        end_time = time.time() + duration
        
        while time.time() < end_time:
            if not alert_triggered and (time.time() - start_time) > 10:
                await send_alert("critical", "DDoS Attack Detected", "HIGH")
                alert_triggered = True
            try:
                async with session.get(f"{target_url}/", headers=headers) as resp:
                    pass
            except:
                pass

def start_ddos():
    target = BASE_URL
    spoofed_ips = [
        "102.145.234.20","167.30.12.14","179.30.99.15","85.16.128.4","163.172.16.1",
        "12.116.23.14","45.88.201.17","91.204.33.122","203.17.89.201","154.67.12.98","72.190.44.11","188.23.177.54",
  "61.132.205.8","109.45.77.143","217.91.12.199","34.221.56.78","146.12.88.211","58.174.39.62","192.83.14.170",
  "75.66.201.94","131.209.18.33","220.47.155.72","96.143.221.5","171.88.64.120","43.217.11.201","124.55.178.39",
  "211.14.90.163","68.229.45.87","156.77.203.14","84.190.132.244","177.25.61.108","28.199.74.31","115.66.208.191",
  "198.41.97.55","53.144.23.176","140.87.211.64","222.109.38.142","99.175.84.219","174.52.166.27","37.118.205.93"]
    
    try:
        threads_input = input("Enter number of threads (max 40) [default=5]: ")
        thread_count = int(threads_input) if threads_input.strip() else 5
        thread_time = input("Enter duration of attack (seconds) [default=15]: ")
        thread_time = int(thread_time) if thread_time.strip() else 15    
        thread_count = min(thread_count, 40)
    except ValueError:
        thread_count = 5
        thread_time = 15

    print(f"Launching DDoS attack with {thread_count} threads from IPs: {spoofed_ips}")
    
    start_time = time.time()
    threads = []
    for i in range(thread_count):
        ip = spoofed_ips[i % len(spoofed_ips)]
        # Pass start_time to check duration
        t = threading.Thread(target=lambda: asyncio.run(run_ddos_attack(target, 1, ip, start_time, thread_time)))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    print("DDoS attack burst finished.")

def port_scan():
    target_ip = "127.0.0.1"
    target_ports = [8000, 8001, 8002, 5432]
    
    print(f"Scanning ports {target_ports} on {target_ip}...")
    # Send alert immediately
    asyncio.run(send_alert("warning", "Port Scan Detected", "MED"))
    
    for port in target_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(f"Port {port}: OPEN")
        else:
            print(f"Port {port}: CLOSED")
        sock.close()

def main_menu():
    while True:
        print("\n--- Bank Server Attack Load Tool ---")
        print("1. Initialize Accounts")
        print(f"2. {'STOP' if bg_worker_running else 'START'} Background Traffic")
        print("3. Start DDoS Attack")
        print("4. Start Port Scan")
        print("5. Exit")
        
        choice = input("Select option: ")
        
        if choice == "1":
            try:
                count = int(input("Number of accounts to create [default=50]: ") or "50")
                asyncio.run(init_accounts(count))
            except ValueError:
                print("Invalid number.")
        elif choice == "2":
            if bg_worker_running:
                stop_background_worker()
            else:
                start_background_worker()
        elif choice == "3":
            start_ddos()
        elif choice == "4":
            port_scan()
        elif choice == "5":
            if bg_worker_running:
                stop_background_worker()
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        if bg_worker_running:
            stop_background_worker()
