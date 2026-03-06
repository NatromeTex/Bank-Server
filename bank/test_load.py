import asyncio
import aiohttp
import time
import random
from statistics import mean

BASE_URL = "http://localhost:8000"

# Load phases: [tpm, duration_seconds]
LOAD_PHASES = [
    [60, 5],  
    [100, 5], 
    [150, 5],
    [300, 5], 
    [100, 5]  
]

async def create_account(session, name, pin):
    async with session.post(f"{BASE_URL}/accounts", json={"name": name, "pin": pin}) as resp:
        if resp.status != 200:
            print(f"Error creating account: {await resp.text()}")
            return None
        return await resp.json()

async def deposit(session, account_id, amount):
    async with session.post(f"{BASE_URL}/deposit", json={"account_id": account_id, "amount": amount}) as resp:
        return await resp.text()

async def transfer(session, from_id, to_id, pin, amount):
    try:
        async with session.post(f"{BASE_URL}/transfer", json={"from_account_id": from_id, "to_account_id": to_id, "pin": pin, "amount": amount}) as resp:
            return resp.status
    except Exception as e:
        return 500

async def get_stats(session):
    async with session.get(f"{BASE_URL}/admin/stats") as resp:
        return await resp.json()

async def run_phase(session, tpm, duration, accounts):
    print(f"\n--- Starting Phase: {tpm} TPM for {duration}s ---")
    interval = 60.0 / tpm
    end_time = time.time() + duration
    tasks = []

    sent_count = 0
    while time.time() < end_time:
        loop_start = time.time()
        
        # Pick two random accounts
        from_acc = random.choice(accounts)
        to_acc = random.choice(accounts)
        while to_acc['id'] == from_acc['id']:
            to_acc = random.choice(accounts)
            
        task = asyncio.create_task(transfer(session, from_acc['id'], to_acc['id'], "1234", random.randrange(50,5000)))
        tasks.append(task)
        sent_count += 1
        
        # Sleep to maintain rate
        elapsed = time.time() - loop_start
        sleep_time = interval - elapsed
        if sleep_time > 0:
            await asyncio.sleep(sleep_time)
            
    print(f"Phase complete. Sent {sent_count} requests. Waiting for pending...")
    results = await asyncio.gather(*tasks)
    success_count = results.count(200)
    print(f"Completed. Success: {success_count}, Failed: {len(results) - success_count}")
    
    # Allow metrics to catch up (moving averages)
    await asyncio.sleep(2) 
    stats = await get_stats(session)
    print(f"Server Metrics -> TPM: {stats['tpm']:.2f}, Avg Latency: {stats['avg_latency']:.4f}s")
    return stats

async def main():
    async with aiohttp.ClientSession() as session:
        print("Creating 100 accounts...")
        accounts = []
        # Create accounts in batches to be faster
        batch_size = 10
        for i in range(0, 100, batch_size):
            batch_tasks = []
            for j in range(batch_size):
                name = f"User_{i+j}"
                batch_tasks.append(create_account(session, name, "1234"))
            batch_results = await asyncio.gather(*batch_tasks)
            accounts.extend([acc for acc in batch_results if acc])
            
        print(f"Created {len(accounts)} accounts.")
        
        # Initial Deposit
        print("Depositing funds...")
        deposit_tasks = [deposit(session, acc['id'], random.randrange(10000, 500000)) for acc in accounts]
        await asyncio.gather(*deposit_tasks)
        print("Deposits complete.")
        
        # Run Phases
        for phase in LOAD_PHASES:
            tpm, duration = phase
            await run_phase(session, tpm, duration, accounts)
            await asyncio.sleep(2) # Cool down

if __name__ == "__main__":
    asyncio.run(main())
