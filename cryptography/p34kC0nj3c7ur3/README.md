# p34kC0nj3c7ur3

## Description
> Pave your path to ultimate hash function!
> 
> nc remote.infoseciitr.in 4002

## Challenge Analysis
This is the [3n + 1](https://en.wikipedia.org/wiki/Collatz_conjecture) problem in the form of a hash function

The server computes `myHash = uniqueHash(message)` and we are given `uniqueHash(myHash)`

We must find 10 values such that H(i) = myHash
## Exploit Idea
First, we need to find the value of myHash

The server returns H(myHash) = 25, we can search from 1 to 10000 to find which number has 25 steps, and then we can determine myHash = 4017

Then, by simply reversing the operations x * 2 and (x-1)/3 from 1, we will trace back 10 numbers that have 4017 steps to reach 1

## PoC
```
from pwn import *
from Crypto.Util.number import isPrime
import random
import time

# --- Configuration ---
HOST = 'remote.infoseciitr.in'
PORT = 4002
MY_HASH_TARGET = 4017 # Found from leak analysis step (uniqueHash(4017) -> 25)

# --- Helper Functions ---
def get_preimage_batch(target_steps, batch_size=8000):
    """
    Generate numbers with stopping time equal to target_steps by reversing Collatz.
    Use large batch_size to increase chances of finding prime numbers at deeper levels.
    """
    # Start reversing from number 1
    current_layer = {1}

    # Loop to go back target_steps - 1 steps
    for i in range(target_steps - 1):
        next_layer = set()
        
        # Optimization: Keep population size stable to avoid RAM overflow
        parents = list(current_layer)
        if len(parents) > batch_size:
            parents = random.sample(parents, batch_size)
            
        for x in parents:
            # Reverse Rule 1: From division by 2 => multiply by 2
            next_layer.add(x * 2)

            # Reverse Rule 2: From 3x+1 => (x-1)/3
            if (x - 1) % 3 == 0:
                prev = (x - 1) // 3
                # Forward Collatz condition: 3x+1 only applies to odd numbers
                if prev % 2 == 1 and prev > 1:
                    next_layer.add(prev)
        
        current_layer = next_layer
        if not current_layer:
            return [], []

    # Final step: Classify into Prime and Composite
    primes = []
    composites = []
    
    for x in current_layer:
        # Branch A: Multiply by 2 (Always composite since x > 1)
        composites.append(x * 2)
        
        # Branch B: (x-1)/3
        if (x - 1) % 3 == 0:
            prev = (x - 1) // 3
            if prev % 2 == 1 and prev > 1:
                if isPrime(prev):
                    primes.append(prev)
                else:
                    composites.append(prev)
                    
    return primes, composites

def solve():
    context.log_level = 'info'
    
    # 1. PRE-COMPUTE: Calculate offline beforehand to avoid timeout
    # Need to find at least 10 numbers, take 15 extra to be sure
    primes_pool = set() 
    composites_pool = set()
    
    log.info(f"Target Hash: {MY_HASH_TARGET}. Finding at least 15 Prime numbers...")
    
    attempt = 1
    # Generate loop until enough Primes are collected
    while len(primes_pool) < 15:
        log.info(f"Batch {attempt}: Generating (current primes count: {len(primes_pool)})...")
        p, c = get_preimage_batch(MY_HASH_TARGET, batch_size=8000)
        primes_pool.update(p)
        composites_pool.update(c)
        attempt += 1
        
    # Convert to list to use pop() function
    primes_pool = list(primes_pool)
    composites_pool = list(composites_pool)
    
    log.success(f"Ready! Found {len(primes_pool)} Primes and {len(composites_pool)} Composites.")

    # 2. CONNECT: Now connect to server
    conn = remote(HOST, PORT)

    # 3. VERIFY LEAK
    conn.recvuntil(b"This is my hash of hash: ")
    leak = int(conn.recvline().strip())
    log.info(f"Leak from server: {leak}")
    
    proofs_needed = 10
    
    # Based on "Well Well" error analysis from previous run, we know Flag is Prime
    target_is_prime = True
    log.info("Locked Target Type: PRIME (Based on previous analysis)")
    
    while proofs_needed > 0:
        candidate = None
        
        if target_is_prime:
            if not primes_pool:
                log.error("Ran out of Prime numbers to send! Need to increase batch_size or run again.")
                return
            candidate = primes_pool.pop()
        else:
            if not composites_pool:
                log.error("Ran out of Composite numbers!")
                return
            candidate = composites_pool.pop()

        # Send number to server
        log.info(f"Sending number (Is Prime? {isPrime(candidate)})...")
        conn.recvuntil(b"Enter your message in hex: ")
        conn.sendline(hex(candidate).encode())
        
        # Read response
        try:
            response = conn.recvline().decode().strip()
            log.info(f"Server response: {response}")
        except EOFError:
            log.error("Server closed connection unexpectedly.")
            return

        if "Incorrect!" in response:
            log.error("Incorrect hash! Logic calculation has issues.")
            return
            
        elif "Correct!" in response:
            proofs_needed -= 1
            log.success(f"Correct! {proofs_needed} remaining.")
                
        elif "Well Well" in response:
            # Backup case, if guessed wrong Prime/Composite type
            log.warning("Wrong prime property! Changing target...")
            target_is_prime = not target_is_prime

    # Get Flag
    conn.interactive()

if __name__ == "__main__":
    solve()
    
flag{1r0n_m4n_f0r_c0ll4tz_3ndg4m3_0f_cryp70gr4phy_1s_p34k_r16h7_313}
```