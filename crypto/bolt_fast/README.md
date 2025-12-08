# bolt_fast
## Description
Everyone keeps telling me to worry about Wiener's attack, but they just don't understand optimization. Don't bother checking my key size; it's huge. You'll never catch me! Hahahaha!

## 1. Analysis

The challenge provides RSA key generation code with a critical vulnerability in creating the $d_p$ parameter (CRT exponent).

### Vulnerable Code:
```python
# The vulnerability is here:
dp_smart = getPrime(16)
e = inverse(dp_smart, p-1)
```

### Weakness:
In standard RSA CRT (Chinese Remainder Theorem), $d_p$ is calculated as:
$$d_p \equiv d \pmod{p-1} \equiv e^{-1} \pmod{p-1}$$

Normally, $d_p$ should be approximately the same size as $p$ (around 1024 bits). However, the challenge uses `getPrime(16)`, meaning $d_p$ is only a **16-bit** prime number.

Range of values for $d_p$:
$$2^{15} < d_p < 2^{16} \implies 32,768 < d_p < 65,536$$

Due to the extremely small key space (only a few thousand prime numbers), we can perform a **Brute-force attack** to find $d_p$.

---

## 2. Mathematical Derivation

The goal is to find the prime factor $p$ from $N$ and $e$ when we know (or can guess) $d_p$.

1.  From the definition $d_p \equiv e^{-1} \pmod{p-1}$, we have:
    $$e \cdot d_p - 1 = k \cdot (p-1)$$
    This means $(e \cdot d_p - 1)$ is a multiple of $(p-1)$.

2.  According to **Fermat's Little Theorem**, for any integer $a$ (choose $a=2$):
    $$a^{p-1} \equiv 1 \pmod p$$

3.  Substituting, we get:
    $$a^{e \cdot d_p - 1} \equiv 1 \pmod p$$
    $$\Rightarrow p \mid (a^{e \cdot d_p - 1} - 1)$$

4.  Since $p$ is also a divisor of $N$, we can find $p$ by calculating the **Greatest Common Divisor (GCD)**:
    $$p = \text{GCD}(a^{e \cdot d_p - 1} - 1 \pmod N, N)$$

---

## 3. Exploit Script

The script below doesn't require external libraries (like `pycryptodome`), and can be run directly with Python 3.

```python
import math
import sys

# --- CHALLENGE DATA ---
N = 22061149554706951873851465765917042279909309233484615798640186468876401527123242297915465375459511054772541825273007749026648641620485458471351811298443479262277231839408201654282927999029324652496830649919637863202844794784443579336735415046336390091671003022244732389217910334465895328371360158510046347031294125509649474722535171601096998732929497780870057433634214228116293166963101489644680801538837005001377764416442380530464289453201654394144682138927826247301956954884930328147978637795259346321547054237005318172528896865428457293207571804464061990459958593520373578234234490804585522859401957032395007142007
e = 9648003423571638489624579625383119603270189664714210175737275695548206153582516635644990660189908448510652756058045483763071850222529184219333877863638216254054444012130393864033392161426815671725858723096432660521038315432183692553568344247916320931122090436770154203149432285380142051084178668290839858171
c = 18817014323644102879407569381912044887671193778381872592373573382139976320220125847317309926920208859012582031032930373240219755720268543444729983316326640661427616841700761054678137741340093140586895094016730198447552611014038632666821117758006775144046000049080406858764900680265384743839472653817299383323869146152251839342236631780818396088131196202767951301023089053662813175083035336272981588533957561537975684034210166185396046071368061264321959248372783262788158418696375783427276741258526067168910326630496339287237940444426277757582174810909733937257258767407189452212391936958267819666424558678534741723930

# --- MATH HELPER FUNCTIONS ---

# 1. Extended Euclidean Algorithm (Calculate modular inverse)
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

# 2. Convert Long to Bytes (Crypto library replacement)
def long_to_bytes(val, endianness='big'):
    width = val.bit_length()
    width += 8 - ((width % 8) or 8)
    fmt = '%%0%dx' % (width // 4)
    s = bytes.fromhex(fmt % val)
    return s

# 3. Sieve of Eratosthenes (Generate list of prime numbers)
def sieve(limit):
    is_prime = [True] * (limit + 1)
    is_prime[0] = is_prime[1] = False
    for p in range(2, int(math.sqrt(limit)) + 1):
        if is_prime[p]:
            for i in range(p * p, limit + 1, p):
                is_prime[i] = False
    return [p for p in range(limit + 1) if is_prime[p]]

# --- ATTACK LOGIC ---

def solve():
    print("[*] STEP 1: Generating 16-bit primes...")
    # dp_smart is 16-bit, so max value is 65536
    primes = sieve(65536)
    
    # Filter primes that fit getPrime(16) -> [2^15, 2^16]
    candidates = [p for p in primes if p >= (1 << 15)]
    print(f"[*] Found {len(candidates)} candidates for dp.")

    print("[*] STEP 2: Brute-forcing dp to find p...")
    for dp in candidates:
        # Check: a^(e*dp - 1) = 1 mod p
        # Calculate GCD(a^(e*dp - 1) - 1, N) to find p
        
        exponent = e * dp - 1
        
        # Base a = 2
        val = pow(2, exponent, N)
        
        p = math.gcd(val - 1, N)
        
        if p > 1 and p < N:
            print(f"\n[+] SUCCESS! Found dp: {dp}")
            print(f"[+] Found p: {str(p)[:30]}...")
            
            # --- DECRYPTION ---
            print("[*] STEP 3: Decrypting the flag...")
            q = N // p
            phi = (p - 1) * (q - 1)
            d = modinv(e, phi)
            
            m_int = pow(c, d, N)
            flag = long_to_bytes(m_int)
            
            print("-" * 40)
            try:
                print(f"FLAG: {flag.decode()}")
            except:
                print(f"FLAG (HEX): {flag.hex()}")
            print("-" * 40)
            return

if __name__ == "__main__":
    solve()
```
FLAG: `flag{w31n3r_d1dn7_73ll_y0u_70_b3_6r33dy}`