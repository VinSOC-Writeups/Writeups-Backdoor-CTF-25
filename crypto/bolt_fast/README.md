# bolt_fast
## Description
Everyone keeps telling me to worry about Wiener's attack, but they just don't understand optimization. Don't bother checking my key size; it's huge. You'll never catch me! Hahahaha!

## 1. Phân tích bài toán (Analysis)

Đề bài cung cấp một đoạn code tạo khóa RSA với một lỗ hổng nghiêm trọng trong việc tạo tham số $d_p$ (CRT exponent).

### Code bị lỗi:
```python
# Lỗ hổng nằm ở đây:
dp_smart = getPrime(16)
e = inverse(dp_smart, p-1)
```

### Điểm yếu:
Trong RSA chuẩn CRT (Chinese Remainder Theorem), $d_p$ được tính bằng:
$$d_p \equiv d \pmod{p-1} \equiv e^{-1} \pmod{p-1}$$

Thông thường, $d_p$ phải có độ lớn tương đương với $p$ (khoảng 1024 bit). Tuy nhiên, đề bài sử dụng `getPrime(16)`, nghĩa là $d_p$ chỉ là một số nguyên tố **16-bit**.

Khoảng giá trị của $d_p$:
$$2^{15} < d_p < 2^{16} \implies 32,768 < d_p < 65,536$$

Do không gian khóa quá nhỏ (chỉ khoảng vài nghìn số nguyên tố), ta có thể thực hiện tấn công **Vét cạn (Brute-force)** để tìm $d_p$.

---

## 2. Cơ sở toán học (Mathematical Derivation)

Mục tiêu là tìm ra thừa số nguyên tố $p$ từ $N$ và $e$ khi biết (hoặc đoán được) $d_p$.

1.  Từ định nghĩa $d_p \equiv e^{-1} \pmod{p-1}$, ta có:
    $$e \cdot d_p - 1 = k \cdot (p-1)$$
    Điều này nghĩa là $(e \cdot d_p - 1)$ là một bội số của $(p-1)$.

2.  Theo **Định lý nhỏ Fermat** (Fermat's Little Theorem), với mọi số nguyên $a$ (chọn $a=2$):
    $$a^{p-1} \equiv 1 \pmod p$$

3.  Thay thế vào, ta có:
    $$a^{e \cdot d_p - 1} \equiv 1 \pmod p$$
    $$\Rightarrow p \mid (a^{e \cdot d_p - 1} - 1)$$

4.  Vì $p$ cũng là ước của $N$, ta có thể tìm $p$ bằng cách tính **Ước chung lớn nhất (GCD)**:
    $$p = \text{GCD}(a^{e \cdot d_p - 1} - 1 \pmod N, N)$$

---

## 3. Script khai thác (Exploit Script)

Script dưới đây không yêu cầu thư viện ngoài (như `pycryptodome`), có thể chạy trực tiếp bằng Python 3.

```python
import math
import sys

# --- DỮ LIỆU ĐỀ BÀI (CHALLENGE DATA) ---
N = 22061149554706951873851465765917042279909309233484615798640186468876401527123242297915465375459511054772541825273007749026648641620485458471351811298443479262277231839408201654282927999029324652496830649919637863202844794784443579336735415046336390091671003022244732389217910334465895328371360158510046347031294125509649474722535171601096998732929497780870057433634214228116293166963101489644680801538837005001377764416442380530464289453201654394144682138927826247301956954884930328147978637795259346321547054237005318172528896865428457293207571804464061990459958593520373578234234490804585522859401957032395007142007
e = 9648003423571638489624579625383119603270189664714210175737275695548206153582516635644990660189908448510652756058045483763071850222529184219333877863638216254054444012130393864033392161426815671725858723096432660521038315432183692553568344247916320931122090436770154203149432285380142051084178668290839858171
c = 18817014323644102879407569381912044887671193778381872592373573382139976320220125847317309926920208859012582031032930373240219755720268543444729983316326640661427616841700761054678137741340093140586895094016730198447552611014038632666821117758006775144046000049080406858764900680265384743839472653817299383323869146152251839342236631780818396088131196202767951301023089053662813175083035336272981588533957561537975684034210166185396046071368061264321959248372783262788158418696375783427276741258526067168910326630496339287237940444426277757582174810909733937257258767407189452212391936958267819666424558678534741723930

# --- CÁC HÀM TOÁN HỌC (MATH HELPERS) ---

# 1. Extended Euclidean Algorithm (Tính nghịch đảo module)
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

# 2. Convert Long to Bytes (Thay thế thư viện Crypto)
def long_to_bytes(val, endianness='big'):
    width = val.bit_length()
    width += 8 - ((width % 8) or 8)
    fmt = '%%0%dx' % (width // 4)
    s = bytes.fromhex(fmt % val)
    return s

# 3. Sàng Eratosthenes (Tạo list số nguyên tố)
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