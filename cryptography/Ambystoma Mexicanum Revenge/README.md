# Ambystoma Mexicanum Revenge

## Description
> The axolotls are not what they seem, they are back now, with a revenge.
> 
> nc remote.infoseciitr.in 4005

## Vulnerability
In this challenge, the author patched the unintended solution, forcing us to use 4 keys instead of just 1 like in the previous challenge to encrypt

```
for i in range(4):
    try:
        key = binascii.unhexlify(KEYS[i])
        ct = binascii.unhexlify(CIPHERTEXTS[i % len(CIPHERTEXTS)])
```

This means the Server wants to use the same ciphertext ct for all 4 keys

When decrypting:

* Under key 0, block 0 → "gib m"
* Under key 1, block 1 → "e fla"
* Under key 2, block 2 → "g pli"
* Under key 3, block 3 → "s"

Decryption under all 4 keys must pass authentication (tag must be correct with POLYVAL for each key)
$$ tag = AES_{mek_j} (S_j \oplus(nonce||0^{32}) \ and \ MSB)$$
where:
* $S_j=POLYVALHj(AAD,plaintext,length block)$
* $nonce || 0^{32}=nonce || b"\x00\x00\x00\x00"$

Get 4 equations and get $S_j$

Then solve the system of equations in $GF(2^{128})$ to obtain the plaintext for every key

## PoC
Choose option 1 three times to get 4 keys
Choose option 2 to get key, nonce leak
Then run the following script
```
from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
import binascii, os, sys

# --------- FILL IN YOUR DEBUG INFO ----------

KEYS=['4a3384d96c2477580b3fd572108a3011', '56cbc2e00e4310981a768126c5aa0916', 'c3c9675f70b0a1c3e197b63bae8b23af', '1a63c6625cb03c957c8ec8ce39ba57ed']
CIPHERTEXTS=[]
nonce='b0369d1ca4dc211062666850'

KEYS_HEX=KEYS
CIPHERTEXTS=[]
NONCE_HEX= nonce

# ------------------------------------------------

keys  = [binascii.unhexlify(k) for k in KEYS_HEX]
nonce = binascii.unhexlify(NONCE_HEX)

# =========== GF(2^128) for POLYVAL ==============
R = PolynomialRing(GF(2), 'x')
x = R.gen()
POLYVAL_modulus = x**128 + x**127 + x**126 + x**121 + 1
K = GF(2**128, name='a', modulus=POLYVAL_modulus)

def bytes_to_bit_array(data):
    bits = []
    for b in data:
        s = bin(b)[2:].zfill(8)
        s = s[::-1]  # little-endian within byte (according to RFC 8452)
        bits.extend(int(bit) for bit in s)
    return bits

def bytes_to_fe(b):
    return K(bytes_to_bit_array(b))

def fe_to_bytes(fe):
    bits = list(fe)
    if len(bits) < 128:
        bits += [0]*(128-len(bits))
    out = bytearray()
    for i in range(0, 128, 8):
        chunk = bits[i:i+8]
        chunk.reverse()
        s = ''.join(str(bit) for bit in chunk)
        out.append(int(s, 2))
    return bytes(out)

def u64_le(i):
    return i.to_bytes(8, "little")

def length_block(aad_len, pt_len):
    # length in bits, little-endian as per RFC 8452
    return u64_le(aad_len * 8) + u64_le(pt_len * 8)

# =========== Key derivation AES-GCM-SIV =========

def derive_keys(master_key, nonce):
    """
    RFC 8452 derive_keys (AES-128).
    Returns (msg_auth_key, msg_enc_key).
    """
    assert len(master_key) in (16, 32)
    assert len(nonce) == 12
    cipher = AES.new(master_key, AES.MODE_ECB)
    blocks = []
    for ctr in range(4):
        blk = cipher.encrypt(ctr.to_bytes(4, "little") + nonce)
        blocks.append(blk)
    msg_auth_key = blocks[0][:8] + blocks[1][:8]
    msg_enc_key  = blocks[2][:8] + blocks[3][:8]
    return msg_auth_key, msg_enc_key

def check_polyval(msg_enc_key, nonce, tag):
    """
    From tag, recover S_s (POLYVAL output) like Malosdaf:
      tag = AES_Enc(mek, (S_s xor nonce||0^32) & 0x7f in MSB)
    """
    cipher = AES.new(msg_enc_key, AES.MODE_ECB)
    s = cipher.decrypt(tag)  # S_s' = S_s xor nonce||0^32, with MSB cleared
    if s[15] & 0x80:
        return False, None
    s = strxor(s, nonce + b"\x00"*4)  # S_s
    return True, s

# ========= Prepare plaintext for K[0] ==========
# Divide into 4 blocks of 16 bytes, each block .strip() then concatenate = "gib me flag plis"

b0 = b"gib m" + b" " * 11
b1 = b"e fla" + b" " * 11
b2 = b"g pli" + b" " * 11
b3 = b"s"     + b" " * 15

need_plaintext = b0 + b1 + b2 + b3
if len(need_plaintext) % 16 != 0:
    need_plaintext += b"\x00" * (16 - len(need_plaintext) % 16)

need_blocks = len(need_plaintext) // 16      # = 4
M = 4                                        # number of keys
S = M                                        # number of sacrificial blocks = M
num_blocks = need_blocks + S                 # total plaintext blocks under each key

# ======= Derive per-message keys for 4 keys =====

msg_auth_keys = []
msg_enc_keys  = []
for k in keys:
    mak, mek = derive_keys(k, nonce)
    msg_auth_keys.append(mak)
    msg_enc_keys.append(mek)

# ======= Choose common tag for all 4 keys =======

while True:
    tag = os.urandom(16)
    ok = True
    s_list = []
    for mek in msg_enc_keys:
        ok_tag, s = check_polyval(mek, nonce, tag)
        if not ok_tag:
            ok = False
            break
        s_list.append(s)
    if ok:
        break

# ======= Generate AES-CTR keystream for each key =====

counter = bytearray(tag)
counter[15] |= 0x80
counter = bytes(counter)

keystreams = [[] for _ in range(M)]
aes_objs = [AES.new(mek, AES.MODE_ECB) for mek in msg_enc_keys]

for _ in range(num_blocks):
    for j in range(M):
        ks = aes_objs[j].encrypt(counter)
        keystreams[j].append(ks)
    ctr_int = int.from_bytes(counter, "little") + 1
    counter = ctr_int.to_bytes(16, "little")

# ======= Prepare POLYVAL parameters =========

inv = bytes_to_fe(b"\x01" + b"\x00"*13 + b"\x04\x92")  # x^-128, according to RFC 8452
w = [bytes_to_fe(mak) * inv for mak in msg_auth_keys]   # H_j = msg_auth_key_j * x^-128

LENBLOCK_fe = bytes_to_fe(length_block(0, 16 * num_blocks))   # AAD = 0, plaintext = 16*num_blocks
aad_poly = [K(0)] * M  # no AAD

polyvals_rhs = []
for j in range(M):
    s_fe = bytes_to_fe(s_list[j])     # S_s^(j)
    polyvals_rhs.append(s_fe + w[j] * LENBLOCK_fe + aad_poly[j])

# ======= Build linear system A * X = b ===========
# Variable X contains M*num_blocks plaintext blocks:
#   key 0: P_0[0..num_blocks-1]
#   key 1: P_1[...]
#   key 2: ...
#   key 3: ...

matrix_size = M * num_blocks
rows = []
rhs  = []

# 1) POLYVAL equations: 1 equation per key
for j in range(M):
    row = [K(0)] * matrix_size
    # sum_i P_{j,i} * H_j^{num_blocks+1-i}
    for i in range(num_blocks):
        row[j * num_blocks + i] = w[j] ** (num_blocks + 1 - i)
    rows.append(row)
    rhs.append(polyvals_rhs[j])

# 2) Ciphertext equality equations:
#    C_i is the same for all keys => P_0[i] + P_j[i] = KS0[i] + KSj[i]
for i in range(num_blocks):
    ks0_fe = bytes_to_fe(keystreams[0][i])
    for j in range(1, M):
        row = [K(0)] * matrix_size
        row[0 * num_blocks + i] = K(1)
        row[j * num_blocks + i] = K(1)
        rows.append(row)
        rhs.append(ks0_fe + bytes_to_fe(keystreams[j][i]))

# 3) Fix plaintext for key 0, first 4 blocks
target_positions = [
    (0, 0),  # b0 for key0, block0
    (1, 1),  # b1 for key1, block1
    (2, 2),  # b2 for key2, block2
    (3, 3),  # b3 for key3, block3
]

for blk_idx, (j, blk) in enumerate(target_positions):
    row = [K(0)] * matrix_size
    row[j * num_blocks + blk] = K(1)
    rows.append(row)
    block_bytes = need_plaintext[16 * blk_idx : 16 * (blk_idx + 1)]
    rhs.append(bytes_to_fe(block_bytes))

assert len(rows) == matrix_size == len(rhs), "System is not square!"

A = Matrix(K, rows)
b_vec = vector(K, rhs)

print("[*] Solving linear system over GF(2^128)...")
X = A.solve_right(b_vec)

# ======= Construct ciphertext for key 0 ============

P0_blocks_fe = [X[i] for i in range(num_blocks)]

ct_blocks = []
for i in range(num_blocks):
    ks0_fe = bytes_to_fe(keystreams[0][i])
    ct_blocks.append(ks0_fe + P0_blocks_fe[i])  # C_i = KS0_i + P0_i

ct_bytes = b"".join(fe_to_bytes(c) for c in ct_blocks)
ciphertext_full = ct_bytes + tag

print("[*] Ciphertext length:", len(ciphertext_full))
print("[*] Ciphertext hex (paste into option 3):")
print(binascii.hexlify(ciphertext_full).decode())
```

Choose option 3 to submit the obtained ciphertext
Choose option 4 to get the flag

```
flag{4x0l075_0nly_5p4wn_1n_lu5h_c4v35_0r_1n_7h3_d4rk}
```