# To jmp or not jmp

## Overview

This is a reverse engineering challenge that involves decrypting an encrypted flag using RC4 encryption. The binary uses obfuscation techniques to hide the implementation.

## Binary Analysis

### File Information
```bash
challenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3dd27df153c863f59a03dcd6cbbe810abda047bf, for GNU/Linux 3.2.0, stripped
```

### Initial Observations

- The binary uses `libstdc++` (evident from functions: `_ZSt3cin`, `_ZSt4cout`, `std::getline` in PLT)
- Contains many `jn`/`jne` jumps to illogical addresses - classic control flow obfuscation
- String analysis in IDA Pro reveals an obfuscated string at `0x2020`

```
.rodata:0000000000002020 sza1a9a1fsR db '!a1 a&',0Dh,'9a+',0Dh,' 1fsR'
```

## Key Recovery

The binary contains XOR-based key obfuscation. Tracing the code:

```asm
.text:000000000000134C         lea     rdx, sza1a9a1fsR        ; "!a1 a&\r9a+\r 1fsR"
.text:0000000000001353         mov     rax, [rbp-8]
.text:0000000000001357         add     rax, rdx
.text:000000000000135A         movzx   eax, byte ptr [rax]
.text:000000000000135D         xor     eax, 52h
```

The string `sza1a9a1fsR` is XORed with `0x52` to reveal the actual key:

```
b'!a1 a&\r9a+\r 1fsR' ^ 0x52 = b's3cr3t_k3y_rc4!\x00'
```

## RC4 Implementation Analysis

### Encrypted Data Location
- At `0x2040`: 66 bytes of high-entropy data (ciphertext)
- At `0x2088`: length value `0x42` (66 decimal)
- At `0x2080`: magic value `0xf1ed`

### Algorithm Confirmation
The binary contains a standard RC4 implementation starting at `0x12e6`:

1. **Key Scheduling Algorithm (KSA)**: Initializes 256-byte S-box at `0x4280`
2. **Pseudo-Random Generation Algorithm (PRGA)**: Generates keystream bytes at `0x1413`-`0x14ff`

Key structure identified:
- RC4 key: `"s3cr3t_k3y_rc4!"` (15 bytes)
- Ciphertext: 66 bytes at `0x2040`

## Solution

### Decryption Script
```python
def rc4_ksa(key: bytes):
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xff
        S[i], S[j] = S[j], S[i]
    return S

def rc4_prga(S, n):
    i = j = 0
    out = []
    for _ in range(n):
        i = (i + 1) & 0xff
        j = (j + S[i]) & 0xff
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) & 0xff]
        out.append(K)
    return bytes(out)

def rc4_decrypt(key, cipher):
    S = rc4_ksa(key)
    ks = rc4_prga(S, len(cipher))
    return bytes(c ^ k for c, k in zip(cipher, ks))
```

### Flag Extraction
```python
# Extract from binary
key_full = b's3cr3t_k3y_rc4!\x00'
key = key_full[:15]               # First 15 bytes as the key
cipher = ro_bytes[0x40:0x40+66]   # 66 bytes at offset 0x40

# Decrypt
plain = rc4_decrypt(key, cipher)
print(plain.decode())
```

Flag: `flag{$t0p_JUmp1n9_@R0uNd_1!k3_A_F00l_4nd_gib3_M3333_7H@t_f14g!!!!}`