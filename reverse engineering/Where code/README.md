# Where code

## Description
That's it! I am done! I tried but cannot find any useful code! I am handing down this to you! Find the code and get the flag! Good luck!

## Analysis

Check the main flow of the program: flag checking
```c
unsigned __int64 sub_186A()
{
    __int64 v0; // rax
    const void *v1; // rax
    size_t n; // [rsp+8h] [rbp-68h]
    char v4[32]; // [rsp+10h] [rbp-60h] BYREF
    __int64 dest[4]; // [rsp+30h] [rbp-40h] BYREF
    __int16 v6; // [rsp+50h] [rbp-20h]
    unsigned __int64 v7; // [rsp+58h] [rbp-18h]

    v7 = __readfsqword(0x28u);
    std::string::basic_string(v4);
    std::operator<<<std::char_traits<char>>(&std::cout, "Enter the flag: ");
    std::getline<char,std::char_traits<char>,std::allocator<char>>(&std::cin, v4);
    memset(dest, 0, sizeof(dest));
    v6 = 0;
    if ( (unsigned __int64)std::string::length(v4) > 0x21 )
    {
        v0 = 0x22LL;
    }
    else
    {
        v0 = std::string::length(v4);
    }

    n = v0;
    v1 = (const void *)std::string::c_str(v4);
    memcpy(dest, v1, n);
    sub_1592(dest, &unk_4280, 0x22LL);
    std::string::~string(v4);
    return v7 - __readfsqword(0x28u);
}
```

`dest + v6` is a 34-byte buffer on the stack.

Your input (up to 34 bytes) is copied into `dest`, zero-padded.

Then `sub_1592(dest, &unk_4280, 34)` is called.

`unk_4280` is some global buffer; the real check is likely elsewhere (e.g. later `memcmp(&unk_4280, EXPECTED, 34)` or vice versa). For solving we just need to understand `sub_1592`.

Check `sub_1592` (Chacha20 cipher)
```c
unsigned __int64 __fastcall sub_1592(__int64 a1, __int64 a2, unsigned __int64 a3)
{
    unsigned __int64 v3; // rax
    int i; // [rsp+28h] [rbp-B8h]
    int j; // [rsp+2Ch] [rbp-B4h]
    unsigned __int64 k; // [rsp+30h] [rbp-B0h]
    unsigned __int64 m; // [rsp+38h] [rbp-A8h]
    int v10[12]; // [rsp+50h] [rbp-90h] BYREF
    int v11; // [rsp+80h] [rbp-60h]
    char v12[72]; // [rsp+90h] [rbp-50h] BYREF
    unsigned __int64 v13; // [rsp+D8h] [rbp-8h]

    v13 = __readfsqword(0x28u);
    qmemcpy(v10, "expand 32-byte k", 0x10);
    for ( i = 0; i <= 7; ++i )
    {
        v10[i + 4] = (byte_2080[4 * i + 2] << 0x10) | (byte_2080[4 * i + 1] << 8) | byte_2080[4 * i] | (byte_2080[4 * i + 3] << 0x18);
    }

    v11 = 1;
    for ( j = 0; j <= 2; ++j )
    {
        v10[j + 0xD] = (byte_20A0[4 * j + 2] << 0x10) | (byte_20A0[4 * j + 1] << 8) | byte_20A0[4 * j] | (byte_20A0[4 * j + 3] << 0x18);
    }

    for ( k = 0LL; k < a3; k += v3 )
    {
        sub_13A4(v10, v12);
        ++v11;
        v3 = a3 - k;
        if ( a3 - k > 0x40 )
        {
            v3 = 0x40LL;
        }

        for ( m = 0LL; m < v3; ++m )
        {
            *(_BYTE *)(m + k + a2) = v12[m] ^ *(_BYTE *)(m + k + a1);
        }
    }

    return v13 - __readfsqword(0x28u);
}
```

So:

- `a1` = input buffer
- `a2` = output buffer
- `a3` = length

`sub_13A4` generates a 64-byte block from state `v10`.

`*(a2 + offset) = keystream_byte ^ *(a1 + offset)`

That's exactly how ChaCha20 works: `keystream ⊕ plaintext → ciphertext`.

The constants give it away:

`qmemcpy(v10, "expand 32-byte k", 16)` is the ChaCha constant.

`sub_1285`:
```c
__int64 __fastcall sub_1285(_DWORD *a1, _DWORD *a2, _DWORD *a3, _DWORD *a4)
{
    __int64 result; // rax

    *a1 += *a2;
    *a4 ^= *a1;
    *a4 = sub_1269((unsigned int)*a4, 0x10LL);
    *a3 += *a4;
    *a2 ^= *a3;
    *a2 = sub_1269((unsigned int)*a2, 0xCLL);
    *a1 += *a2;
    *a4 ^= *a1;
    *a4 = sub_1269((unsigned int)*a4, 8LL);
    *a3 += *a4;
    *a2 ^= *a3;
    result = sub_1269((unsigned int)*a2, 7LL);
    *a2 = result;
    return result;
}
```

is a standard ChaCha quarter-round.

So `sub_13A4` is "ChaCha20 block function" and `sub_1592` is the ChaCha20 XOR loop.

The hard-coded key & nonce:
```
byte_2080 db 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0Ah, 0Bh, 0Ch, 0Dh, 0Eh, 0Fh

byte_20A0 db 7 dup(0), 4Ah, 4 dup(0)
```

`byte_2080` is a 32-byte key; only pasted the start, but the pattern is clearly `0x00, 0x01, ... 0x1F`.

`byte_20A0` is 12 bytes: `00 00 00 00 00 00 00 00 4A 00 00 00 00`

That's a 96-bit nonce: words are `[0, 0, 0x4A]` in little-endian.

Counter starts at `1`.

So the keystream for the first block (counter = 1) is:

```
key   = bytes(range(32))                    # 00 01 02 ... 1f
nonce = b'\x00'*7 + b'\x4a' + b'\x00'*4     # 00...00 4a 00 00 00 00
counter = 1
```

And first 34 bytes of keystream:

```
22 4f 51 f3 40 1b d9 e1 2f de 27 6f b8 63 1d ed
8c 13 1f 82 3d 2c 06 e2 7e 4f ca ec 9e f3 cf 78
8a 3b
```

### Relation between flag and `unk_4280`

From the call:

```c
sub_1592(dest, &unk_4280, 34);
```

get (for `0 ≤ i < 34`):

```
unk_4280[i] = keystream[i] ^ dest[i]
```

where `dest` is your (zero-padded) input flag.

That means for the correct flag `F` and the corresponding stored bytes `C` (what the program uses in its comparison), the relationship is:

```
C[i] = F[i] ⊕ KS[i]
⇒ F[i] = C[i] ⊕ KS[i]
```

So once know the 34 bytes of ciphertext (`C`), recovering the flag is trivial XOR with the keystream.

This script re-implements the ChaCha20 block exactly as in the binary and recovers the flag from the 34-byte ciphertext.

From the `.rodata` section, the 34-byte array the checker uses is at offset `0x2040`:
```
44 23 30 94 3b 72 97 d0 70 b8 06 01 d1 3c 50 84
e2 22 40 ef 0d 02 28 cc 4f 10 ee 89 ad ac b6 37
ff 46
```


## Solve

```python
from typing import List

def rotl32(x, n):
    return ((x << n) & 0xffffffff) | ((x & 0xffffffff) >> (32 - n))

def quarter_round(a, b, c, d):
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 16)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 12)
    a = (a + b) & 0xffffffff; d ^= a; d = rotl32(d, 8)
    c = (c + d) & 0xffffffff; b ^= c; b = rotl32(b, 7)
    return a, b, c, d

def chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    assert len(key) == 32
    assert len(nonce) == 12

    def u32_le(b: bytes) -> int:
        return int.from_bytes(b, "little")

    state = [
        u32_le(b"expa"),
        u32_le(b"nd 3"),
        u32_le(b"2-by"),
        u32_le(b"te k"),
    ]
    for i in range(8):
        state.append(int.from_bytes(key[4*i:4*i+4], "little"))
    state.append(counter)
    for i in range(3):
        state.append(int.from_bytes(nonce[4*i:4*i+4], "little"))

    working = state.copy()
    for _ in range(10):  # 20 rounds
        # column
        working[0], working[4], working[8], working[12] = quarter_round(working[0], working[4], working[8], working[12])
        working[1], working[5], working[9], working[13] = quarter_round(working[1], working[5], working[9], working[13])
        working[2], working[6], working[10], working[14] = quarter_round(working[2], working[6], working[10], working[14])
        working[3], working[7], working[11], working[15] = quarter_round(working[3], working[7], working[11], working[15])
        # diagonal
        working[0], working[5], working[10], working[15] = quarter_round(working[0], working[5], working[10], working[15])
        working[1], working[6], working[11], working[12] = quarter_round(working[1], working[6], working[11], working[12])
        working[2], working[7], working[8],  working[13] = quarter_round(working[2], working[7], working[8],  working[13])
        working[3], working[4], working[9],  working[14] = quarter_round(working[3], working[4], working[9],  working[14])

    out = [(a + b) & 0xffffffff for a, b in zip(state, working)]
    return b"".join(x.to_bytes(4, "little") for x in out)

key   = bytes(range(32))  # 00 01 02 ... 1f
nonce = bytes.fromhex("000000000000004a00000000")
enc   = bytes.fromhex(
    "44 23 30 94 3b 72 97 d0 70 b8 06 01 d1 3c 50 84"
    " e2 22 40 ef 0d 02 28 cc 4f 10 ee 89 ad ac b6 37"
    " ff 46"
)

ks = chacha_block(key, 1, nonce)   # counter = 1
flag = bytes(e ^ k for e, k in zip(enc, ks[:len(enc)]))
print(flag)
print(flag.decode())
```
FLAG: `flag{iN1_f!ni_Min1_m0...1_$e3_yOu}`