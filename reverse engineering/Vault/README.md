# Vault
## Description

I heard you are a master at breaking vaults, try to break this one..

## Analysis
Based on the challenge name "Vault", we can guess this is a binary related to shellcode. When opening the file with IDA Pro, we can see the main program flow as follows:

## 1. Quick recon

```bash
file chal
# ELF 64-bit LSB pie executable, x86-64, stripped

readelf -h chal | grep 'Entry point'
# Entry point: 0x1160

readelf -S chal | grep '\.data'
# .data: vaddr 0x4000, file offset 0x3000, size 0x1380
```

Useful imported functions from the PLT:

- `printf`, `puts`, `__isoc23_scanf`, `strcspn`
- `mmap`, `munmap`, `perror`, `exit`

So we immediately suspect some dynamic code generation (JIT) via `mmap`.

### `main` – input & length check

Disassembling around 0x1460 shows the main function:

- Prints the intro string (vault story) and a prompt.
- Reads the password into a 0x90‑byte stack buffer via `__isoc23_scanf`.
- Uses `strcspn` to strip the trailing newline and stores the length in `[rbp-0x98]`.
- If length != `0x35` (53), it prints an error message and exits.
- If length == `0x35`, it calls the verifier at `0x1379`, passing the pointer to string in `rdi`.

So we know the *only* accepted password is exactly 53 bytes long.

### The JIT builder (function at 0x1249)

The verifier calls a helper at 0x1249 with `edi = index` for each character position.

Pseudocode for 0x1249:

```c
void *build_shellcode(int idx) {
    // mmap RWX 0x8000 bytes
    void *buf = mmap(NULL, 0x8000, PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) { perror("mmap"); exit(-1); }

    // local tmp[57]
    for (int j = 0; j <= 0x38; j++) {
        // index into a big byte table at .data+0x20 (vaddr 0x4020)
        size_t off = idx * 57 + j;
        uint8_t b = byte_table_4020[off];

        // XOR with a dword from 0x4C00 and keep only the low byte
        uint32_t key = dword_table_4C00[idx];
        tmp[j] = (uint8_t)(b ^ (uint8_t)key);
    }

    // then splat tmp[0..56] into `buf` as overlapping qwords,
    // resulting in a 57‑byte chunk of executable shellcode.
    // Finally return buf;
}
```

So for each character position `i`, the program builds a custom 57‑byte piece of code and returns a
function pointer to it.

### The verifier (function at 0x1379)

The function at 0x1379 loops over every character of input string:

```c
int check(const char *s) {
    int i = 0;
    for (;;) {
        unsigned char ch = s[i];
        if (!ch) break;            // end of string

        void *code = build_shellcode(i);  // 0x1249
        uint32_t *pattern = &table_bits_4CE0[i * 8];
        uint32_t key      = dword_table_4C00[i];

        int ok = jit_func(ch, key, 0, 0, pattern); // call via function pointer
        if (ok != 1) {
            puts("Wrong password");
            exit(-1);
        }
        munmap(code, 0x8000);
        i++;
    }
    puts("Correct password");
    return 0;
}
```

The interesting part is what `jit_func` actually does with `(ch, key, pattern)`.

### Reversing the shellcode

We can reconstruct the shellcode bytes **for a given index** entirely in Python by mimicking the loop in
0x1249 (that’s exactly what the solver does internally), but to understand the logic we only need one
instance, say for `idx = 0`.

Once we build those 57 bytes, we disassemble them as raw x86‑64:

```bash
# code0.bin contains the first 80 bytes of the mmap'ed shellcode for index 0
objdump -D -b binary -m i386:x86-64 code0.bin
```

The disassembly (cleaned up) is:

```asm
mov  ecx, 4              ; start checking from bit 4
xor  rdi, rsi            ; rdi = ch ^ key
loop_start:
    cmp  rdx, 8
    sete al
    je   done_success    ; if we checked 8 bits, return 1

    mov  rax, rdi
    shr  rax, cl         ; shift our value by cl bits
    and  rax, 1          ; keep only the lowest bit
    mov  rbx, rax

    movzbq rax, [r8 + rdx*4]  ; pattern[rdx], 8 entries of 0/1
    cmp    rax, rbx
    sete   al
    jne    done_fail     ; mismatch -> return 0

    inc  rdx             ; next pattern entry
    inc  rcx             ; next bit of v
    and  rcx, 7          ; wrap around mod 8
    jmp  loop_start

done_fail:
    ret
done_success:
    ret
```

Call-site register setup (from 0x1379):

- `rdi` = sign-extended input character
- `rsi` = 32‑bit key from table at 0x4C00
- `rdx` = 0
- `rcx` = 0
- `r8`  = pointer into the table at 0x4CE0 (8 dwords per character index)

So the **abstract logic** of the shellcode is:

```c
int jit(int ch, uint32_t key, int zero1, int zero2, uint32_t *pattern) {
    unsigned long v = (unsigned long)ch ^ (unsigned long)key;
    int bit = 4;       // start from bit 4
    int k   = 0;       // pattern index

    for (;;) {
        if (k == 8) return 1;  // all 8 bits matched

        unsigned long actual = (v >> bit) & 1;
        unsigned long expected = pattern[k] & 1;  // 8 entries of 0 or 1

        if (actual != expected) return 0;

        k++;
        bit = (bit + 1) & 7;  // 4,5,6,7,0,1,2,3
    }
}
```

### Understanding the data tables

From the disassembly:

- Byte table at **0x4020** (vaddr) in `.data` – used only to construct the shellcode.
- Dword key table at **0x4C00** – 64 entries of 32‑bit keys.
- Dword bit-pattern table at **0x4CE0** – for each character index `i`, 8 x 32‑bit integers (0 or 1),
  i.e. 32 bytes per index.

We don’t actually need the byte table at 0x4020 to *solve* the challenge; it’s just an obfuscation layer
for the JIT. Once we know what the shellcode does, only 0x4C00 and 0x4CE0 matter.

Let:

```c
v_i = password[i] ^ (key[i] & 0xFF);
```

and let `pattern[i][k]` be the 8 dwords at `0x4CE0 + i*32 + k*4`, each equal to 0 or 1.

The shellcode checks:

- `pattern[i][0] == bit4(v_i)`
- `pattern[i][1] == bit5(v_i)`
- `pattern[i][2] == bit6(v_i)`
- `pattern[i][3] == bit7(v_i)`
- `pattern[i][4] == bit0(v_i)`
- `pattern[i][5] == bit1(v_i)`
- `pattern[i][6] == bit2(v_i)`
- `pattern[i][7] == bit3(v_i)`

So each index `i` has an 8‑bit pattern that exactly encodes the bits of `v_i`.

### Inverting the check

For each position `i`:

1. Read the 8 dwords from 0x4CE0:
   `bits[k] = (raw_bits[32*i + 4*k] & 1)` for `k = 0..7`.
2. Reconstruct `v_i` from those bits:

   ```python
   v = 0
   # bits[0..3] -> bits 4..7
   for bitpos in range(4, 8):
       if bits[bitpos - 4]:
           v |= (1 << bitpos)
   # bits[4..7] -> bits 0..3
   for bitpos in range(0, 4):
       if bits[bitpos + 4]:
           v |= (1 << bitpos)
   ```

3. Recover the actual password byte as:

   ```python
   ch = v ^ (key[i] & 0xFF)
   ```

Doing this for all 53 positions yields a 53‑byte password.

The provided solver (`solve_chal.py`) implements exactly this logic directly on the `chal` binary.


## Solve

```c
#!/usr/bin/env python3
import struct

FILENAME = "chal"   # change if filename is different

def main():
    with open(FILENAME, "rb") as f:
        data = f.read()

    # According to readelf: .data has virtual addr 0x4000 and file offset 0x3000
    off_data = 0x3000

    # Offsets in .data obtained from disassembly:
    # 0x4020: byte table used to build shellcode (57 bytes / index, 64 indexes)
    # 0x4c00: dword key table (4 bytes / index, 64 indexes)
    # 0x4ce0: bit pattern table (32 bytes / index, 64 indexes)
    off_4020 = off_data + 0x20   # 0x4020
    off_4c00 = off_data + 0xC00  # 0x4C00
    off_4ce0 = off_data + 0xCE0  # 0x4CE0

    n_slots = 64
    raw_shell = data[off_4020: off_4020 + 57 * n_slots]
    raw_keys  = data[off_4c00: off_4c00 + 4  * n_slots]
    raw_bits  = data[off_4ce0: off_4ce0 + 32 * n_slots]

    # key[i] is a dword, but shellcode only uses the low byte
    keys = [struct.unpack_from("<I", raw_keys, 4 * i)[0] for i in range(n_slots)]

    def recover_char(i: int) -> int:
        """
        Based on shellcode:
          v = ch ^ key_byte
          then check 8 bits of v in bitpos order: 4,5,6,7,0,1,2,3
          expected bit values are taken from table 4ce0, each index occupies 32 bytes,
          but only uses 8 bytes at offset 0,4,8,...,28 (1 byte each time).
        We reverse: from 8 expected bits -> v -> ch.
        """
        key_byte = keys[i] & 0xFF

        # Get 8 bits (actually 8 bytes of 0/1) for index i
        bits = [(raw_bits[32 * i + 4 * t] & 1) for t in range(8)]

        # Rebuild v = ch ^ key_byte from those bits.
        # mapping:
        #  t=0..3  -> bitpos 4..7
        #  t=4..7  -> bitpos 0..3
        v = 0
        # bit 4..7
        for bitpos in range(4, 8):
            t = bitpos - 4
            if bits[t]:
                v |= (1 << bitpos)
        # bit 0..3
        for bitpos in range(0, 4):
            t = bitpos + 4
            if bits[t]:
                v |= (1 << bitpos)

        ch = v ^ key_byte
        return ch

    # main() in binary requires length = 0x35 (53) before calling the check function
    length = 0x35
    secret = bytes(recover_char(i) for i in range(length))

    # Print results
    print("Raw password bytes:", list(secret))
    print("Raw password hex  :", secret.hex())
    print("Printable preview :", ''.join(chr(c) if 32 <= c < 127 else '.' for c in secret))

    # A reasonable flag format: flag{<password_hex>}
    print("\nCandidate flag (password hex-encoded):")
    print(f"flag{{{secret.hex()}}}")

if __name__ == "__main__":
    main()
```

FLAG: `flag{hm_she11c0d3_v4u17_cr4ck1ng_4r3_t0ugh_r1gh7!!??}`