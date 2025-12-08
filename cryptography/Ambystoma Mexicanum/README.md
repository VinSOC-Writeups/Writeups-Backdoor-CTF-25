# Ambystoma Mexicanum

## Description
> The axolotl (Ambystoma mexicanum) is a species of paedomorphic mole salamander, meaning they mature without undergoing metamorphosis into the terrestrial adult form; the adults remain fully aquatic with obvious external gills.
> 
> nc remote.infoseciitr.in 4004
 
## Vulnerability
The server uses the [AES GCMSIV](https://eprint.iacr.org/2017/168.pdf) encryption system.

The exploitation point leading to the unintended solution is the following code segment:

```
for i in range(4):
    key = binascii.unhexlify(KEYS[i % len(KEYS)])
    ct = binascii.unhexlify(CIPHERTEXTS[i % len(CIPHERTEXTS)])
```

* Using the modulo operation: If there's only 1 key, all 4 iterations use the same key, so we just need to use the first key to encrypt 4 plaintext blocks sequentially:

```
block0 = b"gib me flag p" + b"   "   # 13 chars + 3 spaces
block1 = b"l" + b" " * 15
block2 = b"i" + b" " * 15
block3 = b"s" + b" " * 15
```

so that after decryption, they can be combined to form the target message.

## PoC
```
from pwn import *
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

HOST = "remote.infoseciitr.in"   
PORT = 4004          

def main():
    r = remote(HOST, PORT)

    r.recvuntil(b"Your choice:")

    r.sendline(b"2")
    data = r.recvuntil(b"Your choice:").decode()


    key_match   = re.search(r"KEYS=\['([0-9a-f]+)'\]", data)
    nonce_match = re.search(r"nonce=([0-9a-f]+)", data)
    assert key_match and nonce_match, "Failed to parse key/nonce"

    key_hex   = key_match.group(1)
    nonce_hex = nonce_match.group(1)

    print(f"[+] Leaked key:   {key_hex}")
    print(f"[+] Leaked nonce: {nonce_hex}")

    key   = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)

    block0 = b"gib me flag p" + b"   "   # 13 chars + 3 spaces
    block1 = b"l" + b" " * 15
    block2 = b"i" + b" " * 15
    block3 = b"s" + b" " * 15
    P = block0 + block1 + block2 + block3
    assert len(P) == 64

    aead = AESGCMSIV(key)
    ct   = aead.encrypt(nonce, P, b"")
    ct_hex = ct.hex()
    print(f"[+] Forged ciphertext (hex): {ct_hex}")

    r.sendline(b"3")
    r.recvuntil(b"Enter ciphertext (hex):")
    r.sendline(ct_hex.encode())

    r.recvuntil(b"Your choice:")

    r.sendline(b"4")

    print(r.recvall().decode())

if __name__ == "__main__":
    main()
    
flag{th3_4x0lo7ls_4r3_n07_wh47_th3y_s33m}
```
