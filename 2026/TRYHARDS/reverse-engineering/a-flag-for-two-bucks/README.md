# a-flag-for-two-bucks

> Category: Reverse Engineering
> CTF: TRYHARDS
> Year: 2026

## Description

We are given `aflagfortwobucks`, a stripped x86-64 ELF that pretends to be a pawn shop. It asks for a flag, runs the input through a small in-place byte transform, and then `strncmp`s the result against a 39-byte constant in `.rodata`. There is no encryption and no key: the transform chains a 32-bit state with `state = state * 33 ^ x`, where `x` is built from a pair of input bytes as `(c0 * 0x101) ^ (c1 * 0x1fd)`. Because only the low two bytes of the state are written back to the buffer, the low 16 bits of the state evolve independently and the whole check can be inverted pair by pair. A brute force over `256 * 256` byte pairs recovers a unique printable pair for each of the 19 stored states, and the final odd byte is recovered from the low 8 bits.

---

## Initial Analysis

### File / Binary

The supplied archive contains a single file:

```text
a-flag-for-two-bucks.zip
└── aflagfortwobucks        # 14408-byte ELF
```

```bash
$ file aflagfortwobucks
aflagfortwobucks: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, stripped
```

The binary is stripped, so the interesting code is found from `_start`. `0x4010a4` loads `0x40126a` into `rdi` before calling `__libc_start_main`, which makes `0x40126a` the real `main`. The check logic is the function at `0x401176`, called from `main` with the input buffer and its length.

The target in `.rodata`:

```text
0x402020: fe b6 ef 60 04 fd 47 1d f6 5f 1b 87 e2 bb 70 68
0x402030: 1b ae 94 f0 bb db 96 81 ed 09 0d a9 4e 43 f5 51
0x402040: 73 65 85 47 4d 66 90
```

### Program Behavior

The program is a single prompt with two possible replies:

```text
$ ./aflagfortwobucks
Welcome to my Pawn Shop, go ahead and show me the flag you want appraised: hello
Unfortunately, your flag here looks to be a counterfeit.

$ ./aflagfortwobucks
Welcome to my Pawn Shop, go ahead and show me the flag you want appraised: TryHards{...}
Well good news, your flag looks to be authentic! Best I can do is $2.
```

| address | meaning |
|---|---|
| `0x40126a` | `main` |
| `0x401176` | in-place transform / check function |
| `0x402020` | target bytes (39 bytes) |
| `0x402048` | prompt string |
| `0x402094` | `"\r\n"` delimiter for `strcspn` |
| `0x402098` | authentic message |
| `0x4020e0` | counterfeit message |

The relevant part of `main` is:

```asm
401306 mov    rdx,QWORD PTR [rip+0x2d43]        # stdin
40130d lea    rax,[rbp-0x70]                    # char buf[100]
401311 mov    esi,0x64
401319 call   fgets
...
40132a lea    rax,[rbp-0x70]
40132e mov    esi,0x402094                      # "\r\n"
401336 call   strcspn
40133b mov    QWORD PTR [rbp-0x8],rax           # len
40133f lea    rdx,[rbp-0x70]
401343 mov    rax,QWORD PTR [rbp-0x8]
401347 add    rax,rdx
40134a mov    BYTE PTR [rax],0x0                # strip newline
...
401355 mov    rsi,rdx                           # len
401358 mov    rdi,rax                           # buf
40135b call   0x401176                          # transform(buf, len)
...
401364 mov    edx,0x27                          # 39
401369 mov    esi,0x402020                      # target
40136e mov    rdi,rax                           # transformed buf
401371 call   strncmp
401376 test   eax,eax
401378 jne    0x401386                          # counterfeit
40137a mov    edi,0x402098
40137f call   puts                              # authentic
```

Two details are decided here:

- `fgets` reads at most `0x64` bytes, so the flag is a normal line of text.
- `strncmp` uses length `0x27 = 39`, which is exactly the size of the target blob at `0x402020`. The flag is therefore 39 characters long.

### Algorithm / Check

`0x401176` is a small function with three locals: `state` (a 32-bit int at `rbp-0x4`, initialized to `0`), the byte index `i` at `rbp-0x10`, and `len` at `rbp-0x20`. It walks the buffer two bytes at a time:

```asm
401176 push   rbp
401177 mov    rbp,rsp
40117a mov    QWORD PTR [rbp-0x18],rdi           # data
40117e mov    QWORD PTR [rbp-0x20],rsi           # len
401182 mov    DWORD PTR [rbp-0x4],0x0            # state = 0
401189 mov    QWORD PTR [rbp-0x10],0x0           # i = 0
401191 jmp    0x401209
401193 mov    rdx,QWORD PTR [rbp-0x18]
401197 mov    rax,QWORD PTR [rbp-0x10]
40119b add    rax,rdx
40119e movzx  eax,BYTE PTR [rax]                 # c0 = data[i]
4011a1 movzx  edx,al
4011a4 mov    eax,edx
4011a6 shl    eax,0x8
4011a9 add    edx,eax                            # c0 * 0x101
4011ab mov    rax,QWORD PTR [rbp-0x10]
4011af lea    rcx,[rax+0x1]
4011b3 mov    rax,QWORD PTR [rbp-0x18]
4011b7 add    rax,rcx
4011ba movzx  eax,BYTE PTR [rax]                 # c1 = data[i+1]
4011bd movzx  eax,al
4011c0 imul   eax,eax,0x1fd                       # c1 * 0x1fd
4011c6 mov    ecx,edx
4011c8 xor    ecx,eax                            # x = (c0*0x101) ^ (c1*0x1fd)
4011ca mov    edx,DWORD PTR [rbp-0x4]            # state
4011cd mov    eax,edx
4011cf shl    eax,0x5                            # state << 5
4011d2 add    eax,edx                            # state * 33
4011d4 xor    eax,ecx
4011d6 mov    DWORD PTR [rbp-0x4],eax            # state = state*33 ^ x
4011d9 mov    rdx,QWORD PTR [rbp-0x18]
4011dd mov    rax,QWORD PTR [rbp-0x10]
4011e1 add    rax,rdx
4011e4 mov    edx,DWORD PTR [rbp-0x4]
4011e7 mov    BYTE PTR [rax],dl                  # data[i] = state & 0xff
4011e9 mov    eax,DWORD PTR [rbp-0x4]
4011ec shr    eax,0x8
4011ef mov    ecx,eax
4011f1 mov    rax,QWORD PTR [rbp-0x10]
4011f5 lea    rdx,[rax+0x1]
4011f9 mov    rax,QWORD PTR [rbp-0x18]
4011fd add    rax,rdx
401200 mov    edx,ecx
401202 mov    BYTE PTR [rax],dl                  # data[i+1] = (state >> 8) & 0xff
401204 add    QWORD PTR [rbp-0x10],0x2           # i += 2
401209 mov    rax,QWORD PTR [rbp-0x10]
40120d add    rax,0x1
401211 cmp    rax,QWORD PTR [rbp-0x20]
401215 jb     0x401193                          # while (i+1 < len)
```

In pseudocode, for every pair of input bytes `(c0, c1)`:

```text
x     = (c0 * 0x101) ^ (c1 * 0x1fd)
state = state * 33 ^ x
data[i]     =  state        & 0xff
data[i + 1] = (state >> 8)  & 0xff
```

After the loop, an odd trailing byte is handled separately:

```asm
40121b mov    rax,QWORD PTR [rbp-0x20]
40121f and    eax,0x1
401222 test   rax,rax
401225 je     0x401267
401227 mov    rax,QWORD PTR [rbp-0x20]
40122b lea    rdx,[rax-0x1]
40122f mov    rax,QWORD PTR [rbp-0x18]
401233 add    rax,rdx
401236 movzx  eax,BYTE PTR [rax]                 # last = data[len-1]
401239 movzx  edx,al
40123c mov    eax,edx
40123e shl    eax,0x8
401241 lea    ecx,[rax+rdx*1]                    # last * 0x101
401244 mov    edx,DWORD PTR [rbp-0x4]
401247 mov    eax,edx
401249 shl    eax,0x5
40124c add    eax,edx                            # state * 33
40124e xor    eax,ecx
401250 mov    DWORD PTR [rbp-0x4],eax            # state = state*33 ^ (last*0x101)
401253 mov    rax,QWORD PTR [rbp-0x20]
401257 lea    rdx,[rax-0x1]
40125b mov    rax,QWORD PTR [rbp-0x18]
40125f add    rax,rdx
401262 mov    edx,DWORD PTR [rbp-0x4]
401265 mov    BYTE PTR [rax],dl                  # data[len-1] = state & 0xff
```

Only the low byte is written for the odd tail, but that is enough to invert it later.

## Solution

### Reconstruction / Inversion

The state is a 32-bit `int`, and `c1 * 0x1fd` can exceed 16 bits, so the full state is not stored. Only two bytes of each state reach the output. Normally that would make the chain lossy, but the recurrence saves us:

```text
state_k = (state_{k-1} * 33) ^ x_k
```

The low 16 bits of `state_{k-1} * 33` depend only on the low 16 bits of `state_{k-1}`, and `x_k` is 16-bit for the purposes of the low half. XOR cannot move bits downward. Therefore the low 16 bits of the state evolve independently of the high bits:

```text
s_k = ((s_{k-1} * 33) & 0xffff) ^ ((c0 * 0x101) & 0xffff) ^ ((c1 * 0x1fd) & 0xffff)
```

where `s_k` is precisely the little-endian 16-bit value stored at `data[2k]`. The high bits never influence `s_k`, so the check can be reconstructed exactly from the target pairs alone. For the odd tail, only the low byte is written, and `(last * 0x101) & 0xff == last`, so the same reasoning reduces to an 8-bit inversion.

```text
t_k = target[2k] | (target[2k + 1] << 8)          # stored state s_k
t_k = ((s_{k-1} * 33) & 0xffff) ^ x_k             # invert for x_k
```

Because `s_{k-1}` is known, each pair reduces to finding `(c0, c1)` such that

```text
((c0 * 0x101) & 0xffff) ^ ((c1 * 0x1fd) & 0xffff) == t_k ^ ((s_{k-1} * 33) & 0xffff)
```

There are only `256 * 256 = 65536` possible pairs, so a full brute force per state is trivial. For every state the printable filter leaves exactly one candidate, which makes the recovery unambiguous. The completed pairs are:

| k | stored state | recovered |
|---:|---:|---|
| 0 | `0xb6fe` | `Tr` |
| 1 | `0x60ef` | `yH` |
| 2 | `0xfd04` | `ar` |
| 3 | `0x1d47` | `ds` |
| 4 | `0x5ff6` | `{r` |
| 5 | `0x871b` | `3v` |
| 6 | `0xbbe2` | `3r` |
| 7 | `0x6870` | `53` |
| 8 | `0xae1b` | `_D` |
| 9 | `0xf094` | `_p` |
| 10 | `0xdbbb` | `4w` |
| 11 | `0x8196` | `n_` |
| 12 | `0x09ed` | `sh` |
| 13 | `0xa90d` | `0p` |
| 14 | `0x434e` | `_l` |
| 15 | `0x51f5` | `0g` |
| 16 | `0x6573` | `1c` |
| 17 | `0x4785` | `13` |
| 18 | `0x664d` | `37` |

The final target byte is `0x90`. With `s_18 = 0x664d`:

```text
last = 0x90 ^ ((0x664d * 33) & 0xff)
     = 0x90 ^ 0xed
     = 0x7d
     = '}'
```

Concatenating the 19 pairs and the trailing byte gives the flag.

### Verification

Feeding the recovered string back into the binary confirms the check:

```text
$ printf 'TryHards{r3v3r53_D_p4wn_sh0p_l0g1c1337}\n' | ./aflagfortwobucks
Welcome to my Pawn Shop, go ahead and show me the flag you want appraised: Well good news, your flag looks to be authentic! Best I can do is $2.
```

## Solver

```python
target = bytes.fromhex("feb6ef6004fd471df65f1b87e2bb7068"
    "1bae94f0bbdb9681ed090da94e43f551"
    "736585474d6690")

L = len(target)

n_pairs = L // 2 
states = []
for k in range(n_pairs):
    st = target[2*k] | (target[2*k+1] << 8)
    states.append(st)

flag = bytearray()
prev = 0 
for k in range(n_pairs):
    st = states[k]
    lhs = (st ^ ((prev*33) & 0xffff)) & 0xffff
    cand = []
    for a in range(256):
        va = (a*0x101) & 0xffff
        for b in range(256):
            vb = (b*0x1fd) & 0xffff
            if (va ^ vb) == lhs:
                cand.append((a,b))

    good = [(a,b) for a,b in cand if 32 <= a < 127 and 32 <= b < 127]
    pick = good[0] if good else cand[0]
    flag += bytes(pick)
    prev = st 

if L & 1:
    out_last = target[-1]

    a = out_last ^ ((prev*33) & 0xff)
    flag.append(a)

print(flag)
print(flag.decode(errors='replace'))
```

Running it:

```text
$ python3 solve.py
bytearray(b'TryHards{r3v3r53_D_p4wn_sh0p_l0g1c1337}')
TryHards{r3v3r53_D_p4wn_sh0p_l0g1c1337}
```

## Flag

```text
TryHards{r3v3r53_D_p4wn_sh0p_l0g1c1337}
```

## Takeaways

- This is obfuscation, not cryptography. There is no secret key; every constant (`0x101`, `0x1fd`, `33`) is in the binary, and the check map is small enough to brute force.
- A 32-bit state can leak only two bytes per step and still be fully reversible, as long as the bits that survive depend only on themselves. Here the low 16 bits of `state * 33` depend only on the low 16 bits of `state`.
- The pair encoding `(c0 * 0x101) ^ (c1 * 0x1fd)` is a 16-bit mixing function over 65,536 inputs. Enumerating all byte pairs recovers the plaintext directly, and the printable filter makes the result unique.
- The odd-length tail shrinks to 8 bits because `(c * 0x101) & 0xff == c`, so the same inversion idea applies with a one-byte brute force.
- Always validate a recovered flag by running the original binary; the "authentic" message is the ground truth that the inversion is correct.
