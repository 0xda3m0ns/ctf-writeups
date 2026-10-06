# CTF Writeups

A collection of my CTF writeups, notes, and things I learned while breaking stuff.

This repository documents my journey through **binary exploitation, web security, reverse engineering, cryptography, forensics, and other areas of cybersecurity**.

Some writeups are detailed walkthroughs, while others are more like notes on what I discovered while solving a challenge.

## Categories

* **Pwn** — buffer overflows, ROP, heap exploitation, format strings, and other binary exploitation techniques

## CTFs

| CTF      | Year | Categories    |
| -------- | ---- | ------------- |
| ARA-ITS  | 2026 | Pwn           |
| REDLIMIT | 2026 | Pwn           |
| TRYHARDS | 2026 | Pwn           |

> This list will grow as I keep solving things.

## Structure

```text
ctf-writeups/
├── 2026/
│   ├── competition-name/
│   │   ├── pwn/
│   │   │   ├── challenge-name/
│   │   │   │   ├── README.md
│   │   │   │   └── solve.py
│   │   │   ├── ...
│   │   │   └── ...
│   └── lab-name/
│   │   ├── pwn/
│   │   │   ├── challenge-name/
│   │   │   │   ├── README.md
│   │   │   │   └── solve.py
│   │   │   ├── ...
│   │   │   └── ...
└── README.md
└── LICENSE
```

Each challenge directory may contain:

* `README.md` — the writeup
* exploit scripts
* relevant source code
* notes and analysis
* other files used during the solve

## Disclaimer

These writeups are written for **educational purposes and authorized CTF environments**.

Techniques demonstrated here should only be used against systems you have permission to test.

---

*explore, get lost, find your way back, learn, grow, repeat.*
