# CTF Writeups

A collection of my CTF writeups, notes, and things I learned while breaking stuff.

This repository documents my journey through **binary exploitation, web security, reverse engineering, cryptography, forensics, and other areas of cybersecurity**.

Some writeups are detailed walkthroughs, while others are more like notes on what I discovered while solving a challenge.

## Categories

* **Pwn** — buffer overflows, ROP, heap exploitation, format strings, and other binary exploitation techniques
* **Web** — authentication, access control, server-side vulnerabilities, and web exploitation
* **Reverse Engineering** — binary analysis, debugging, and program behavior
* **Crypto** — cryptographic vulnerabilities and challenges
* **Forensics** — file analysis, memory, network, and artifact investigation
* **Misc** — challenges that don't fit neatly into the categories above

## CTFs

| CTF      | Year | Categories    |
| -------- | ---- | ------------- |
| Compfest | 2026 | Pwn           |
| Gemastik | 2026 | Pwn           |
| ARA-ITS  | 2026 | Pwn           |
| CBD      | 2026 | Pwn           |

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

*explore, get lost, find your way back, learn, grow, repeat*
