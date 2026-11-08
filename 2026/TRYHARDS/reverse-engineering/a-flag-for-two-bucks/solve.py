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
