import sys
sys.stdout.reconfigure(encoding='utf-8',errors='replace')

DELTA = 0x9e3779b9
M = 0xffffffff

def be32(b, o): return (b[o]<<24)|(b[o+1]<<16)|(b[o+2]<<8)|b[o+3]
def be32b(v): return bytes([(v>>24)&0xff,(v>>16)&0xff,(v>>8)&0xff,v&0xff])

def tea_enc(pt, key, rounds=16):
    v0, v1 = be32(pt,0), be32(pt,4)
    k = [be32(key,i*4) for i in range(4)]
    s = 0
    for _ in range(rounds):
        s = (s + DELTA) & M
        v0 = (v0 + ((((v1<<4)&M) + k[0]) ^ ((v1 + s)&M) ^ (((v1>>5) + k[1])&M))) & M
        v1 = (v1 + ((((v0<<4)&M) + k[2]) ^ ((v0 + s)&M) ^ (((v0>>5) + k[3])&M))) & M
    return be32b(v0)+be32b(v1)

def tea_dec(ct, key, rounds=16):
    v0, v1 = be32(ct,0), be32(ct,4)
    k = [be32(key,i*4) for i in range(4)]
    s = (DELTA * rounds) & M
    for _ in range(rounds):
        v1 = (v1 - ((((v0<<4)&M) + k[2]) ^ ((v0 + s)&M) ^ (((v0>>5) + k[3])&M))) & M
        v0 = (v0 - ((((v1<<4)&M) + k[0]) ^ ((v1 + s)&M) ^ (((v1>>5) + k[1])&M))) & M
        s = (s - DELTA) & M
    return be32b(v0)+be32b(v1)

tests = [
 ("0011223344556677", "000102030405060708090a0b0c0d0e0f", "205f515574f0821c"),
 ("0000000000000000", "00000000000000000000000000000000", "a889f798182d8083"),
 ("0102030405060708", "000102030405060708090a0b0c0d0e0f", "6ac3f66fac01d1ad"),
]
print("大端 TEA-16轮/delta=0x9e3779b9 复现 native 结果：")
allok=True
for pt,k,expect in tests:
    got = tea_enc(bytes.fromhex(pt), bytes.fromhex(k)).hex()
    ok = got==expect
    allok &= ok
    print(f"  pt={pt} key={k}")
    print(f"    native={expect}  mine={got}  {'✔' if ok else '✘'}")
    back = tea_dec(bytes.fromhex(expect), bytes.fromhex(k)).hex()
    print(f"    解密回={back}  {'✔' if back==pt else '✘'}")
print()
print("全部吻合:", allok)
