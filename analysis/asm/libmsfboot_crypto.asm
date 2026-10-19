# libmsfbootV2.so 加密相关函数反汇编
# base = 0x12000000

================================================================================
## _ZN7QSCrypt7EncryptEPKhiPhRi
## base+0x2668c
================================================================================
1202668c  sub        sp, sp, #0x90
12026690  stp        x29, x30, [sp, #0x30]
12026694  add        x29, sp, #0x30
12026698  stp        x28, x27, [sp, #0x40]
1202669c  stp        x26, x25, [sp, #0x50]
120266a0  stp        x24, x23, [sp, #0x60]
120266a4  stp        x22, x21, [sp, #0x70]
120266a8  stp        x20, x19, [sp, #0x80]
120266ac  mrs        x9, tpidr_el0
120266b0  ldr        x8, [x9, #0x28]
120266b4  stur       x8, [x29, #-8]
120266b8  ldrb       w8, [x0, #0x18]
120266bc  cbnz       w8, #0x12026ac0
120266c0  add        w8, w2, #0xa
120266c4  stp        x1, x9, [sp, #8]
120266c8  add        w9, w2, #0x11
120266cc  cmp        w8, #0
120266d0  csel       w9, w9, w8, lt
120266d4  mov        x19, x4
120266d8  and        w9, w9, #0xfffffff8
120266dc  mov        x23, x3
120266e0  subs       w8, w8, w9
120266e4  movz       w9, #0x8
120266e8  sub        w8, w9, w8
120266ec  mov        x20, x0
120266f0  mov        w21, w2
120266f4  csel       w22, wzr, w8, eq
120266f8  bl         #0x1204d490
120266fc  movz       w27, #0x3
12026700  movz       w28, #0xfffe
12026704  movk       w27, #0x8001, lsl #16
12026708  smull      x8, w0, w27
1202670c  lsr        x8, x8, #0x20
12026710  add        w8, w8, w0
12026714  lsr        w9, w8, #0xf
12026718  add        w8, w9, w8, lsr #31
1202671c  msub       w8, w8, w28, w0
12026720  and        w8, w8, #0xf8
12026724  orr        w8, w8, w22
12026728  sturb      w8, [x29, #-0x10]
1202672c  cbz        w22, #0x12026770
12026730  sub        x8, x29, #0x10
12026734  mov        x24, xzr
12026738  orr        x25, x8, #1
1202673c  bl         #0x1204d490
12026740  smull      x8, w0, w27
12026744  lsr        x8, x8, #0x20
12026748  add        w8, w8, w0
1202674c  lsr        w9, w8, #0xf
12026750  add        w8, w9, w8, lsr #31
12026754  msub       w8, w8, w28, w0
12026758  strb       w8, [x25, x24]
1202675c  add        x24, x24, #1
12026760  cmp        w22, w24
12026764  b.ne       #0x1202673c
12026768  add        w26, w24, #1
1202676c  b          #0x12026774
12026770  movz       w26, #0x1
12026774  add        x25, sp, #0x18
12026778  add        x20, x20, #8
1202677c  movz       w22, #0x1
12026780  str        xzr, [sp, #0x18]
12026784  str        wzr, [x19]
12026788  b          #0x12026858
1202678c  ldr        d0, [x25]
12026790  sub        x0, x29, #0x10
12026794  ldur       d1, [x29, #-0x10]
12026798  mov        x1, x20
1202679c  mov        x2, x23
120267a0  eor        v0.8b, v1.8b, v0.8b
120267a4  stur       d0, [x29, #-0x10]
120267a8  bl         #0x1204d470
120267ac  ldrb       w8, [sp, #0x18]
120267b0  add        x24, x23, #8
120267b4  ldrb       w9, [x23]
120267b8  mov        w26, wzr
120267bc  mov        x25, x23
120267c0  eor        w8, w9, w8
120267c4  ldrb       w9, [x23, #1]
120267c8  strb       w8, [x23]
120267cc  ldrb       w8, [sp, #0x19]
120267d0  eor        w8, w9, w8
120267d4  ldrb       w9, [x23, #2]
120267d8  strb       w8, [x23, #1]
120267dc  ldrb       w8, [sp, #0x1a]
120267e0  eor        w8, w9, w8
120267e4  ldrb       w9, [x23, #3]
120267e8  strb       w8, [x23, #2]
120267ec  ldrb       w8, [sp, #0x1b]
120267f0  eor        w8, w9, w8
120267f4  ldrb       w9, [x23, #4]
120267f8  strb       w8, [x23, #3]
120267fc  ldrb       w8, [sp, #0x1c]
12026800  eor        w8, w9, w8
12026804  ldrb       w9, [x23, #5]
12026808  strb       w8, [x23, #4]
1202680c  ldrb       w8, [sp, #0x1d]
12026810  eor        w8, w9, w8
12026814  ldrb       w9, [x23, #6]
12026818  strb       w8, [x23, #5]
1202681c  ldrb       w8, [sp, #0x1e]
12026820  eor        w8, w9, w8
12026824  ldrb       w9, [x23, #7]
12026828  strb       w8, [x23, #6]
1202682c  ldrb       w8, [sp, #0x1f]
12026830  eor        w8, w9, w8
12026834  strb       w8, [x23, #7]
12026838  mov        x23, x24
1202683c  ldr        w8, [x19]
12026840  ldur       x9, [x29, #-0x10]
12026844  add        w8, w8, #8
12026848  str        x9, [sp, #0x18]
1202684c  str        w8, [x19]
12026850  cmp        w22, #3
12026854  b.ge       #0x120268a0
12026858  cmp        w26, #7
1202685c  b.gt       #0x12026890
12026860  bl         #0x1204d490
12026864  smull      x8, w0, w27
12026868  sub        x10, x29, #0x10
1202686c  add        w22, w22, #1
12026870  lsr        x8, x8, #0x20
12026874  add        w8, w8, w0
12026878  lsr        w9, w8, #0xf
1202687c  add        w8, w9, w8, lsr #31
12026880  add        w9, w26, #1
12026884  msub       w8, w8, w28, w0
12026888  strb       w8, [x10, w26, sxtw]
1202688c  mov        w26, w9
12026890  cmp        w26, #8
12026894  b.eq       #0x1202678c
12026898  mov        x24, x23
1202689c  b          #0x12026850
120268a0  cbz        w21, #0x120269ac
120268a4  sub        x22, x29, #0x10
120268a8  ldr        x27, [sp, #8]
120268ac  b          #0x1202697c
120268b0  ldr        d0, [x25]
120268b4  sub        x0, x29, #0x10
120268b8  ldur       d1, [x29, #-0x10]
120268bc  mov        x1, x20
120268c0  mov        x2, x24
120268c4  eor        v0.8b, v1.8b, v0.8b
120268c8  stur       d0, [x29, #-0x10]
120268cc  bl         #0x1204d470
120268d0  ldrb       w8, [sp, #0x18]
120268d4  mov        w26, wzr
120268d8  ldrb       w9, [x24]
120268dc  add        x23, x24, #8
120268e0  mov        x25, x24
120268e4  eor        w8, w9, w8
120268e8  ldrb       w9, [x24, #1]
120268ec  strb       w8, [x24]
120268f0  ldrb       w8, [sp, #0x19]
120268f4  eor        w8, w9, w8
120268f8  ldrb       w9, [x24, #2]
120268fc  strb       w8, [x24, #1]
12026900  ldrb       w8, [sp, #0x1a]
12026904  eor        w8, w9, w8
12026908  ldrb       w9, [x24, #3]
1202690c  strb       w8, [x24, #2]
12026910  ldrb       w8, [sp, #0x1b]
12026914  eor        w8, w9, w8
12026918  ldrb       w9, [x24, #4]
1202691c  strb       w8, [x24, #3]
12026920  ldrb       w8, [sp, #0x1c]
12026924  eor        w8, w9, w8
12026928  ldrb       w9, [x24, #5]
1202692c  strb       w8, [x24, #4]
12026930  ldrb       w8, [sp, #0x1d]
12026934  eor        w8, w9, w8
12026938  ldrb       w9, [x24, #6]
1202693c  strb       w8, [x24, #5]
12026940  ldrb       w8, [sp, #0x1e]
12026944  eor        w8, w9, w8
12026948  ldrb       w9, [x24, #7]
1202694c  strb       w8, [x24, #6]
12026950  ldrb       w8, [sp, #0x1f]
12026954  eor        w8, w9, w8
12026958  strb       w8, [x24, #7]
1202695c  ldr        w8, [x19]
12026960  ldur       x9, [x29, #-0x10]
12026964  add        w8, w8, #8
12026968  str        x9, [sp, #0x18]
1202696c  str        w8, [x19]
12026970  mov        x8, x24
12026974  mov        x24, x23
12026978  cbz        w21, #0x120269b4
1202697c  cmp        w26, #7
12026980  b.gt       #0x12026998
12026984  ldrb       w8, [x27], #1
12026988  add        w9, w26, #1
1202698c  sub        w21, w21, #1
12026990  strb       w8, [x22, w26, sxtw]
12026994  mov        w26, w9
12026998  cmp        w26, #8
1202699c  b.eq       #0x120268b0
120269a0  mov        x23, x24
120269a4  mov        x24, x25
120269a8  b          #0x12026970
120269ac  mov        x23, x24
120269b0  mov        x8, x25
120269b4  movz       w21, #0x1
120269b8  sub        x22, x29, #0x10
120269bc  b          #0x120269c8
120269c0  cmp        w21, #8
120269c4  b.ge       #0x12026abc
120269c8  cmp        w26, #7
120269cc  b.le       #0x120269dc
120269d0  cmp        w26, #8
120269d4  b.ne       #0x120269c0
120269d8  b          #0x120269f4
120269dc  add        w9, w26, #1
120269e0  strb       wzr, [x22, w26, sxtw]
120269e4  add        w21, w21, #1
120269e8  mov        w26, w9
120269ec  cmp        w26, #8
120269f0  b.ne       #0x120269c0
120269f4  ldr        d0, [x8]
120269f8  sub        x0, x29, #0x10
120269fc  ldur       d1, [x29, #-0x10]
12026a00  mov        x1, x20
12026a04  mov        x2, x23
12026a08  eor        v0.8b, v1.8b, v0.8b
12026a0c  stur       d0, [x29, #-0x10]
12026a10  bl         #0x1204d470
12026a14  ldrb       w8, [sp, #0x18]
12026a18  mov        w26, wzr
12026a1c  ldrb       w9, [x23]
12026a20  eor        w8, w9, w8
12026a24  ldrb       w9, [x23, #1]
12026a28  strb       w8, [x23]
12026a2c  ldrb       w8, [sp, #0x19]
12026a30  eor        w8, w9, w8
12026a34  ldrb       w9, [x23, #2]
12026a38  strb       w8, [x23, #1]
12026a3c  ldrb       w8, [sp, #0x1a]
12026a40  eor        w8, w9, w8
12026a44  ldrb       w9, [x23, #3]
12026a48  strb       w8, [x23, #2]
12026a4c  ldrb       w8, [sp, #0x1b]
12026a50  eor        w8, w9, w8
12026a54  ldrb       w9, [x23, #4]
12026a58  strb       w8, [x23, #3]
12026a5c  ldrb       w8, [sp, #0x1c]
12026a60  eor        w8, w9, w8
12026a64  ldrb       w9, [x23, #5]
12026a68  strb       w8, [x23, #4]
12026a6c  ldrb       w8, [sp, #0x1d]
12026a70  eor        w8, w9, w8
12026a74  ldrb       w9, [x23, #6]
12026a78  strb       w8, [x23, #5]
12026a7c  ldrb       w8, [sp, #0x1e]
12026a80  eor        w8, w9, w8
12026a84  ldrb       w9, [x23, #7]
12026a88  strb       w8, [x23, #6]
12026a8c  ldrb       w8, [sp, #0x1f]
12026a90  eor        w8, w9, w8
12026a94  add        x9, x23, #8
12026a98  strb       w8, [x23, #7]
12026a9c  ldr        w8, [x19]
12026aa0  ldur       x10, [x29, #-0x10]
12026aa4  add        w11, w8, #8
12026aa8  mov        x8, x23
12026aac  mov        x23, x9
12026ab0  str        x10, [sp, #0x18]
12026ab4  str        w11, [x19]
12026ab8  b          #0x120269c0
12026abc  ldr        x9, [sp, #0x10]
12026ac0  ldr        x8, [x9, #0x28]
12026ac4  ldur       x9, [x29, #-8]
12026ac8  cmp        x8, x9
12026acc  b.ne       #0x12026af0
12026ad0  ldp        x20, x19, [sp, #0x80]
12026ad4  ldp        x22, x21, [sp, #0x70]
12026ad8  ldp        x24, x23, [sp, #0x60]
12026adc  ldp        x26, x25, [sp, #0x50]
12026ae0  ldp        x28, x27, [sp, #0x40]
12026ae4  ldp        x29, x30, [sp, #0x30]
12026ae8  add        sp, sp, #0x90
12026aec  ret        
12026af0  bl         #0x1204d080
12026af4  sub        sp, sp, #0x80
12026af8  stp        x29, x30, [sp, #0x20]
12026afc  add        x29, sp, #0x20
12026b00  stp        x28, x27, [sp, #0x30]
12026b04  stp        x26, x25, [sp, #0x40]
12026b08  stp        x24, x23, [sp, #0x50]
12026b0c  stp        x22, x21, [sp, #0x60]
12026b10  stp        x20, x19, [sp, #0x70]
12026b14  mrs        x24, tpidr_el0
12026b18  ldr        x9, [x24, #0x28]
12026b1c  stur       x9, [x29, #-8]
12026b20  ldrb       w9, [x0, #0x19]
12026b24  cbz        w9, #0x12026b5c
12026b28  mov        w0, wzr
12026b2c  ldr        x8, [x24, #0x28]
12026b30  ldur       x9, [x29, #-8]
12026b34  cmp        x8, x9
12026b38  b.ne       #0x12026f60
12026b3c  ldp        x20, x19, [sp, #0x70]
12026b40  ldp        x22, x21, [sp, #0x60]
12026b44  ldp        x24, x23, [sp, #0x50]
12026b48  ldp        x26, x25, [sp, #0x40]
12026b4c  ldp        x28, x27, [sp, #0x30]
12026b50  ldp        x29, x30, [sp, #0x20]
12026b54  add        sp, sp, #0x80
12026b58  ret        

================================================================================
## _ZN7QSCrypt7DecryptEPKhiPhRi
## base+0x26af4
================================================================================
12026af4  sub        sp, sp, #0x80
12026af8  stp        x29, x30, [sp, #0x20]
12026afc  add        x29, sp, #0x20
12026b00  stp        x28, x27, [sp, #0x30]
12026b04  stp        x26, x25, [sp, #0x40]
12026b08  stp        x24, x23, [sp, #0x50]
12026b0c  stp        x22, x21, [sp, #0x60]
12026b10  stp        x20, x19, [sp, #0x70]
12026b14  mrs        x24, tpidr_el0
12026b18  ldr        x9, [x24, #0x28]
12026b1c  stur       x9, [x29, #-8]
12026b20  ldrb       w9, [x0, #0x19]
12026b24  cbz        w9, #0x12026b5c
12026b28  mov        w0, wzr
12026b2c  ldr        x8, [x24, #0x28]
12026b30  ldur       x9, [x29, #-8]
12026b34  cmp        x8, x9
12026b38  b.ne       #0x12026f60
12026b3c  ldp        x20, x19, [sp, #0x70]
12026b40  ldp        x22, x21, [sp, #0x60]
12026b44  ldp        x24, x23, [sp, #0x50]
12026b48  ldp        x26, x25, [sp, #0x40]
12026b4c  ldp        x28, x27, [sp, #0x30]
12026b50  ldp        x29, x30, [sp, #0x20]
12026b54  add        sp, sp, #0x80
12026b58  ret        
12026b5c  mov        x8, x0
12026b60  mov        w19, w2
12026b64  mov        w0, wzr
12026b68  cmp        w2, #0x10
12026b6c  b.lt       #0x12026b2c
12026b70  and        w9, w19, #7
12026b74  cbnz       w9, #0x12026b2c
12026b78  add        x21, x8, #8
12026b7c  mov        x20, x1
12026b80  add        x2, sp, #0x10
12026b84  mov        x0, x1
12026b88  mov        x1, x21
12026b8c  mov        x23, x4
12026b90  mov        x22, x3
12026b94  bl         #0x1204d480
12026b98  ldrb       w8, [sp, #0x10]
12026b9c  mov        w0, wzr
12026ba0  and        w9, w8, #7
12026ba4  mvn        w8, w9
12026ba8  add        w8, w8, w19
12026bac  subs       w10, w8, #9
12026bb0  b.lt       #0x12026b2c
12026bb4  ldr        w8, [x23]
12026bb8  cmp        w8, w10
12026bbc  b.lt       #0x12026b2c
12026bc0  add        x8, sp, #8
12026bc4  add        x28, x20, #8
12026bc8  add        w9, w9, #1
12026bcc  movz       w27, #0x1
12026bd0  movz       w25, #0x8
12026bd4  str        w10, [x23]
12026bd8  str        xzr, [sp, #8]
12026bdc  b          #0x12026bf4
12026be0  add        w9, w9, #1
12026be4  add        w27, w27, #1
12026be8  mov        x26, x28
12026bec  cmp        w27, #3
12026bf0  b.ge       #0x12026cf4
12026bf4  cmp        w9, #8
12026bf8  b.lt       #0x12026be0
12026bfc  cmp        w25, w19
12026c00  csel       w8, w25, w19, gt
12026c04  subs       w8, w8, w25
12026c08  b.eq       #0x12026b28
12026c0c  ldrb       w9, [x20, #8]
12026c10  cmp        w8, #1
12026c14  ldrb       w10, [sp, #0x10]
12026c18  eor        w9, w10, w9
12026c1c  strb       w9, [sp, #0x10]
12026c20  b.eq       #0x12026b28
12026c24  ldrb       w9, [x28, #1]
12026c28  cmp        w8, #2
12026c2c  ldrb       w10, [sp, #0x11]
12026c30  eor        w9, w10, w9
12026c34  strb       w9, [sp, #0x11]
12026c38  b.eq       #0x12026b28
12026c3c  ldrb       w9, [x28, #2]
12026c40  cmp        w8, #3
12026c44  ldrb       w10, [sp, #0x12]
12026c48  eor        w9, w10, w9
12026c4c  strb       w9, [sp, #0x12]
12026c50  b.eq       #0x12026b28
12026c54  ldrb       w9, [x28, #3]
12026c58  cmp        w8, #4
12026c5c  ldrb       w10, [sp, #0x13]
12026c60  eor        w9, w10, w9
12026c64  strb       w9, [sp, #0x13]
12026c68  b.eq       #0x12026b28
12026c6c  ldrb       w9, [x28, #4]
12026c70  cmp        w8, #5
12026c74  ldrb       w10, [sp, #0x14]
12026c78  eor        w9, w10, w9
12026c7c  strb       w9, [sp, #0x14]
12026c80  b.eq       #0x12026b28
12026c84  ldrb       w9, [x28, #5]
12026c88  cmp        w8, #6
12026c8c  ldrb       w10, [sp, #0x15]
12026c90  eor        w9, w10, w9
12026c94  strb       w9, [sp, #0x15]
12026c98  b.eq       #0x12026b28
12026c9c  ldrb       w9, [x28, #6]
12026ca0  cmp        w8, #7
12026ca4  ldrb       w10, [sp, #0x16]
12026ca8  eor        w9, w10, w9
12026cac  strb       w9, [sp, #0x16]
12026cb0  b.eq       #0x12026b28
12026cb4  ldrb       w8, [x28, #7]
12026cb8  add        x0, sp, #0x10
12026cbc  ldrb       w9, [sp, #0x17]
12026cc0  add        x2, sp, #0x10
12026cc4  mov        x1, x21
12026cc8  eor        w8, w9, w8
12026ccc  strb       w8, [sp, #0x17]
12026cd0  bl         #0x1204d480
12026cd4  add        x26, x28, #8
12026cd8  mov        w9, wzr
12026cdc  add        w25, w25, #8
12026ce0  mov        x8, x20
12026ce4  mov        x20, x28
12026ce8  mov        x28, x26
12026cec  cmp        w27, #3
12026cf0  b.lt       #0x12026bf4
12026cf4  ldr        w23, [x23]
12026cf8  cbz        w23, #0x12026e2c
12026cfc  add        x27, sp, #0x10
12026d00  b          #0x12026d28
12026d04  sxtw       x10, w9
12026d08  sub        w23, w23, #1
12026d0c  ldrb       w11, [x27, x10]
12026d10  ldrb       w12, [x8, x10]
12026d14  add        w10, w9, #1
12026d18  mov        w9, w10
12026d1c  eor        w11, w12, w11
12026d20  strb       w11, [x22], #1
12026d24  cbz        w23, #0x12026e30
12026d28  cmp        w9, #8
12026d2c  b.lt       #0x12026d04
12026d30  cmp        w25, w19
12026d34  csel       w8, w25, w19, gt
12026d38  subs       w8, w8, w25
12026d3c  b.eq       #0x12026b28
12026d40  ldrb       w9, [x20, #8]
12026d44  cmp        w8, #1
12026d48  ldrb       w10, [sp, #0x10]
12026d4c  eor        w9, w10, w9
12026d50  strb       w9, [sp, #0x10]
12026d54  b.eq       #0x12026b28
12026d58  ldrb       w9, [x26, #1]
12026d5c  cmp        w8, #2
12026d60  ldrb       w10, [sp, #0x11]
12026d64  eor        w9, w10, w9
12026d68  strb       w9, [sp, #0x11]
12026d6c  b.eq       #0x12026b28
12026d70  ldrb       w9, [x26, #2]
12026d74  cmp        w8, #3
12026d78  ldrb       w10, [sp, #0x12]
12026d7c  eor        w9, w10, w9
12026d80  strb       w9, [sp, #0x12]
12026d84  b.eq       #0x12026b28
12026d88  ldrb       w9, [x26, #3]
12026d8c  cmp        w8, #4
12026d90  ldrb       w10, [sp, #0x13]
12026d94  eor        w9, w10, w9
12026d98  strb       w9, [sp, #0x13]
12026d9c  b.eq       #0x12026b28
12026da0  ldrb       w9, [x26, #4]
12026da4  cmp        w8, #5
12026da8  ldrb       w10, [sp, #0x14]
12026dac  eor        w9, w10, w9
12026db0  strb       w9, [sp, #0x14]
12026db4  b.eq       #0x12026b28
12026db8  ldrb       w9, [x26, #5]
12026dbc  cmp        w8, #6
12026dc0  ldrb       w10, [sp, #0x15]
12026dc4  eor        w9, w10, w9
12026dc8  strb       w9, [sp, #0x15]
12026dcc  b.eq       #0x12026b28
12026dd0  ldrb       w9, [x26, #6]
12026dd4  cmp        w8, #7
12026dd8  ldrb       w10, [sp, #0x16]
12026ddc  eor        w9, w10, w9
12026de0  strb       w9, [sp, #0x16]
12026de4  b.eq       #0x12026b28
12026de8  ldrb       w8, [x26, #7]
12026dec  add        x0, sp, #0x10
12026df0  ldrb       w9, [sp, #0x17]
12026df4  add        x2, sp, #0x10
12026df8  mov        x1, x21
12026dfc  eor        w8, w9, w8
12026e00  strb       w8, [sp, #0x17]
12026e04  bl         #0x1204d480
12026e08  add        x11, x26, #8
12026e0c  mov        w10, wzr
12026e10  mov        w9, wzr
12026e14  mov        x8, x20
12026e18  add        w25, w25, #8
12026e1c  mov        x20, x26
12026e20  mov        x26, x11
12026e24  cbnz       w23, #0x12026d28
12026e28  b          #0x12026e30
12026e2c  mov        w10, w9
12026e30  movz       w22, #0x1
12026e34  add        x23, sp, #0x10
12026e38  b          #0x12026e64
12026e3c  sxtw       x9, w10
12026e40  ldrb       w11, [x23, x9]
12026e44  ldrb       w9, [x8, x9]
12026e48  cmp        w11, w9
12026e4c  b.ne       #0x12026b28
12026e50  add        w10, w10, #1
12026e54  add        w22, w22, #1
12026e58  movz       w0, #0x1
12026e5c  cmp        w22, #8
12026e60  b.ge       #0x12026b2c
12026e64  cmp        w10, #8
12026e68  b.lt       #0x12026e3c
12026e6c  cmp        w25, w19
12026e70  csel       w8, w25, w19, gt
12026e74  subs       w8, w8, w25
12026e78  b.eq       #0x12026b28
12026e7c  ldrb       w9, [x20, #8]
12026e80  cmp        w8, #1
12026e84  ldrb       w10, [sp, #0x10]
12026e88  eor        w9, w10, w9
12026e8c  strb       w9, [sp, #0x10]
12026e90  b.eq       #0x12026b28
12026e94  ldrb       w9, [x26, #1]
12026e98  cmp        w8, #2
12026e9c  ldrb       w10, [sp, #0x11]
12026ea0  eor        w9, w10, w9
12026ea4  strb       w9, [sp, #0x11]
12026ea8  b.eq       #0x12026b28
12026eac  ldrb       w9, [x26, #2]
12026eb0  cmp        w8, #3
12026eb4  ldrb       w10, [sp, #0x12]
12026eb8  eor        w9, w10, w9
12026ebc  strb       w9, [sp, #0x12]
12026ec0  b.eq       #0x12026b28
12026ec4  ldrb       w9, [x26, #3]
12026ec8  cmp        w8, #4
12026ecc  ldrb       w10, [sp, #0x13]
12026ed0  eor        w9, w10, w9
12026ed4  strb       w9, [sp, #0x13]
12026ed8  b.eq       #0x12026b28
12026edc  ldrb       w9, [x26, #4]
12026ee0  cmp        w8, #5
12026ee4  ldrb       w10, [sp, #0x14]
12026ee8  eor        w9, w10, w9
12026eec  strb       w9, [sp, #0x14]
12026ef0  b.eq       #0x12026b28
12026ef4  ldrb       w9, [x26, #5]
12026ef8  cmp        w8, #6
12026efc  ldrb       w10, [sp, #0x15]
12026f00  eor        w9, w10, w9
12026f04  strb       w9, [sp, #0x15]
12026f08  b.eq       #0x12026b28
12026f0c  ldrb       w9, [x26, #6]
12026f10  cmp        w8, #7
12026f14  ldrb       w10, [sp, #0x16]
12026f18  eor        w9, w10, w9
12026f1c  strb       w9, [sp, #0x16]
12026f20  b.eq       #0x12026b28
12026f24  ldrb       w8, [x26, #7]
12026f28  add        x0, sp, #0x10
12026f2c  ldrb       w9, [sp, #0x17]
12026f30  add        x2, sp, #0x10
12026f34  mov        x1, x21
12026f38  eor        w8, w9, w8
12026f3c  strb       w8, [sp, #0x17]
12026f40  bl         #0x1204d480
12026f44  add        x9, x26, #8
12026f48  mov        w10, wzr
12026f4c  mov        x8, x20
12026f50  mov        x20, x26
12026f54  add        w25, w25, #8
12026f58  mov        x26, x9
12026f5c  b          #0x12026e58
12026f60  bl         #0x1204d080
12026f64  ldrb       w8, [x0, #0x18]
12026f68  cmp        w8, #1
12026f6c  b.hi       #0x12026f9c
12026f70  add        w8, w1, #0xa
12026f74  add        w9, w1, #0x11
12026f78  cmp        w8, #0
12026f7c  movz       w10, #0x8
12026f80  csel       w9, w9, w8, lt
12026f84  and        w9, w9, #0xfffffff8
12026f88  subs       w9, w8, w9
12026f8c  sub        w9, w10, w9
12026f90  csel       w9, wzr, w9, eq
12026f94  add        w0, w9, w8
12026f98  ret        

================================================================================
## _ZN7QSCrypt6SetKeyEPhi
## base+0x27028
================================================================================
12027028  cmp        w2, #0x10
1202702c  b.ne       #0x12027038
12027030  ldr        q0, [x1]
12027034  stur       q0, [x0, #8]
12027038  ret        
1202703c  strb       w1, [x0, #0x18]
12027040  strb       w2, [x0, #0x19]
12027044  ret        

================================================================================
## _ZN7QSCrypt8SetArithEhh
## base+0x2703c
================================================================================
1202703c  strb       w1, [x0, #0x18]
12027040  strb       w2, [x0, #0x19]
12027044  ret        
12027048  str        xzr, [x0]
1202704c  str        wzr, [x0, #8]
12027050  ret        

================================================================================
## _ZN7QSCryptC2EPhhh
## base+0x26668
================================================================================
12026668  adrp       x8, #0x12051000
1202666c  ldr        x8, [x8, #0xeb8]
12026670  strb       w2, [x0, #0x18]
12026674  strb       w3, [x0, #0x19]
12026678  add        x8, x8, #0x10
1202667c  str        x8, [x0]
12026680  ldr        q0, [x1]
12026684  stur       q0, [x0, #8]
12026688  ret        
1202668c  sub        sp, sp, #0x90
12026690  stp        x29, x30, [sp, #0x30]
12026694  add        x29, sp, #0x30
12026698  stp        x28, x27, [sp, #0x40]
1202669c  stp        x26, x25, [sp, #0x50]
120266a0  stp        x24, x23, [sp, #0x60]
120266a4  stp        x22, x21, [sp, #0x70]
120266a8  stp        x20, x19, [sp, #0x80]
120266ac  mrs        x9, tpidr_el0
120266b0  ldr        x8, [x9, #0x28]
120266b4  stur       x8, [x29, #-8]
120266b8  ldrb       w8, [x0, #0x18]
120266bc  cbnz       w8, #0x12026ac0
120266c0  add        w8, w2, #0xa
120266c4  stp        x1, x9, [sp, #8]
120266c8  add        w9, w2, #0x11
120266cc  cmp        w8, #0
120266d0  csel       w9, w9, w8, lt
120266d4  mov        x19, x4
120266d8  and        w9, w9, #0xfffffff8
120266dc  mov        x23, x3
120266e0  subs       w8, w8, w9
120266e4  movz       w9, #0x8
120266e8  sub        w8, w9, w8
120266ec  mov        x20, x0
120266f0  mov        w21, w2
120266f4  csel       w22, wzr, w8, eq
120266f8  bl         #0x1204d490
120266fc  movz       w27, #0x3
12026700  movz       w28, #0xfffe
12026704  movk       w27, #0x8001, lsl #16
12026708  smull      x8, w0, w27
1202670c  lsr        x8, x8, #0x20
12026710  add        w8, w8, w0
12026714  lsr        w9, w8, #0xf
12026718  add        w8, w9, w8, lsr #31
1202671c  msub       w8, w8, w28, w0
12026720  and        w8, w8, #0xf8
12026724  orr        w8, w8, w22
12026728  sturb      w8, [x29, #-0x10]
1202672c  cbz        w22, #0x12026770
12026730  sub        x8, x29, #0x10
12026734  mov        x24, xzr
12026738  orr        x25, x8, #1
1202673c  bl         #0x1204d490
12026740  smull      x8, w0, w27
12026744  lsr        x8, x8, #0x20
12026748  add        w8, w8, w0
1202674c  lsr        w9, w8, #0xf
12026750  add        w8, w9, w8, lsr #31
12026754  msub       w8, w8, w28, w0
12026758  strb       w8, [x25, x24]
1202675c  add        x24, x24, #1
12026760  cmp        w22, w24
12026764  b.ne       #0x1202673c
12026768  add        w26, w24, #1
1202676c  b          #0x12026774
12026770  movz       w26, #0x1
12026774  add        x25, sp, #0x18
12026778  add        x20, x20, #8
1202677c  movz       w22, #0x1
12026780  str        xzr, [sp, #0x18]
12026784  str        wzr, [x19]
12026788  b          #0x12026858
1202678c  ldr        d0, [x25]
12026790  sub        x0, x29, #0x10
12026794  ldur       d1, [x29, #-0x10]
12026798  mov        x1, x20
1202679c  mov        x2, x23
120267a0  eor        v0.8b, v1.8b, v0.8b
120267a4  stur       d0, [x29, #-0x10]
120267a8  bl         #0x1204d470
120267ac  ldrb       w8, [sp, #0x18]
120267b0  add        x24, x23, #8
120267b4  ldrb       w9, [x23]
120267b8  mov        w26, wzr
120267bc  mov        x25, x23
120267c0  eor        w8, w9, w8
120267c4  ldrb       w9, [x23, #1]
120267c8  strb       w8, [x23]
120267cc  ldrb       w8, [sp, #0x19]
120267d0  eor        w8, w9, w8
120267d4  ldrb       w9, [x23, #2]
120267d8  strb       w8, [x23, #1]
120267dc  ldrb       w8, [sp, #0x1a]
120267e0  eor        w8, w9, w8
120267e4  ldrb       w9, [x23, #3]
120267e8  strb       w8, [x23, #2]
120267ec  ldrb       w8, [sp, #0x1b]
120267f0  eor        w8, w9, w8
120267f4  ldrb       w9, [x23, #4]
120267f8  strb       w8, [x23, #3]
120267fc  ldrb       w8, [sp, #0x1c]
12026800  eor        w8, w9, w8
12026804  ldrb       w9, [x23, #5]
12026808  strb       w8, [x23, #4]
1202680c  ldrb       w8, [sp, #0x1d]
12026810  eor        w8, w9, w8
12026814  ldrb       w9, [x23, #6]
12026818  strb       w8, [x23, #5]
1202681c  ldrb       w8, [sp, #0x1e]
12026820  eor        w8, w9, w8
12026824  ldrb       w9, [x23, #7]
12026828  strb       w8, [x23, #6]
1202682c  ldrb       w8, [sp, #0x1f]
12026830  eor        w8, w9, w8
12026834  strb       w8, [x23, #7]
12026838  mov        x23, x24
1202683c  ldr        w8, [x19]
12026840  ldur       x9, [x29, #-0x10]
12026844  add        w8, w8, #8
12026848  str        x9, [sp, #0x18]
1202684c  str        w8, [x19]
12026850  cmp        w22, #3
12026854  b.ge       #0x120268a0
12026858  cmp        w26, #7
1202685c  b.gt       #0x12026890
12026860  bl         #0x1204d490
12026864  smull      x8, w0, w27
12026868  sub        x10, x29, #0x10
1202686c  add        w22, w22, #1
12026870  lsr        x8, x8, #0x20
12026874  add        w8, w8, w0
12026878  lsr        w9, w8, #0xf
1202687c  add        w8, w9, w8, lsr #31
12026880  add        w9, w26, #1
12026884  msub       w8, w8, w28, w0
12026888  strb       w8, [x10, w26, sxtw]
1202688c  mov        w26, w9
12026890  cmp        w26, #8
12026894  b.eq       #0x1202678c
12026898  mov        x24, x23
1202689c  b          #0x12026850
120268a0  cbz        w21, #0x120269ac
120268a4  sub        x22, x29, #0x10
120268a8  ldr        x27, [sp, #8]
120268ac  b          #0x1202697c
120268b0  ldr        d0, [x25]
120268b4  sub        x0, x29, #0x10
120268b8  ldur       d1, [x29, #-0x10]
120268bc  mov        x1, x20
120268c0  mov        x2, x24
120268c4  eor        v0.8b, v1.8b, v0.8b
120268c8  stur       d0, [x29, #-0x10]
120268cc  bl         #0x1204d470
120268d0  ldrb       w8, [sp, #0x18]
120268d4  mov        w26, wzr
120268d8  ldrb       w9, [x24]
120268dc  add        x23, x24, #8
120268e0  mov        x25, x24
120268e4  eor        w8, w9, w8
120268e8  ldrb       w9, [x24, #1]
120268ec  strb       w8, [x24]
120268f0  ldrb       w8, [sp, #0x19]
120268f4  eor        w8, w9, w8
120268f8  ldrb       w9, [x24, #2]
120268fc  strb       w8, [x24, #1]
12026900  ldrb       w8, [sp, #0x1a]
12026904  eor        w8, w9, w8
12026908  ldrb       w9, [x24, #3]
1202690c  strb       w8, [x24, #2]
12026910  ldrb       w8, [sp, #0x1b]
12026914  eor        w8, w9, w8
12026918  ldrb       w9, [x24, #4]
1202691c  strb       w8, [x24, #3]
12026920  ldrb       w8, [sp, #0x1c]
12026924  eor        w8, w9, w8
12026928  ldrb       w9, [x24, #5]
1202692c  strb       w8, [x24, #4]
12026930  ldrb       w8, [sp, #0x1d]
12026934  eor        w8, w9, w8
12026938  ldrb       w9, [x24, #6]
1202693c  strb       w8, [x24, #5]
12026940  ldrb       w8, [sp, #0x1e]
12026944  eor        w8, w9, w8
12026948  ldrb       w9, [x24, #7]
1202694c  strb       w8, [x24, #6]
12026950  ldrb       w8, [sp, #0x1f]
12026954  eor        w8, w9, w8
12026958  strb       w8, [x24, #7]
1202695c  ldr        w8, [x19]
12026960  ldur       x9, [x29, #-0x10]
12026964  add        w8, w8, #8
12026968  str        x9, [sp, #0x18]
1202696c  str        w8, [x19]
12026970  mov        x8, x24
12026974  mov        x24, x23
12026978  cbz        w21, #0x120269b4
1202697c  cmp        w26, #7
12026980  b.gt       #0x12026998
12026984  ldrb       w8, [x27], #1
12026988  add        w9, w26, #1
1202698c  sub        w21, w21, #1
12026990  strb       w8, [x22, w26, sxtw]
12026994  mov        w26, w9
12026998  cmp        w26, #8
1202699c  b.eq       #0x120268b0
120269a0  mov        x23, x24
120269a4  mov        x24, x25
120269a8  b          #0x12026970
120269ac  mov        x23, x24
120269b0  mov        x8, x25
120269b4  movz       w21, #0x1
120269b8  sub        x22, x29, #0x10
120269bc  b          #0x120269c8
120269c0  cmp        w21, #8
120269c4  b.ge       #0x12026abc
120269c8  cmp        w26, #7
120269cc  b.le       #0x120269dc
120269d0  cmp        w26, #8
120269d4  b.ne       #0x120269c0
120269d8  b          #0x120269f4
120269dc  add        w9, w26, #1
120269e0  strb       wzr, [x22, w26, sxtw]
120269e4  add        w21, w21, #1
120269e8  mov        w26, w9
120269ec  cmp        w26, #8
120269f0  b.ne       #0x120269c0
120269f4  ldr        d0, [x8]
120269f8  sub        x0, x29, #0x10
120269fc  ldur       d1, [x29, #-0x10]
12026a00  mov        x1, x20
12026a04  mov        x2, x23
12026a08  eor        v0.8b, v1.8b, v0.8b
12026a0c  stur       d0, [x29, #-0x10]
12026a10  bl         #0x1204d470
12026a14  ldrb       w8, [sp, #0x18]
12026a18  mov        w26, wzr
12026a1c  ldrb       w9, [x23]
12026a20  eor        w8, w9, w8
12026a24  ldrb       w9, [x23, #1]
12026a28  strb       w8, [x23]
12026a2c  ldrb       w8, [sp, #0x19]
12026a30  eor        w8, w9, w8
12026a34  ldrb       w9, [x23, #2]
12026a38  strb       w8, [x23, #1]
12026a3c  ldrb       w8, [sp, #0x1a]
12026a40  eor        w8, w9, w8
12026a44  ldrb       w9, [x23, #3]
12026a48  strb       w8, [x23, #2]
12026a4c  ldrb       w8, [sp, #0x1b]
12026a50  eor        w8, w9, w8
12026a54  ldrb       w9, [x23, #4]
12026a58  strb       w8, [x23, #3]
12026a5c  ldrb       w8, [sp, #0x1c]
12026a60  eor        w8, w9, w8
12026a64  ldrb       w9, [x23, #5]
12026a68  strb       w8, [x23, #4]
12026a6c  ldrb       w8, [sp, #0x1d]
12026a70  eor        w8, w9, w8
12026a74  ldrb       w9, [x23, #6]
12026a78  strb       w8, [x23, #5]
12026a7c  ldrb       w8, [sp, #0x1e]
12026a80  eor        w8, w9, w8
12026a84  ldrb       w9, [x23, #7]
12026a88  strb       w8, [x23, #6]
12026a8c  ldrb       w8, [sp, #0x1f]
12026a90  eor        w8, w9, w8
12026a94  add        x9, x23, #8
12026a98  strb       w8, [x23, #7]
12026a9c  ldr        w8, [x19]
12026aa0  ldur       x10, [x29, #-0x10]
12026aa4  add        w11, w8, #8
12026aa8  mov        x8, x23
12026aac  mov        x23, x9
12026ab0  str        x10, [sp, #0x18]
12026ab4  str        w11, [x19]
12026ab8  b          #0x120269c0
12026abc  ldr        x9, [sp, #0x10]
12026ac0  ldr        x8, [x9, #0x28]
12026ac4  ldur       x9, [x29, #-8]
12026ac8  cmp        x8, x9
12026acc  b.ne       #0x12026af0
12026ad0  ldp        x20, x19, [sp, #0x80]
12026ad4  ldp        x22, x21, [sp, #0x70]
12026ad8  ldp        x24, x23, [sp, #0x60]
12026adc  ldp        x26, x25, [sp, #0x50]
12026ae0  ldp        x28, x27, [sp, #0x40]
12026ae4  ldp        x29, x30, [sp, #0x30]
12026ae8  add        sp, sp, #0x90
12026aec  ret        

================================================================================
## _ZN7QSCryptC2Ev
## base+0x26644
================================================================================
12026644  adrp       x9, #0x12051000
12026648  movz       w8, #0x1
1202664c  ldr        x9, [x9, #0xeb8]
12026650  strh       w8, [x0, #0x18]
12026654  add        x8, x9, #0x10
12026658  str        x8, [x0]
1202665c  ret        
12026660  ret        

================================================================================
## _ZN7QSCrypt15FindEncryptSizeEi
## base+0x26f64
================================================================================
12026f64  ldrb       w8, [x0, #0x18]
12026f68  cmp        w8, #1
12026f6c  b.hi       #0x12026f9c
12026f70  add        w8, w1, #0xa
12026f74  add        w9, w1, #0x11
12026f78  cmp        w8, #0
12026f7c  movz       w10, #0x8
12026f80  csel       w9, w9, w8, lt
12026f84  and        w9, w9, #0xfffffff8
12026f88  subs       w9, w8, w9
12026f8c  sub        w9, w10, w9
12026f90  csel       w9, wzr, w9, eq
12026f94  add        w0, w9, w8
12026f98  ret        
12026f9c  mov        w0, wzr
12026fa0  ret        

================================================================================
## _ZN7QSCrypt7GetLongERlPh
## base+0x26418
================================================================================
12026418  ldrb       w8, [x1, #3]
1202641c  strb       w8, [x0]
12026420  ldrb       w8, [x1, #2]
12026424  strb       w8, [x0, #1]
12026428  ldrb       w8, [x1, #1]
1202642c  strb       w8, [x0, #2]
12026430  ldrb       w8, [x1]
12026434  strb       w8, [x0, #3]
12026438  ret        
1202643c  ldrb       w8, [x1, #3]
12026440  strb       w8, [x0]
12026444  ldrb       w8, [x1, #2]
12026448  strb       w8, [x0, #1]
1202644c  ldrb       w8, [x1, #1]
12026450  strb       w8, [x0, #2]
12026454  ldrb       w8, [x1]
12026458  strb       w8, [x0, #3]
1202645c  ret        

================================================================================
## _ZN7QSCrypt8GetShortERsPh
## base+0x26404
================================================================================
12026404  ldrb       w8, [x1, #1]
12026408  strb       w8, [x0]
1202640c  ldrb       w8, [x1]
12026410  strb       w8, [x0, #1]
12026414  ret        
12026418  ldrb       w8, [x1, #3]
1202641c  strb       w8, [x0]
12026420  ldrb       w8, [x1, #2]
12026424  strb       w8, [x0, #1]
12026428  ldrb       w8, [x1, #1]
1202642c  strb       w8, [x0, #2]
12026430  ldrb       w8, [x1]
12026434  strb       w8, [x0, #3]
12026438  ret        

================================================================================
## NOT FOUND: _ZN7QSCrypt8SetLongEPhl

================================================================================
## _ZN7QSCrypt8SetShortEPhs
## base+0x263e8
================================================================================
120263e8  rev        w8, w1
120263ec  lsr        w8, w8, #0x10
120263f0  strh       w8, [x0]
120263f4  ret        
120263f8  rev        w8, w1
120263fc  str        w8, [x0]
12026400  ret        

================================================================================
## _ZN7QSCrypt7Md5HashEPhPKhi
## base+0x26fa4
================================================================================
12026fa4  sub        sp, sp, #0xa0
12026fa8  stp        x29, x30, [sp, #0x80]
12026fac  add        x29, sp, #0x80
12026fb0  stp        x20, x19, [sp, #0x90]
12026fb4  mrs        x20, tpidr_el0
12026fb8  adrp       x9, #0x12017000
12026fbc  ldr        x8, [x20, #0x28]
12026fc0  mov        x19, x0
12026fc4  movi       v0.2d, #0000000000000000
12026fc8  sxtw       x2, w2
12026fcc  ldr        q1, [x9, #0x1f0]
12026fd0  mov        x0, sp
12026fd4  stur       x8, [x29, #-8]
12026fd8  adrp       x8, #0x12017000
12026fdc  str        xzr, [sp, #0x70]
12026fe0  stp        q0, q0, [sp, #0x50]
12026fe4  stp        q0, q0, [sp, #0x30]
12026fe8  ldr        q0, [x8, #0x1e0]
12026fec  stp        xzr, xzr, [sp, #0x20]
12026ff0  stp        q1, q0, [sp]
12026ff4  bl         #0x1204d440
12026ff8  mov        x1, sp
12026ffc  mov        x0, x19
12027000  bl         #0x1204d450
12027004  ldr        x8, [x20, #0x28]
12027008  ldur       x9, [x29, #-8]
1202700c  cmp        x8, x9
12027010  b.ne       #0x12027024
12027014  ldp        x20, x19, [sp, #0x90]
12027018  ldp        x29, x30, [sp, #0x80]
1202701c  add        sp, sp, #0xa0
12027020  ret        
12027024  bl         #0x1204d080
12027028  cmp        w2, #0x10
1202702c  b.ne       #0x12027038
12027030  ldr        q0, [x1]
12027034  stur       q0, [x0, #8]
12027038  ret        

================================================================================
## _ZN7QSCrypt13TeaEncryptECBEPKhS1_Ph
## base+0x26460
================================================================================
12026460  ldp        w16, w17, [x1]
12026464  ldp        w1, w15, [x1, #8]
12026468  movz       w3, #0x79b9
1202646c  mov        x9, xzr
12026470  movz       w10, #0x10
12026474  ldrb       w8, [x0, #3]
12026478  ldrb       w11, [x0, #2]
1202647c  rev        w16, w16
12026480  ldrb       w13, [x0, #1]
12026484  rev        w15, w15
12026488  ldrb       w14, [x0]
1202648c  rev        w17, w17
12026490  ldrb       w12, [x0, #7]
12026494  rev        w1, w1
12026498  ldrb       w4, [x0, #6]
1202649c  movk       w3, #0x9e37, lsl #16
120264a0  ldrb       w5, [x0, #5]
120264a4  ldrb       w0, [x0, #4]
120264a8  and        w5, w5, #0xff
120264ac  and        w4, w4, #0xff
120264b0  lsl        w0, w0, #0x18
120264b4  and        w13, w13, #0xff
120264b8  and        w11, w11, #0xff
120264bc  lsl        w14, w14, #0x18
120264c0  bfi        w0, w5, #0x10, #8
120264c4  add        x9, x3, w9, uxtw
120264c8  bfi        w0, w4, #8, #8
120264cc  bfi        w14, w13, #0x10, #8
120264d0  bfxil      w0, w12, #0, #8
120264d4  bfi        w14, w11, #8, #8
120264d8  add        w11, w0, w9
120264dc  bfxil      w14, w8, #0, #8
120264e0  add        w12, w16, w0, lsl #4
120264e4  add        w13, w17, w0, lsr #5
120264e8  eor        w11, w12, w11
120264ec  subs       w10, w10, #1
120264f0  eor        w8, w11, w13
120264f4  add        w8, w14, w8
120264f8  add        w12, w8, w9
120264fc  lsr        w11, w8, #8
12026500  add        w13, w1, w8, lsl #4
12026504  add        w14, w15, w8, lsr #5
12026508  eor        w12, w13, w12
1202650c  lsr        w13, w8, #0x10
12026510  eor        w12, w12, w14
12026514  lsr        w14, w8, #0x18
12026518  add        w12, w12, w0
1202651c  lsr        w4, w12, #8
12026520  lsr        w5, w12, #0x10
12026524  lsr        w0, w12, #0x18
12026528  b.ne       #0x120264a8
1202652c  strb       w14, [x2]
12026530  strb       w13, [x2, #1]
12026534  strb       w11, [x2, #2]
12026538  strb       w8, [x2, #3]
1202653c  strb       w0, [x2, #4]
12026540  strb       w5, [x2, #5]
12026544  strb       w4, [x2, #6]
12026548  strb       w12, [x2, #7]
1202654c  ret        
12026550  ldp        w12, w11, [x1, #8]
12026554  ldp        w13, w14, [x1]
12026558  movz       w9, #0x9b90
1202655c  movz       w16, #0x8647
12026560  movk       w9, #0xe377, lsl #16
12026564  ldrb       w10, [x0, #3]
12026568  ldrb       w3, [x0, #2]
1202656c  rev        w11, w11
12026570  ldrb       w4, [x0, #1]
12026574  rev        w12, w12
12026578  ldrb       w5, [x0]
1202657c  rev        w13, w13
12026580  ldrb       w8, [x0, #7]
12026584  rev        w14, w14
12026588  ldrb       w17, [x0, #6]
1202658c  movz       w15, #0x10
12026590  ldrb       w1, [x0, #5]
12026594  movk       w16, #0x61c8, lsl #16
12026598  ldrb       w0, [x0, #4]
1202659c  and        w4, w4, #0xff
120265a0  and        w3, w3, #0xff
120265a4  lsl        w5, w5, #0x18
120265a8  and        w1, w1, #0xff
120265ac  and        w17, w17, #0xff
120265b0  lsl        w0, w0, #0x18
120265b4  bfi        w5, w4, #0x10, #8
120265b8  subs       w15, w15, #1
120265bc  bfi        w5, w3, #8, #8
120265c0  bfi        w0, w1, #0x10, #8
120265c4  bfxil      w5, w10, #0, #8
120265c8  bfi        w0, w17, #8, #8
120265cc  add        w10, w9, w5
120265d0  bfxil      w0, w8, #0, #8
120265d4  add        w17, w12, w5, lsl #4
120265d8  add        w1, w11, w5, lsr #5
120265dc  eor        w10, w17, w10
120265e0  eor        w8, w10, w1
120265e4  sub        w8, w0, w8
120265e8  add        w10, w9, w8
120265ec  lsr        w1, w8, #0x10
120265f0  add        w17, w13, w8, lsl #4
120265f4  add        w0, w14, w8, lsr #5
120265f8  eor        w10, w17, w10
120265fc  lsr        w17, w8, #8
12026600  eor        w10, w10, w0
12026604  lsr        w0, w8, #0x18
12026608  sub        w10, w5, w10
1202660c  add        w9, w9, w16
12026610  lsr        w3, w10, #8
12026614  lsr        w4, w10, #0x10
12026618  lsr        w5, w10, #0x18
1202661c  b.ne       #0x1202659c
12026620  strb       w5, [x2]
12026624  strb       w4, [x2, #1]
12026628  strb       w3, [x2, #2]
1202662c  strb       w10, [x2, #3]
12026630  strb       w0, [x2, #4]
12026634  strb       w1, [x2, #5]
12026638  strb       w17, [x2, #6]
1202663c  strb       w8, [x2, #7]
12026640  ret        

================================================================================
## _ZN7QSCrypt13TeaDecryptECBEPKhS1_Ph
## base+0x26550
================================================================================
12026550  ldp        w12, w11, [x1, #8]
12026554  ldp        w13, w14, [x1]
12026558  movz       w9, #0x9b90
1202655c  movz       w16, #0x8647
12026560  movk       w9, #0xe377, lsl #16
12026564  ldrb       w10, [x0, #3]
12026568  ldrb       w3, [x0, #2]
1202656c  rev        w11, w11
12026570  ldrb       w4, [x0, #1]
12026574  rev        w12, w12
12026578  ldrb       w5, [x0]
1202657c  rev        w13, w13
12026580  ldrb       w8, [x0, #7]
12026584  rev        w14, w14
12026588  ldrb       w17, [x0, #6]
1202658c  movz       w15, #0x10
12026590  ldrb       w1, [x0, #5]
12026594  movk       w16, #0x61c8, lsl #16
12026598  ldrb       w0, [x0, #4]
1202659c  and        w4, w4, #0xff
120265a0  and        w3, w3, #0xff
120265a4  lsl        w5, w5, #0x18
120265a8  and        w1, w1, #0xff
120265ac  and        w17, w17, #0xff
120265b0  lsl        w0, w0, #0x18
120265b4  bfi        w5, w4, #0x10, #8
120265b8  subs       w15, w15, #1
120265bc  bfi        w5, w3, #8, #8
120265c0  bfi        w0, w1, #0x10, #8
120265c4  bfxil      w5, w10, #0, #8
120265c8  bfi        w0, w17, #8, #8
120265cc  add        w10, w9, w5
120265d0  bfxil      w0, w8, #0, #8
120265d4  add        w17, w12, w5, lsl #4
120265d8  add        w1, w11, w5, lsr #5
120265dc  eor        w10, w17, w10
120265e0  eor        w8, w10, w1
120265e4  sub        w8, w0, w8
120265e8  add        w10, w9, w8
120265ec  lsr        w1, w8, #0x10
120265f0  add        w17, w13, w8, lsl #4
120265f4  add        w0, w14, w8, lsr #5
120265f8  eor        w10, w17, w10
120265fc  lsr        w17, w8, #8
12026600  eor        w10, w10, w0
12026604  lsr        w0, w8, #0x18
12026608  sub        w10, w5, w10
1202660c  add        w9, w9, w16
12026610  lsr        w3, w10, #8
12026614  lsr        w4, w10, #0x10
12026618  lsr        w5, w10, #0x18
1202661c  b.ne       #0x1202659c
12026620  strb       w5, [x2]
12026624  strb       w4, [x2, #1]
12026628  strb       w3, [x2, #2]
1202662c  strb       w10, [x2, #3]
12026630  strb       w0, [x2, #4]
12026634  strb       w1, [x2, #5]
12026638  strb       w17, [x2, #6]
1202663c  strb       w8, [x2, #7]
12026640  ret        
12026644  adrp       x9, #0x12051000
12026648  movz       w8, #0x1
1202664c  ldr        x9, [x9, #0xeb8]
12026650  strh       w8, [x0, #0x18]
12026654  add        x8, x9, #0x10
12026658  str        x8, [x0]
1202665c  ret        

================================================================================
## _ZN18CNativeConfigStore10loadConfigEP7_JNIEnvP8_jobjecth
## base+0x22158
================================================================================
12022158  sub        sp, sp, #0x180
1202215c  stp        x29, x30, [sp, #0x120]
12022160  add        x29, sp, #0x120
12022164  stp        x28, x27, [sp, #0x130]
12022168  stp        x26, x25, [sp, #0x140]
1202216c  stp        x24, x23, [sp, #0x150]
12022170  stp        x22, x21, [sp, #0x160]
12022174  stp        x20, x19, [sp, #0x170]
12022178  adrp       x9, #0x12051000
1202217c  stp        x1, x2, [sp, #0x50]
12022180  mrs        x21, tpidr_el0
12022184  mov        w22, w3
12022188  ldr        x8, [x21, #0x28]
1202218c  mov        x19, x0
12022190  ldr        x9, [x9, #0xe90]
12022194  stur       x8, [x29, #-0x10]
12022198  ldrb       w8, [x9]
1202219c  cbz        w8, #0x120221bc
120221a0  adrp       x1, #0x12015000
120221a4  adrp       x2, #0x12015000
120221a8  and        w3, w22, #0xff
120221ac  add        x1, x1, #0x34a
120221b0  add        x2, x2, #0x21a
120221b4  movz       w0, #0x4
120221b8  bl         #0x1204d050
120221bc  adrp       x10, #0x12051000
120221c0  ands       w8, w22, #0xff
120221c4  cset       w9, ne
120221c8  ldr        x10, [x10, #0xe90]
120221cc  strb       w9, [x10]
120221d0  cbz        w8, #0x120221ec
120221d4  adrp       x1, #0x12015000
120221d8  adrp       x2, #0x12015000
120221dc  add        x1, x1, #0x34a
120221e0  add        x2, x2, #0xd99
120221e4  movz       w0, #0x4
120221e8  bl         #0x1204d050
120221ec  ldrb       w8, [x19, #8]
120221f0  stp        xzr, xzr, [x29, #-0x60]
120221f4  ldp        x9, x10, [x19, #0x10]
120221f8  stur       xzr, [x29, #-0x50]
120221fc  lsr        x11, x8, #1
12022200  tst        w8, #1
12022204  add        x8, x19, #9
12022208  csel       x22, x11, x9, eq
1202220c  csel       x23, x8, x10, eq
12022210  str        x8, [sp, #0x48]
12022214  add        x8, x22, #0x16
12022218  cmn        x8, #0x10
1202221c  b.hs       #0x12022974
12022220  cmp        x8, #0x17
12022224  b.hs       #0x12022240
12022228  sub        x9, x29, #0x60
1202222c  lsl        w8, w22, #1
12022230  orr        x24, x9, #1
12022234  sturb      w8, [x29, #-0x60]
12022238  cbnz       x22, #0x12022260
1202223c  b          #0x12022270
12022240  add        x8, x22, #0x26
12022244  and        x25, x8, #0xfffffffffffffff0
12022248  mov        x0, x25
1202224c  bl         #0x1204d060
12022250  orr        x8, x25, #1
12022254  mov        x24, x0
12022258  stp        x22, x0, [x29, #-0x58]
1202225c  stur       x8, [x29, #-0x60]
12022260  mov        x0, x24
12022264  mov        x1, x23
12022268  mov        x2, x22
1202226c  bl         #0x1204d120
12022270  adrp       x1, #0x12015000
12022274  sub        x0, x29, #0x60
12022278  add        x1, x1, #0x65a
1202227c  movz       w2, #0x16
12022280  strb       wzr, [x24, x22]
12022284  sub        x20, x29, #0x60
12022288  bl         #0x1204d130
1202228c  ldurb      w8, [x29, #-0x60]
12022290  orr        x10, x20, #1
12022294  ldur       x9, [x29, #-0x50]
12022298  adrp       x1, #0x12015000
1202229c  add        x1, x1, #0xc4c
120222a0  tst        w8, #1
120222a4  csel       x0, x10, x9, eq
120222a8  bl         #0x1204d140
120222ac  str        x21, [sp, #0x40]
120222b0  cbz        x0, #0x120222c4
120222b4  bl         #0x1204d150
120222b8  movn       w8, #0x1
120222bc  str        w8, [sp, #0x3c]
120222c0  b          #0x120222c8
120222c4  str        wzr, [sp, #0x3c]
120222c8  sub        x8, x29, #0x78
120222cc  add        x9, x19, #0x20
120222d0  orr        x20, x8, #1
120222d4  add        x8, sp, #0x88
120222d8  orr        x8, x8, #1
120222dc  mov        w23, wzr
120222e0  add        x24, x19, #0x28
120222e4  add        x21, x19, #0x30
120222e8  add        x26, x19, #0x40
120222ec  stp        x9, x8, [sp, #0x28]
120222f0  add        x8, sp, #0x60
120222f4  orr        x9, x8, #1
120222f8  sub        x8, x29, #0x48
120222fc  orr        x8, x8, #1
12022300  stp        x8, x9, [sp, #0x18]
12022304  ldrb       w8, [x19, #0x58]
12022308  cbz        w8, #0x12022898
1202230c  ldr        x1, [x19, #0x30]
12022310  mov        x0, x24
12022314  bl         #0x1204d100
12022318  ldp        x0, x1, [sp, #0x50]
1202231c  mov        x2, x26
12022320  mov        w3, w23
12022324  stp        xzr, xzr, [x19, #0x30]
12022328  str        x21, [x19, #0x28]
1202232c  bl         #0x1204d160
12022330  ldrb       w8, [x19, #8]
12022334  stp        xzr, xzr, [x29, #-0x78]
12022338  ldp        x9, x10, [x19, #0x10]
1202233c  stur       xzr, [x29, #-0x68]
12022340  lsr        x11, x8, #1
12022344  tst        w8, #1
12022348  ldr        x8, [sp, #0x48]
1202234c  csel       x22, x11, x9, eq
12022350  csel       x25, x8, x10, eq
12022354  add        x8, x22, #0x11
12022358  cmn        x8, #0x10
1202235c  b.hs       #0x1202296c
12022360  cmp        x8, #0x17
12022364  b.hs       #0x1202237c
12022368  lsl        w8, w22, #1
1202236c  mov        x27, x20
12022370  sturb      w8, [x29, #-0x78]
12022374  cbnz       x22, #0x1202239c
12022378  b          #0x120223ac
1202237c  add        x8, x22, #0x21
12022380  and        x28, x8, #0xfffffffffffffff0
12022384  mov        x0, x28
12022388  bl         #0x1204d060
1202238c  orr        x8, x28, #1
12022390  mov        x27, x0
12022394  stp        x22, x0, [x29, #-0x70]
12022398  stur       x8, [x29, #-0x78]
1202239c  mov        x0, x27
120223a0  mov        x1, x25
120223a4  mov        x2, x22
120223a8  bl         #0x1204d120
120223ac  adrp       x1, #0x12016000
120223b0  sub        x0, x29, #0x78
120223b4  add        x1, x1, #0x5fa
120223b8  movz       w2, #0x11
120223bc  strb       wzr, [x27, x22]
120223c0  bl         #0x1204d130
120223c4  ldurb      w8, [x29, #-0x78]
120223c8  adrp       x1, #0x12015000
120223cc  ldur       x9, [x29, #-0x68]
120223d0  add        x1, x1, #0xc4c
120223d4  tst        w8, #1
120223d8  csel       x0, x20, x9, eq
120223dc  bl         #0x1204d140
120223e0  cbz        x0, #0x1202242c
120223e4  mov        x1, xzr
120223e8  movz       w2, #0x2
120223ec  mov        x22, x0
120223f0  bl         #0x1204d170
120223f4  mov        x0, x22
120223f8  bl         #0x1204d180
120223fc  subs       x28, x0, #8
12022400  b.hi       #0x1202245c
12022404  adrp       x8, #0x12051000
12022408  ldr        x8, [x8, #0xe90]
1202240c  ldrb       w8, [x8]
12022410  cbz        w8, #0x1202255c
12022414  adrp       x1, #0x12015000
12022418  adrp       x2, #0x12015000
1202241c  movz       w0, #0x6
12022420  add        x1, x1, #0x34a
12022424  add        x2, x2, #0x7c6
12022428  b          #0x12022558
1202242c  adrp       x8, #0x12051000
12022430  ldr        x8, [x8, #0xe90]
12022434  ldrb       w8, [x8]
12022438  cbz        w8, #0x1202252c
1202243c  adrp       x1, #0x12015000
12022440  adrp       x2, #0x12015000
12022444  movz       w0, #0x6
12022448  add        x1, x1, #0x34a
1202244c  add        x2, x2, #0xe1
12022450  bl         #0x1204d050
12022454  mov        w25, wzr
12022458  b          #0x12022568
1202245c  mov        x0, x22
12022460  mov        x1, xzr
12022464  mov        w2, wzr
12022468  bl         #0x1204d170
1202246c  sub        x0, x29, #0x7c
12022470  movz       w1, #0x1
12022474  movz       w2, #0x4
12022478  mov        x3, x22
1202247c  stur       wzr, [x29, #-0x7c]
12022480  bl         #0x1204d190
12022484  cmp        x0, #4
12022488  b.ne       #0x1202251c
1202248c  ldur       w8, [x29, #-0x7c]
12022490  cmp        w8, #1
12022494  b.ne       #0x12022534
12022498  sub        x0, x29, #0x80
1202249c  movz       w1, #0x1
120224a0  movz       w2, #0x4
120224a4  mov        x3, x22
120224a8  stur       wzr, [x29, #-0x80]
120224ac  bl         #0x1204d190
120224b0  adrp       x8, #0x12051000
120224b4  cmp        x0, #4
120224b8  ldr        x8, [x8, #0xe90]
120224bc  ldrb       w8, [x8]
120224c0  b.ne       #0x12022590
120224c4  ldur       w25, [x29, #-0x80]
120224c8  cbz        w8, #0x120224e8
120224cc  adrp       x1, #0x12015000
120224d0  adrp       x2, #0x12016000
120224d4  movz       w0, #0x4
120224d8  add        x1, x1, #0x34a
120224dc  add        x2, x2, #0x60c
120224e0  mov        w3, w25
120224e4  bl         #0x1204d050
120224e8  sxtw       x27, w25
120224ec  cmp        x28, x27
120224f0  b.hs       #0x120225ac
120224f4  adrp       x8, #0x12051000
120224f8  ldr        x8, [x8, #0xe90]
120224fc  ldrb       w8, [x8]
12022500  cbz        w8, #0x1202255c
12022504  adrp       x1, #0x12015000
12022508  adrp       x2, #0x12015000
1202250c  movz       w0, #0x6
12022510  add        x1, x1, #0x34a
12022514  add        x2, x2, #0x229
12022518  b          #0x12022558
1202251c  adrp       x8, #0x12051000
12022520  adrp       x2, #0x12016000
12022524  add        x2, x2, #0x7dc
12022528  b          #0x12022540
1202252c  mov        w25, wzr
12022530  b          #0x12022568
12022534  adrp       x8, #0x12051000
12022538  adrp       x2, #0x12016000
1202253c  add        x2, x2, #0x680
12022540  ldr        x8, [x8, #0xe90]
12022544  ldrb       w8, [x8]
12022548  cbz        w8, #0x1202255c
1202254c  adrp       x1, #0x12015000
12022550  movz       w0, #0x6
12022554  add        x1, x1, #0x34a
12022558  bl         #0x1204d050
1202255c  mov        w25, wzr
12022560  mov        x0, x22
12022564  bl         #0x1204d150
12022568  ldurb      w8, [x29, #-0x78]
1202256c  tbz        w8, #0, #0x12022578
12022570  ldur       x0, [x29, #-0x68]
12022574  bl         #0x1204d0f0
12022578  cbnz       w25, #0x120228d4
1202257c  add        w8, w23, #1
12022580  cmp        w23, #2
12022584  mov        w23, w8
12022588  b.lo       #0x12022304
1202258c  b          #0x120228d4
12022590  cbz        w8, #0x1202255c
12022594  adrp       x1, #0x12015000
12022598  adrp       x2, #0x12016000
1202259c  movz       w0, #0x6
120225a0  add        x1, x1, #0x34a
120225a4  add        x2, x2, #0x4bd
120225a8  b          #0x12022558
120225ac  mov        x0, x27
120225b0  bl         #0x1204d1a0
120225b4  movz       w1, #0x1
120225b8  mov        x2, x27
120225bc  mov        x3, x22
120225c0  str        x0, [sp, #0x10]
120225c4  bl         #0x1204d190
120225c8  adrp       x28, #0x12016000
120225cc  cmp        x0, x27
120225d0  add        x28, x28, #0xdd8
120225d4  b.ne       #0x12022634
120225d8  sub        x0, x29, #0x30
120225dc  bl         #0x1204d1b0
120225e0  sub        x0, x29, #0x30
120225e4  mov        w1, wzr
120225e8  mov        w2, wzr
120225ec  bl         #0x1204d1c0
120225f0  add        x0, sp, #0x88
120225f4  mov        x1, x26
120225f8  stp        xzr, xzr, [sp, #0x88]
120225fc  str        xzr, [sp, #0x98]
12022600  bl         #0x1204d1d0
12022604  ldrb       w8, [sp, #0x88]
12022608  ldr        x9, [sp, #0x90]
1202260c  lsr        x10, x8, #1
12022610  tst        w8, #1
12022614  csel       x8, x10, x9, eq
12022618  cmp        x8, #0x11
1202261c  b.lo       #0x12022668
12022620  sub        x2, x8, #0x10
12022624  add        x0, sp, #0x88
12022628  movz       w1, #0x10
1202262c  bl         #0x1204d1e0
12022630  b          #0x12022684
12022634  adrp       x8, #0x12051000
12022638  ldr        x8, [x8, #0xe90]
1202263c  ldrb       w8, [x8]
12022640  cbz        w8, #0x1202265c
12022644  adrp       x1, #0x12015000
12022648  adrp       x2, #0x12015000
1202264c  movz       w0, #0x6
12022650  add        x1, x1, #0x34a
12022654  add        x2, x2, #0x56e
12022658  bl         #0x1204d050
1202265c  ldr        x0, [sp, #0x10]
12022660  bl         #0x1204d1f0
12022664  b          #0x1202255c
12022668  cmp        x8, #0x10
1202266c  b.eq       #0x12022684
12022670  movz       w9, #0x10
12022674  add        x0, sp, #0x88
12022678  sub        x1, x9, x8
1202267c  movz       w2, #0x41
12022680  bl         #0x1204d200
12022684  ldrb       w8, [sp, #0x88]
12022688  sub        x0, x29, #0x30
1202268c  ldr        x9, [sp, #0x98]
12022690  ldr        w10, [sp, #0x90]
12022694  ldr        x11, [sp, #0x30]
12022698  tst        w8, #1
1202269c  lsr        w8, w8, #1
120226a0  csel       w2, w8, w10, eq
120226a4  csel       x1, x11, x9, eq
120226a8  bl         #0x1204d210
120226ac  mov        x0, x27
120226b0  str        w25, [sp, #0x84]
120226b4  bl         #0x1204d1a0
120226b8  ldr        x27, [sp, #0x10]
120226bc  mov        x3, x0
120226c0  sub        x0, x29, #0x30
120226c4  add        x4, sp, #0x84
120226c8  mov        w2, w25
120226cc  mov        x1, x27
120226d0  str        x3, [sp, #8]
120226d4  bl         #0x1204d220
120226d8  and        w25, w0, #0xff
120226dc  mov        x0, x27
120226e0  bl         #0x1204d1f0
120226e4  adrp       x8, #0x12051000
120226e8  ldr        x8, [x8, #0xe90]
120226ec  ldrb       w8, [x8]
120226f0  cbz        w25, #0x1202276c
120226f4  cbz        w8, #0x12022714
120226f8  adrp       x1, #0x12015000
120226fc  adrp       x2, #0x12015000
12022700  ldr        w3, [sp, #0x84]
12022704  movz       w0, #0x4
12022708  add        x1, x1, #0x34a
1202270c  add        x2, x2, #0xcfd
12022710  bl         #0x1204d050
12022714  ldrsw      x25, [sp, #0x84]
12022718  cbz        w25, #0x120227a0
1202271c  ldr        x27, [sp, #8]
12022720  stp        xzr, xzr, [x29, #-0x48]
12022724  stur       xzr, [x29, #-0x38]
12022728  ldrb       w8, [x27]
1202272c  sub        x0, x29, #0x48
12022730  lsl        x8, x8, #2
12022734  ldrb       w1, [x28, x8]
12022738  bl         #0x1204d230
1202273c  ldrb       w8, [x27], #1
12022740  sub        x0, x29, #0x48
12022744  add        x8, x28, x8, lsl #2
12022748  ldrb       w1, [x8, #1]
1202274c  bl         #0x1204d230
12022750  subs       x25, x25, #1
12022754  b.ne       #0x12022728
12022758  ldur       q0, [x29, #-0x48]
1202275c  ldur       x8, [x29, #-0x38]
12022760  str        q0, [sp, #0x60]
12022764  str        x8, [sp, #0x70]
12022768  b          #0x120227a4
1202276c  cbz        w8, #0x12022788
12022770  adrp       x1, #0x12015000
12022774  adrp       x2, #0x12016000
12022778  movz       w0, #0x6
1202277c  add        x1, x1, #0x34a
12022780  add        x2, x2, #0x9b9
12022784  bl         #0x1204d050
12022788  ldr        x0, [sp, #8]
1202278c  bl         #0x1204d1f0
12022790  mov        w25, wzr
12022794  ldrb       w8, [sp, #0x88]
12022798  tbnz       w8, #0, #0x12022884
1202279c  b          #0x1202288c
120227a0  strh       wzr, [sp, #0x60]
120227a4  adrp       x8, #0x12051000
120227a8  ldr        x8, [x8, #0xe90]
120227ac  ldrb       w8, [x8]
120227b0  cbz        w8, #0x120227e0
120227b4  ldrb       w8, [sp, #0x60]
120227b8  adrp       x1, #0x12015000
120227bc  ldr        x9, [sp, #0x70]
120227c0  adrp       x2, #0x12015000
120227c4  movz       w0, #0x4
120227c8  add        x1, x1, #0x34a
120227cc  tst        w8, #1
120227d0  ldr        x8, [sp, #0x20]
120227d4  add        x2, x2, #0x671
120227d8  csel       x3, x8, x9, eq
120227dc  bl         #0x1204d050
120227e0  ldrsw      x25, [sp, #0x84]
120227e4  cmn        w25, #0x10
120227e8  b.hs       #0x1202297c
120227ec  cmp        w25, #0x17
120227f0  b.hs       #0x1202280c
120227f4  lsl        w8, w25, #1
120227f8  ldr        x27, [sp, #0x18]
120227fc  ldr        x28, [sp, #8]
12022800  sturb      w8, [x29, #-0x48]
12022804  cbnz       w25, #0x12022830
12022808  b          #0x12022840
1202280c  add        x8, x25, #0x10
12022810  and        x28, x8, #0xfffffffffffffff0
12022814  mov        x0, x28
12022818  bl         #0x1204d060
1202281c  orr        x8, x28, #1
12022820  ldr        x28, [sp, #8]
12022824  mov        x27, x0
12022828  stp        x25, x0, [x29, #-0x40]
1202282c  stur       x8, [x29, #-0x48]
12022830  mov        x0, x27
12022834  mov        x1, x28
12022838  mov        x2, x25
1202283c  bl         #0x1204d120
12022840  sub        x1, x29, #0x48
12022844  ldr        x0, [sp, #0x28]
12022848  strb       wzr, [x27, x25]
1202284c  bl         #0x1204d240
12022850  mov        x0, x28
12022854  bl         #0x1204d1f0
12022858  ldurb      w8, [x29, #-0x48]
1202285c  tbz        w8, #0, #0x12022868
12022860  ldur       x0, [x29, #-0x38]
12022864  bl         #0x1204d0f0
12022868  ldrb       w8, [sp, #0x60]
1202286c  tbz        w8, #0, #0x12022878
12022870  ldr        x0, [sp, #0x70]
12022874  bl         #0x1204d0f0
12022878  movz       w25, #0x1
1202287c  ldrb       w8, [sp, #0x88]
12022880  tbz        w8, #0, #0x1202288c
12022884  ldr        x0, [sp, #0x98]
12022888  bl         #0x1204d0f0
1202288c  sub        x0, x29, #0x30
12022890  bl         #0x1204d250
12022894  b          #0x12022560
12022898  adrp       x8, #0x12051000
1202289c  ldr        x8, [x8, #0xe90]
120228a0  ldrb       w8, [x8]
120228a4  cbz        w8, #0x120228c0
120228a8  adrp       x1, #0x12015000
120228ac  adrp       x2, #0x12015000
120228b0  add        x1, x1, #0x34a
120228b4  add        x2, x2, #0xe76
120228b8  movz       w0, #0x4
120228bc  bl         #0x1204d050
120228c0  ldr        x20, [sp, #0x40]
120228c4  movn       w21, #0
120228c8  ldurb      w8, [x29, #-0x60]
120228cc  tbz        w8, #0, #0x12022924
120228d0  b          #0x1202291c
120228d4  adrp       x8, #0x12051000
120228d8  ldr        x8, [x8, #0xe90]
120228dc  ldr        x20, [sp, #0x40]
120228e0  ldr        w21, [sp, #0x3c]
120228e4  ldrb       w8, [x8]
120228e8  cbz        w8, #0x1202290c
120228ec  adrp       x1, #0x12015000
120228f0  adrp       x2, #0x12015000
120228f4  ldr        x3, [x19, #0x38]
120228f8  add        x1, x1, #0x34a
120228fc  add        x2, x2, #0x107
12022900  movz       w0, #0x4
12022904  mov        w4, w21
12022908  bl         #0x1204d050
1202290c  ldr        x8, [x19, #0x38]
12022910  cbz        x8, #0x12022958
12022914  ldurb      w8, [x29, #-0x60]
12022918  tbz        w8, #0, #0x12022924
1202291c  ldur       x0, [x29, #-0x50]
12022920  bl         #0x1204d0f0
12022924  ldr        x8, [x20, #0x28]
12022928  ldur       x9, [x29, #-0x10]
1202292c  cmp        x8, x9
12022930  b.ne       #0x12022984
12022934  mov        w0, w21
12022938  ldp        x20, x19, [sp, #0x170]
1202293c  ldp        x22, x21, [sp, #0x160]
12022940  ldp        x24, x23, [sp, #0x150]
12022944  ldp        x26, x25, [sp, #0x140]
12022948  ldp        x28, x27, [sp, #0x130]
1202294c  ldp        x29, x30, [sp, #0x120]
12022950  add        sp, sp, #0x180
12022954  ret        
12022958  mov        x0, x19
1202295c  bl         #0x1204d260
12022960  ldurb      w8, [x29, #-0x60]
12022964  tbnz       w8, #0, #0x1202291c
12022968  b          #0x12022924
1202296c  sub        x0, x29, #0x78
12022970  bl         #0x1204d270
12022974  sub        x0, x29, #0x60
12022978  bl         #0x1204d270
1202297c  sub        x0, x29, #0x48
12022980  bl         #0x1204d270
12022984  bl         #0x1204d080
12022988  stp        x29, x30, [sp, #-0x20]!
1202298c  str        x19, [sp, #0x10]
12022990  mov        x29, sp
12022994  mov        x19, x1
12022998  add        x1, x0, #0x40
1202299c  mov        x0, x19
120229a0  bl         #0x1204d1d0
120229a4  ldrb       w8, [x19]
120229a8  ldr        x9, [x19, #8]
120229ac  lsr        x10, x8, #1
120229b0  tst        w8, #1
120229b4  csel       x8, x10, x9, eq
120229b8  cmp        x8, #0x11
120229bc  b.lo       #0x120229d4
120229c0  sub        x2, x8, #0x10
120229c4  mov        x0, x19
120229c8  movz       w1, #0x10
120229cc  bl         #0x1204d1e0
120229d0  b          #0x120229f0
120229d4  cmp        x8, #0x10
120229d8  b.eq       #0x120229f0
120229dc  movz       w9, #0x10
120229e0  mov        x0, x19
120229e4  sub        x1, x9, x8
120229e8  movz       w2, #0x41
120229ec  bl         #0x1204d200
120229f0  ldr        x19, [sp, #0x10]
120229f4  ldp        x29, x30, [sp], #0x20
120229f8  ret        

================================================================================
## _ZN18CNativeConfigStore10SaveToFileEv
## base+0x229fc
================================================================================
120229fc  sub        sp, sp, #0xe0
12022a00  stp        x29, x30, [sp, #0x80]
12022a04  add        x29, sp, #0x80
12022a08  str        x27, [sp, #0x90]
12022a0c  stp        x26, x25, [sp, #0xa0]
12022a10  stp        x24, x23, [sp, #0xb0]
12022a14  stp        x22, x21, [sp, #0xc0]
12022a18  stp        x20, x19, [sp, #0xd0]
12022a1c  adrp       x26, #0x12051000
12022a20  mrs        x25, tpidr_el0
12022a24  ldr        x8, [x25, #0x28]
12022a28  mov        x19, x0
12022a2c  ldr        x26, [x26, #0xe90]
12022a30  stur       x8, [x29, #-8]
12022a34  ldrb       w8, [x26]
12022a38  cbz        w8, #0x12022a54
12022a3c  adrp       x1, #0x12015000
12022a40  adrp       x2, #0x12015000
12022a44  add        x1, x1, #0x34a
12022a48  add        x2, x2, #0x68a
12022a4c  movz       w0, #0x4
12022a50  bl         #0x1204d050
12022a54  add        x0, x19, #0x20
12022a58  bl         #0x1204d280
12022a5c  ldrb       w9, [x0]
12022a60  mov        x21, x0
12022a64  ldr        w10, [x0, #8]
12022a68  ldrb       w8, [x26]
12022a6c  lsr        w11, w9, #1
12022a70  tst        w9, #1
12022a74  csel       w22, w11, w10, eq
12022a78  cbz        w8, #0x12022a98
12022a7c  adrp       x1, #0x12015000
12022a80  adrp       x2, #0x12015000
12022a84  add        x1, x1, #0x34a
12022a88  add        x2, x2, #0xdad
12022a8c  movz       w0, #0x4
12022a90  mov        w3, w22
12022a94  bl         #0x1204d050
12022a98  sub        x0, x29, #0x28
12022a9c  bl         #0x1204d1b0
12022aa0  sub        x0, x29, #0x28
12022aa4  mov        w1, wzr
12022aa8  mov        w2, wzr
12022aac  bl         #0x1204d1c0
12022ab0  add        x1, x19, #0x40
12022ab4  add        x0, sp, #0x40
12022ab8  stp        xzr, xzr, [sp, #0x40]
12022abc  str        xzr, [sp, #0x50]
12022ac0  bl         #0x1204d1d0
12022ac4  ldrb       w8, [sp, #0x40]
12022ac8  ldr        x9, [sp, #0x48]
12022acc  lsr        x10, x8, #1
12022ad0  tst        w8, #1
12022ad4  csel       x8, x10, x9, eq
12022ad8  cmp        x8, #0x11
12022adc  b.lo       #0x12022af4
12022ae0  sub        x2, x8, #0x10
12022ae4  add        x0, sp, #0x40
12022ae8  movz       w1, #0x10
12022aec  bl         #0x1204d1e0
12022af0  b          #0x12022b10
12022af4  cmp        x8, #0x10
12022af8  b.eq       #0x12022b10
12022afc  movz       w9, #0x10
12022b00  add        x0, sp, #0x40
12022b04  sub        x1, x9, x8
12022b08  movz       w2, #0x41
12022b0c  bl         #0x1204d200
12022b10  ldrb       w8, [sp, #0x40]
12022b14  add        x10, sp, #0x40
12022b18  ldr        x9, [sp, #0x50]
12022b1c  orr        x10, x10, #1
12022b20  ldr        w11, [sp, #0x48]
12022b24  sub        x0, x29, #0x28
12022b28  tst        w8, #1
12022b2c  lsr        w8, w8, #1
12022b30  csel       x1, x10, x9, eq
12022b34  csel       w2, w8, w11, eq
12022b38  bl         #0x1204d210
12022b3c  sub        x0, x29, #0x28
12022b40  mov        w1, w22
12022b44  bl         #0x1204d290
12022b48  sxtw       x8, w0
12022b4c  str        w0, [sp, #0x3c]
12022b50  mov        x0, x8
12022b54  bl         #0x1204d1a0
12022b58  ldrb       w8, [x21]
12022b5c  mov        x20, x0
12022b60  ldr        x9, [x21, #0x10]
12022b64  sub        x0, x29, #0x28
12022b68  add        x4, sp, #0x3c
12022b6c  mov        w2, w22
12022b70  tst        w8, #1
12022b74  mov        x3, x20
12022b78  csinc      x1, x9, x21, ne
12022b7c  bl         #0x1204d2a0
12022b80  ldrb       w8, [x26]
12022b84  cbz        w8, #0x12022ba4
12022b88  adrp       x1, #0x12015000
12022b8c  adrp       x2, #0x12016000
12022b90  ldr        w3, [sp, #0x3c]
12022b94  add        x1, x1, #0x34a
12022b98  add        x2, x2, #0x8c5
12022b9c  movz       w0, #0x4
12022ba0  bl         #0x1204d050
12022ba4  ldrb       w8, [x21]
12022ba8  tbz        w8, #0, #0x12022bb4
12022bac  ldr        x0, [x21, #0x10]
12022bb0  bl         #0x1204d0f0
12022bb4  mov        x0, x21
12022bb8  bl         #0x1204d0f0
12022bbc  ldrb       w8, [x19, #8]
12022bc0  add        x27, x19, #9
12022bc4  ldp        x9, x10, [x19, #0x10]
12022bc8  stp        xzr, xzr, [sp, #0x20]
12022bcc  lsr        x11, x8, #1
12022bd0  tst        w8, #1
12022bd4  str        xzr, [sp, #0x30]
12022bd8  csel       x21, x11, x9, eq
12022bdc  csel       x22, x27, x10, eq
12022be0  add        x8, x21, #0x11
12022be4  cmn        x8, #0x10
12022be8  b.hs       #0x120230c8
12022bec  cmp        x8, #0x17
12022bf0  b.hs       #0x12022c0c
12022bf4  add        x9, sp, #0x20
12022bf8  lsl        w8, w21, #1
12022bfc  orr        x23, x9, #1
12022c00  strb       w8, [sp, #0x20]
12022c04  cbnz       x21, #0x12022c2c
12022c08  b          #0x12022c3c
12022c0c  add        x8, x21, #0x21
12022c10  and        x24, x8, #0xfffffffffffffff0
12022c14  mov        x0, x24
12022c18  bl         #0x1204d060
12022c1c  orr        x8, x24, #1
12022c20  mov        x23, x0
12022c24  stp        x21, x0, [sp, #0x28]
12022c28  str        x8, [sp, #0x20]
12022c2c  mov        x0, x23
12022c30  mov        x1, x22
12022c34  mov        x2, x21
12022c38  bl         #0x1204d120
12022c3c  adrp       x1, #0x12016000
12022c40  add        x0, sp, #0x20
12022c44  add        x1, x1, #0x5fa
12022c48  movz       w2, #0x11
12022c4c  strb       wzr, [x23, x21]
12022c50  bl         #0x1204d130
12022c54  ldrb       w8, [x19, #8]
12022c58  stp        xzr, xzr, [sp, #8]
12022c5c  ldp        x9, x10, [x19, #0x10]
12022c60  str        xzr, [sp, #0x18]
12022c64  lsr        x11, x8, #1
12022c68  tst        w8, #1
12022c6c  csel       x21, x11, x9, eq
12022c70  csel       x22, x27, x10, eq
12022c74  add        x8, x21, #0x16
12022c78  cmn        x8, #0x10
12022c7c  b.hs       #0x120230d0
12022c80  cmp        x8, #0x17
12022c84  b.hs       #0x12022ca0
12022c88  add        x9, sp, #8
12022c8c  lsl        w8, w21, #1
12022c90  orr        x23, x9, #1
12022c94  strb       w8, [sp, #8]
12022c98  cbnz       x21, #0x12022cc0
12022c9c  b          #0x12022cd0
12022ca0  add        x8, x21, #0x26
12022ca4  and        x24, x8, #0xfffffffffffffff0
12022ca8  mov        x0, x24
12022cac  bl         #0x1204d060
12022cb0  orr        x8, x24, #1
12022cb4  mov        x23, x0
12022cb8  stp        x21, x0, [sp, #0x10]
12022cbc  str        x8, [sp, #8]
12022cc0  mov        x0, x23
12022cc4  mov        x1, x22
12022cc8  mov        x2, x21
12022ccc  bl         #0x1204d120
12022cd0  adrp       x1, #0x12015000
12022cd4  add        x0, sp, #8
12022cd8  add        x1, x1, #0x65a
12022cdc  movz       w2, #0x16
12022ce0  strb       wzr, [x23, x21]
12022ce4  add        x21, sp, #8
12022ce8  bl         #0x1204d130
12022cec  ldrb       w8, [sp, #8]
12022cf0  orr        x23, x21, #1
12022cf4  ldr        x9, [sp, #0x18]
12022cf8  movz       w1, #0x41
12022cfc  movk       w1, #0x8, lsl #16
12022d00  movz       w2, #0x180
12022d04  tst        w8, #1
12022d08  csel       x0, x23, x9, eq
12022d0c  bl         #0x1204d2b0
12022d10  cbz        w0, #0x12022e34
12022d14  adrp       x1, #0x12016000
12022d18  add        x1, x1, #0x8d6
12022d1c  bl         #0x1204d2c0
12022d20  mov        x21, x0
12022d24  cbz        x0, #0x12023018
12022d28  mov        x0, x21
12022d2c  mov        x1, xzr
12022d30  mov        w2, wzr
12022d34  bl         #0x1204d170
12022d38  ldrb       w8, [x26]
12022d3c  cbz        w8, #0x12022d5c
12022d40  adrp       x1, #0x12015000
12022d44  adrp       x2, #0x12015000
12022d48  mov        w3, w0
12022d4c  add        x1, x1, #0x34a
12022d50  add        x2, x2, #0x12a
12022d54  movz       w0, #0x4
12022d58  bl         #0x1204d050
12022d5c  adrp       x0, #0x12016000
12022d60  movz       w1, #0x4
12022d64  add        x0, x0, #0xdd4
12022d68  movz       w2, #0x1
12022d6c  mov        x3, x21
12022d70  bl         #0x1204d2d0
12022d74  mov        x22, x0
12022d78  cmp        w22, #1
12022d7c  cset       w24, eq
12022d80  b.eq       #0x12022da4
12022d84  ldrb       w8, [x26]
12022d88  cbz        w8, #0x12022dc8
12022d8c  adrp       x1, #0x12015000
12022d90  adrp       x2, #0x12015000
12022d94  add        x1, x1, #0x34a
12022d98  add        x2, x2, #0x254
12022d9c  movz       w0, #0x4
12022da0  bl         #0x1204d050
12022da4  ldrb       w8, [x26]
12022da8  cbz        w8, #0x12022dc8
12022dac  adrp       x1, #0x12015000
12022db0  adrp       x2, #0x12015000
12022db4  add        x1, x1, #0x34a
12022db8  add        x2, x2, #0x12a
12022dbc  movz       w0, #0x4
12022dc0  mov        w3, w22
12022dc4  bl         #0x1204d050
12022dc8  add        x0, sp, #0x3c
12022dcc  movz       w1, #0x4
12022dd0  movz       w2, #0x1
12022dd4  mov        x3, x21
12022dd8  bl         #0x1204d2d0
12022ddc  mov        x22, x0
12022de0  cmp        w22, #1
12022de4  b.eq       #0x12022e0c
12022de8  ldrb       w8, [x26]
12022dec  cbz        w8, #0x12022e3c
12022df0  adrp       x1, #0x12015000
12022df4  adrp       x2, #0x12016000
12022df8  add        x1, x1, #0x34a
12022dfc  add        x2, x2, #0x256
12022e00  movz       w0, #0x4
12022e04  bl         #0x1204d050
12022e08  mov        w24, wzr
12022e0c  ldrb       w8, [x26]
12022e10  cbz        w8, #0x12022e40
12022e14  adrp       x1, #0x12015000
12022e18  adrp       x2, #0x12015000
12022e1c  add        x1, x1, #0x34a
12022e20  add        x2, x2, #0x12a
12022e24  movz       w0, #0x4
12022e28  mov        w3, w22
12022e2c  bl         #0x1204d050
12022e30  b          #0x12022e40
12022e34  mov        w21, wzr
12022e38  b          #0x12023018
12022e3c  mov        w24, wzr
12022e40  ldrsw      x1, [sp, #0x3c]
12022e44  mov        x0, x20
12022e48  movz       w2, #0x1
12022e4c  mov        x3, x21
12022e50  bl         #0x1204d2d0
12022e54  mov        x22, x0
12022e58  cmp        w22, #1
12022e5c  b.eq       #0x12022e84
12022e60  ldrb       w8, [x26]
12022e64  cbz        w8, #0x12022eac
12022e68  adrp       x1, #0x12015000
12022e6c  adrp       x2, #0x12016000
12022e70  add        x1, x1, #0x34a
12022e74  add        x2, x2, #0x272
12022e78  movz       w0, #0x4
12022e7c  bl         #0x1204d050
12022e80  mov        w24, wzr
12022e84  ldrb       w8, [x26]
12022e88  cbz        w8, #0x12022eb0
12022e8c  adrp       x1, #0x12015000
12022e90  adrp       x2, #0x12015000
12022e94  add        x1, x1, #0x34a
12022e98  add        x2, x2, #0x12a
12022e9c  movz       w0, #0x4
12022ea0  mov        w3, w22
12022ea4  bl         #0x1204d050
12022ea8  b          #0x12022eb0
12022eac  mov        w24, wzr
12022eb0  mov        x0, x21
12022eb4  bl         #0x1204d2e0
12022eb8  ldrb       w8, [x26]
12022ebc  cbz        w8, #0x12022edc
12022ec0  adrp       x1, #0x12015000
12022ec4  adrp       x2, #0x12016000
12022ec8  mov        w3, w0
12022ecc  add        x1, x1, #0x34a
12022ed0  add        x2, x2, #0xb33
12022ed4  movz       w0, #0x4
12022ed8  bl         #0x1204d050
12022edc  mov        x0, x21
12022ee0  bl         #0x1204d150
12022ee4  ldrb       w8, [x26]
12022ee8  mov        w21, w0
12022eec  cbz        w8, #0x12022f0c
12022ef0  adrp       x1, #0x12015000
12022ef4  adrp       x2, #0x12016000
12022ef8  add        x1, x1, #0x34a
12022efc  add        x2, x2, #0x28e
12022f00  movz       w0, #0x4
12022f04  mov        w3, w21
12022f08  bl         #0x1204d050
12022f0c  tbz        w24, #0, #0x12022f8c
12022f10  cbnz       w21, #0x12022fb0
12022f14  ldrb       w8, [sp, #8]
12022f18  ldr        x9, [sp, #0x18]
12022f1c  ldrb       w10, [sp, #0x20]
12022f20  ldr        x11, [sp, #0x30]
12022f24  tst        w8, #1
12022f28  add        x8, sp, #0x20
12022f2c  csel       x0, x23, x9, eq
12022f30  orr        x8, x8, #1
12022f34  tst        w10, #1
12022f38  csel       x1, x8, x11, eq
12022f3c  bl         #0x1204d2f0
12022f40  ldrb       w8, [x26]
12022f44  mov        w21, w0
12022f48  cbz        w8, #0x12022f68
12022f4c  adrp       x1, #0x12015000
12022f50  adrp       x2, #0x12015000
12022f54  add        x1, x1, #0x34a
12022f58  add        x2, x2, #0x59f
12022f5c  movz       w0, #0x4
12022f60  mov        w3, w21
12022f64  bl         #0x1204d050
12022f68  cbz        w21, #0x12023018
12022f6c  ldrb       w8, [x26]
12022f70  add        w21, w21, #0x7d0
12022f74  cbz        w8, #0x12023018
12022f78  adrp       x1, #0x12015000
12022f7c  adrp       x2, #0x12016000
12022f80  add        x1, x1, #0x34a
12022f84  add        x2, x2, #0x808
12022f88  b          #0x1202300c
12022f8c  ldrb       w8, [x26]
12022f90  cbz        w8, #0x12022fb0
12022f94  adrp       x1, #0x12015000
12022f98  adrp       x2, #0x12015000
12022f9c  add        w3, w21, #0x3e8
12022fa0  add        x1, x1, #0x34a
12022fa4  add        x2, x2, #0x352
12022fa8  movz       w0, #0x4
12022fac  bl         #0x1204d050
12022fb0  ldrb       w8, [sp, #8]
12022fb4  ldr        x9, [sp, #0x18]
12022fb8  tst        w8, #1
12022fbc  csel       x0, x23, x9, eq
12022fc0  bl         #0x1204d300
12022fc4  ldrb       w8, [x26]
12022fc8  mov        w21, w0
12022fcc  cbz        w8, #0x12022fec
12022fd0  adrp       x1, #0x12015000
12022fd4  adrp       x2, #0x12015000
12022fd8  add        x1, x1, #0x34a
12022fdc  add        x2, x2, #0x75a
12022fe0  movz       w0, #0x4
12022fe4  mov        w3, w21
12022fe8  bl         #0x1204d050
12022fec  cbz        w21, #0x12023018
12022ff0  ldrb       w8, [x26]
12022ff4  add        w21, w21, #0xbb8
12022ff8  cbz        w8, #0x12023018
12022ffc  adrp       x1, #0x12015000
12023000  adrp       x2, #0x12016000
12023004  add        x1, x1, #0x34a
12023008  add        x2, x2, #0x1b4
1202300c  movz       w0, #0x4
12023010  mov        w3, w21
12023014  bl         #0x1204d050
12023018  mov        x0, x20
1202301c  bl         #0x1204d1f0
12023020  ldrb       w8, [x26]
12023024  cbz        w8, #0x12023048
12023028  adrp       x1, #0x12015000
1202302c  adrp       x2, #0x12016000
12023030  ldr        x3, [x19, #0x38]
12023034  add        x1, x1, #0x34a
12023038  add        x2, x2, #0x8b
1202303c  movz       w0, #0x4
12023040  mov        w4, w21
12023044  bl         #0x1204d050
12023048  ldrb       w8, [sp, #8]
1202304c  tbnz       w8, #0, #0x120230a4
12023050  ldrb       w8, [sp, #0x20]
12023054  tbnz       w8, #0, #0x120230b4
12023058  ldrb       w8, [sp, #0x40]
1202305c  tbz        w8, #0, #0x12023068
12023060  ldr        x0, [sp, #0x50]
12023064  bl         #0x1204d0f0
12023068  sub        x0, x29, #0x28
1202306c  bl         #0x1204d250
12023070  ldr        x8, [x25, #0x28]
12023074  ldur       x9, [x29, #-8]
12023078  cmp        x8, x9
1202307c  b.ne       #0x120230d8
12023080  mov        w0, w21
12023084  ldr        x27, [sp, #0x90]
12023088  ldp        x20, x19, [sp, #0xd0]
1202308c  ldp        x22, x21, [sp, #0xc0]
12023090  ldp        x24, x23, [sp, #0xb0]
12023094  ldp        x26, x25, [sp, #0xa0]
12023098  ldp        x29, x30, [sp, #0x80]
1202309c  add        sp, sp, #0xe0
120230a0  ret        
120230a4  ldr        x0, [sp, #0x18]
120230a8  bl         #0x1204d0f0
120230ac  ldrb       w8, [sp, #0x20]
120230b0  tbz        w8, #0, #0x12023058
120230b4  ldr        x0, [sp, #0x30]
120230b8  bl         #0x1204d0f0
120230bc  ldrb       w8, [sp, #0x40]
120230c0  tbnz       w8, #0, #0x12023060
120230c4  b          #0x12023068
120230c8  add        x0, sp, #0x20
120230cc  bl         #0x1204d270
120230d0  add        x0, sp, #8
120230d4  bl         #0x1204d270
120230d8  bl         #0x1204d080
120230dc  sub        sp, sp, #0x80
120230e0  stp        x29, x30, [sp, #0x20]
120230e4  add        x29, sp, #0x20
120230e8  str        x27, [sp, #0x30]
120230ec  stp        x26, x25, [sp, #0x40]
120230f0  stp        x24, x23, [sp, #0x50]
120230f4  stp        x22, x21, [sp, #0x60]
120230f8  stp        x20, x19, [sp, #0x70]
120230fc  adrp       x27, #0x12051000
12023100  mrs        x26, tpidr_el0
12023104  ldr        x8, [x26, #0x28]
12023108  mov        x19, x2
1202310c  mov        x20, x1
12023110  mov        x22, x0
12023114  ldr        x27, [x27, #0xe90]
12023118  stur       x8, [x29, #-8]
1202311c  ldrb       w8, [x27]
12023120  cbz        w8, #0x1202313c
12023124  adrp       x1, #0x12015000
12023128  adrp       x2, #0x12015000
1202312c  add        x1, x1, #0x34a
12023130  add        x2, x2, #0x743
12023134  movz       w0, #0x4
12023138  bl         #0x1204d050
1202313c  ldrb       w8, [x22, #0x58]
12023140  cbz        w8, #0x120231b8
12023144  ldr        x8, [x20]
12023148  mov        x0, x20
1202314c  mov        x1, x19
12023150  mov        x2, xzr
12023154  ldr        x8, [x8, #0x548]
12023158  blr        x8
1202315c  ldrb       w8, [x27]
12023160  mov        x21, x0
12023164  cbz        w8, #0x12023184
12023168  adrp       x1, #0x12015000
1202316c  adrp       x2, #0x12015000
12023170  add        x1, x1, #0x34a
12023174  add        x2, x2, #0xda4
12023178  movz       w0, #0x4
1202317c  mov        x3, x21
12023180  bl         #0x1204d050
12023184  mov        x0, x21
12023188  bl         #0x1204d310
1202318c  cmn        x0, #0x10
12023190  b.hs       #0x120232f8
12023194  mov        x23, x0
12023198  cmp        x0, #0x17
1202319c  b.hs       #0x120231e0
120231a0  mov        x9, sp
120231a4  lsl        w8, w23, #1
120231a8  orr        x24, x9, #1
120231ac  strb       w8, [sp]
120231b0  cbnz       x23, #0x12023200
120231b4  b          #0x12023210
120231b8  ldrb       w8, [x27]
120231bc  cbz        w8, #0x120231d8
120231c0  adrp       x1, #0x12015000
120231c4  adrp       x2, #0x12015000
120231c8  add        x1, x1, #0x34a
120231cc  add        x2, x2, #0xe76
120231d0  movz       w0, #0x4
120231d4  bl         #0x1204d050
120231d8  mov        x22, xzr
120231dc  b          #0x120232c4
120231e0  add        x8, x23, #0x10
120231e4  and        x25, x8, #0xfffffffffffffff0
120231e8  mov        x0, x25
120231ec  bl         #0x1204d060
120231f0  orr        x8, x25, #1
120231f4  mov        x24, x0
120231f8  stp        x23, x0, [sp, #8]
120231fc  str        x8, [sp]
12023200  mov        x0, x24
12023204  mov        x1, x21
12023208  mov        x2, x23
1202320c  bl         #0x1204d120
12023210  add        x0, x22, #0x28
12023214  mov        x1, sp
12023218  strb       wzr, [x24, x23]
1202321c  bl         #0x1204d320
12023220  ldrb       w8, [x27]
12023224  add        x9, x22, #0x30
12023228  cmp        x9, x0
1202322c  b.eq       #0x1202327c
12023230  mov        x23, x0
12023234  cbz        w8, #0x12023250
12023238  adrp       x1, #0x12015000
1202323c  adrp       x2, #0x12015000
12023240  add        x1, x1, #0x34a
12023244  add        x2, x2, #0xe87
12023248  movz       w0, #0x4
1202324c  bl         #0x1204d050
12023250  ldrb       w8, [x23, #0x38]
12023254  add        x11, x23, #0x39
12023258  ldr        x9, [x23, #0x48]
1202325c  mov        x0, x20
12023260  ldr        x10, [x20]
12023264  tst        w8, #1
12023268  csel       x1, x11, x9, eq
1202326c  ldr        x8, [x10, #0x538]
12023270  blr        x8
12023274  mov        x22, x0
12023278  b          #0x1202329c
1202327c  cbz        w8, #0x12023298
12023280  adrp       x1, #0x12015000
12023284  adrp       x2, #0x12015000
12023288  add        x1, x1, #0x34a
1202328c  add        x2, x2, #0xd14
12023290  movz       w0, #0x4
12023294  bl         #0x1204d050
12023298  mov        x22, xzr
1202329c  ldr        x8, [x20]
120232a0  mov        x0, x20
120232a4  mov        x1, x19
120232a8  mov        x2, x21
120232ac  ldr        x8, [x8, #0x550]
120232b0  blr        x8
120232b4  ldrb       w8, [sp]
120232b8  tbz        w8, #0, #0x120232c4
120232bc  ldr        x0, [sp, #0x10]
120232c0  bl         #0x1204d0f0
120232c4  ldr        x8, [x26, #0x28]
120232c8  ldur       x9, [x29, #-8]
120232cc  cmp        x8, x9
120232d0  b.ne       #0x12023300
120232d4  mov        x0, x22
120232d8  ldr        x27, [sp, #0x30]
120232dc  ldp        x20, x19, [sp, #0x70]
120232e0  ldp        x22, x21, [sp, #0x60]
120232e4  ldp        x24, x23, [sp, #0x50]
120232e8  ldp        x26, x25, [sp, #0x40]
120232ec  ldp        x29, x30, [sp, #0x20]
120232f0  add        sp, sp, #0x80
120232f4  ret        

================================================================================
## _ZN18CNativeConfigStore9getConfigEP7_JNIEnvP8_jstring
## base+0x230dc
================================================================================
120230dc  sub        sp, sp, #0x80
120230e0  stp        x29, x30, [sp, #0x20]
120230e4  add        x29, sp, #0x20
120230e8  str        x27, [sp, #0x30]
120230ec  stp        x26, x25, [sp, #0x40]
120230f0  stp        x24, x23, [sp, #0x50]
120230f4  stp        x22, x21, [sp, #0x60]
120230f8  stp        x20, x19, [sp, #0x70]
120230fc  adrp       x27, #0x12051000
12023100  mrs        x26, tpidr_el0
12023104  ldr        x8, [x26, #0x28]
12023108  mov        x19, x2
1202310c  mov        x20, x1
12023110  mov        x22, x0
12023114  ldr        x27, [x27, #0xe90]
12023118  stur       x8, [x29, #-8]
1202311c  ldrb       w8, [x27]
12023120  cbz        w8, #0x1202313c
12023124  adrp       x1, #0x12015000
12023128  adrp       x2, #0x12015000
1202312c  add        x1, x1, #0x34a
12023130  add        x2, x2, #0x743
12023134  movz       w0, #0x4
12023138  bl         #0x1204d050
1202313c  ldrb       w8, [x22, #0x58]
12023140  cbz        w8, #0x120231b8
12023144  ldr        x8, [x20]
12023148  mov        x0, x20
1202314c  mov        x1, x19
12023150  mov        x2, xzr
12023154  ldr        x8, [x8, #0x548]
12023158  blr        x8
1202315c  ldrb       w8, [x27]
12023160  mov        x21, x0
12023164  cbz        w8, #0x12023184
12023168  adrp       x1, #0x12015000
1202316c  adrp       x2, #0x12015000
12023170  add        x1, x1, #0x34a
12023174  add        x2, x2, #0xda4
12023178  movz       w0, #0x4
1202317c  mov        x3, x21
12023180  bl         #0x1204d050
12023184  mov        x0, x21
12023188  bl         #0x1204d310
1202318c  cmn        x0, #0x10
12023190  b.hs       #0x120232f8
12023194  mov        x23, x0
12023198  cmp        x0, #0x17
1202319c  b.hs       #0x120231e0
120231a0  mov        x9, sp
120231a4  lsl        w8, w23, #1
120231a8  orr        x24, x9, #1
120231ac  strb       w8, [sp]
120231b0  cbnz       x23, #0x12023200
120231b4  b          #0x12023210
120231b8  ldrb       w8, [x27]
120231bc  cbz        w8, #0x120231d8
120231c0  adrp       x1, #0x12015000
120231c4  adrp       x2, #0x12015000
120231c8  add        x1, x1, #0x34a
120231cc  add        x2, x2, #0xe76
120231d0  movz       w0, #0x4
120231d4  bl         #0x1204d050
120231d8  mov        x22, xzr
120231dc  b          #0x120232c4
120231e0  add        x8, x23, #0x10
120231e4  and        x25, x8, #0xfffffffffffffff0
120231e8  mov        x0, x25
120231ec  bl         #0x1204d060
120231f0  orr        x8, x25, #1
120231f4  mov        x24, x0
120231f8  stp        x23, x0, [sp, #8]
120231fc  str        x8, [sp]
12023200  mov        x0, x24
12023204  mov        x1, x21
12023208  mov        x2, x23
1202320c  bl         #0x1204d120
12023210  add        x0, x22, #0x28
12023214  mov        x1, sp
12023218  strb       wzr, [x24, x23]
1202321c  bl         #0x1204d320
12023220  ldrb       w8, [x27]
12023224  add        x9, x22, #0x30
12023228  cmp        x9, x0
1202322c  b.eq       #0x1202327c
12023230  mov        x23, x0
12023234  cbz        w8, #0x12023250
12023238  adrp       x1, #0x12015000
1202323c  adrp       x2, #0x12015000
12023240  add        x1, x1, #0x34a
12023244  add        x2, x2, #0xe87
12023248  movz       w0, #0x4
1202324c  bl         #0x1204d050
12023250  ldrb       w8, [x23, #0x38]
12023254  add        x11, x23, #0x39
12023258  ldr        x9, [x23, #0x48]
1202325c  mov        x0, x20
12023260  ldr        x10, [x20]
12023264  tst        w8, #1
12023268  csel       x1, x11, x9, eq
1202326c  ldr        x8, [x10, #0x538]
12023270  blr        x8
12023274  mov        x22, x0
12023278  b          #0x1202329c
1202327c  cbz        w8, #0x12023298
12023280  adrp       x1, #0x12015000
12023284  adrp       x2, #0x12015000
12023288  add        x1, x1, #0x34a
1202328c  add        x2, x2, #0xd14
12023290  movz       w0, #0x4
12023294  bl         #0x1204d050
12023298  mov        x22, xzr
1202329c  ldr        x8, [x20]
120232a0  mov        x0, x20
120232a4  mov        x1, x19
120232a8  mov        x2, x21
120232ac  ldr        x8, [x8, #0x550]
120232b0  blr        x8
120232b4  ldrb       w8, [sp]
120232b8  tbz        w8, #0, #0x120232c4
120232bc  ldr        x0, [sp, #0x10]
120232c0  bl         #0x1204d0f0
120232c4  ldr        x8, [x26, #0x28]
120232c8  ldur       x9, [x29, #-8]
120232cc  cmp        x8, x9
120232d0  b.ne       #0x12023300
120232d4  mov        x0, x22
120232d8  ldr        x27, [sp, #0x30]
120232dc  ldp        x20, x19, [sp, #0x70]
120232e0  ldp        x22, x21, [sp, #0x60]
120232e4  ldp        x24, x23, [sp, #0x50]
120232e8  ldp        x26, x25, [sp, #0x40]
120232ec  ldp        x29, x30, [sp, #0x20]
120232f0  add        sp, sp, #0x80
120232f4  ret        
120232f8  mov        x0, sp
120232fc  bl         #0x1204d270
12023300  bl         #0x1204d080
12023304  sub        sp, sp, #0xe0
12023308  stp        x29, x30, [sp, #0x80]
1202330c  add        x29, sp, #0x80
12023310  stp        x28, x27, [sp, #0x90]
12023314  stp        x26, x25, [sp, #0xa0]
12023318  stp        x24, x23, [sp, #0xb0]
1202331c  stp        x22, x21, [sp, #0xc0]
12023320  stp        x20, x19, [sp, #0xd0]
12023324  adrp       x26, #0x12051000
12023328  mrs        x24, tpidr_el0
1202332c  ldr        x8, [x24, #0x28]
12023330  mov        x20, x2
12023334  mov        x19, x1
12023338  mov        x22, x0
1202333c  ldr        x26, [x26, #0xe90]
12023340  stur       x8, [x29, #-8]
12023344  ldrb       w8, [x26]
12023348  cbz        w8, #0x12023364
1202334c  adrp       x1, #0x12015000
12023350  adrp       x2, #0x12015000
12023354  add        x1, x1, #0x34a
12023358  add        x2, x2, #0x591
1202335c  movz       w0, #0x4
12023360  bl         #0x1204d050
12023364  ldrb       w8, [x22, #0x58]
12023368  cbz        w8, #0x120233bc
1202336c  ldr        x8, [x19]
12023370  mov        x0, x19
12023374  mov        x1, x20
12023378  mov        x2, xzr
1202337c  ldr        x8, [x8, #0x548]
12023380  blr        x8
12023384  mov        x21, x0
12023388  bl         #0x1204d310
1202338c  cmn        x0, #0x10
12023390  b.hs       #0x12023734
12023394  mov        x23, x0
12023398  cmp        x0, #0x17
1202339c  str        x24, [sp, #8]
120233a0  b.hs       #0x120233e4
120233a4  sub        x9, x29, #0x28
120233a8  lsl        w8, w23, #1
120233ac  orr        x24, x9, #1
120233b0  sturb      w8, [x29, #-0x28]
120233b4  cbnz       x23, #0x12023404
120233b8  b          #0x12023414
120233bc  ldrb       w8, [x26]
120233c0  cbz        w8, #0x1202372c
120233c4  adrp       x1, #0x12015000
120233c8  adrp       x2, #0x12015000
120233cc  add        x1, x1, #0x34a
120233d0  add        x2, x2, #0xe76
120233d4  movz       w0, #0x4
120233d8  bl         #0x1204d050
120233dc  mov        x20, xzr
120233e0  b          #0x120236f8
120233e4  add        x8, x23, #0x10
120233e8  and        x25, x8, #0xfffffffffffffff0
120233ec  mov        x0, x25
120233f0  bl         #0x1204d060
120233f4  orr        x8, x25, #1
120233f8  mov        x24, x0
120233fc  stp        x23, x0, [x29, #-0x20]
12023400  stur       x8, [x29, #-0x28]
12023404  mov        x0, x24
12023408  mov        x1, x21
1202340c  mov        x2, x23
12023410  bl         #0x1204d120
12023414  ldrb       w8, [x26]
12023418  strb       wzr, [x24, x23]
1202341c  cbz        w8, #0x1202343c
12023420  adrp       x1, #0x12015000
12023424  adrp       x2, #0x12015000
12023428  add        x1, x1, #0x34a
1202342c  add        x2, x2, #0x74d
12023430  movz       w0, #0x4
12023434  mov        x3, x21
12023438  bl         #0x1204d050
1202343c  add        x8, sp, #0x40
12023440  ldr        x26, [x22, #0x28]
12023444  add        x25, x8, #8
12023448  add        x27, x22, #0x30
1202344c  stp        xzr, xzr, [sp, #0x48]
12023450  cmp        x26, x27
12023454  str        x25, [sp, #0x40]
12023458  b.eq       #0x120235d8
1202345c  sub        x8, x29, #0x28
12023460  add        x9, sp, #0x10
12023464  orr        x28, x8, #1
12023468  add        x22, x9, #0x18
1202346c  b          #0x1202347c
12023470  mov        x26, x9
12023474  cmp        x26, x27
12023478  b.eq       #0x120235d8
1202347c  ldurb      w8, [x29, #-0x28]
12023480  add        x23, x26, #0x20
12023484  ldp        x9, x10, [x29, #-0x20]
12023488  mov        x0, x23
1202348c  mov        x1, xzr
12023490  lsr        x11, x8, #1
12023494  tst        w8, #1
12023498  csel       x2, x11, x9, eq
1202349c  csel       x3, x28, x10, eq
120234a0  mov        x4, x2
120234a4  bl         #0x1204d330
120234a8  cbnz       w0, #0x120234f8
120234ac  add        x0, sp, #0x10
120234b0  mov        x1, x23
120234b4  add        x24, x26, #0x38
120234b8  bl         #0x1204d340
120234bc  mov        x0, x22
120234c0  mov        x1, x24
120234c4  bl         #0x1204d340
120234c8  add        x0, sp, #0x40
120234cc  sub        x1, x29, #0x10
120234d0  add        x2, sp, #0x10
120234d4  bl         #0x1204d350
120234d8  ldr        x8, [x0]
120234dc  cbz        x8, #0x12023540
120234e0  ldrb       w8, [sp, #0x28]
120234e4  tbnz       w8, #0, #0x120235c4
120234e8  ldrb       w8, [sp, #0x10]
120234ec  tbz        w8, #0, #0x120234f8
120234f0  ldr        x0, [sp, #0x20]
120234f4  bl         #0x1204d0f0
120234f8  ldr        x8, [x26, #8]
120234fc  cbz        x8, #0x12023510
12023500  mov        x26, x8
12023504  ldr        x8, [x8]
12023508  cbnz       x8, #0x12023500
1202350c  b          #0x12023474
12023510  mov        x8, x26
12023514  ldr        x9, [x8, #0x10]!
12023518  ldr        x10, [x9]
1202351c  cmp        x10, x26
12023520  b.eq       #0x12023470
12023524  ldr        x9, [x8]
12023528  mov        x8, x9
1202352c  ldr        x26, [x8, #0x10]!
12023530  ldr        x10, [x26]
12023534  cmp        x10, x9
12023538  b.ne       #0x12023524
1202353c  b          #0x12023474
12023540  mov        x23, x0
12023544  movz       w0, #0x50
12023548  bl         #0x1204d060
1202354c  ldr        x8, [sp, #0x20]
12023550  str        xzr, [sp, #0x20]
12023554  ldr        q0, [sp, #0x10]
12023558  stp        xzr, xzr, [sp, #0x10]
1202355c  stp        xzr, xzr, [x0]
12023560  str        x8, [x0, #0x30]
12023564  ldr        x8, [x22, #0x10]
12023568  str        q0, [x0, #0x20]
1202356c  ldr        q0, [x22]
12023570  stp        xzr, xzr, [x22]
12023574  str        x8, [x0, #0x48]
12023578  ldur       x8, [x29, #-0x10]
1202357c  stur       q0, [x0, #0x38]
12023580  str        xzr, [x22, #0x10]
12023584  str        x8, [x0, #0x10]
12023588  str        x0, [x23]
1202358c  ldr        x8, [sp, #0x40]
12023590  ldr        x8, [x8]
12023594  cbz        x8, #0x120235a4
12023598  str        x8, [sp, #0x40]
1202359c  ldr        x1, [x23]
120235a0  b          #0x120235a8
120235a4  mov        x1, x0
120235a8  ldr        x0, [sp, #0x48]
120235ac  bl         #0x1204d360
120235b0  ldr        x8, [sp, #0x50]
120235b4  add        x8, x8, #1
120235b8  str        x8, [sp, #0x50]
120235bc  ldrb       w8, [sp, #0x28]
120235c0  tbz        w8, #0, #0x120234e8
120235c4  ldr        x0, [sp, #0x38]
120235c8  bl         #0x1204d0f0
120235cc  ldrb       w8, [sp, #0x10]
120235d0  tbnz       w8, #0, #0x120234f0
120235d4  b          #0x120234f8
120235d8  ldr        x8, [x19]
120235dc  mov        x0, x19
120235e0  mov        x1, x20
120235e4  mov        x2, x21
120235e8  ldr        x8, [x8, #0x550]
120235ec  blr        x8
120235f0  ldr        x8, [x19]
120235f4  adrp       x1, #0x12015000
120235f8  add        x1, x1, #0x446
120235fc  mov        x0, x19
12023600  ldr        w20, [sp, #0x50]
12023604  ldr        x8, [x8, #0x30]
12023608  blr        x8
1202360c  ldr        x8, [x19]
12023610  mov        x2, x0
12023614  mov        x0, x19
12023618  mov        w1, w20
1202361c  mov        x3, xzr
12023620  ldr        x8, [x8, #0x560]
12023624  blr        x8
12023628  ldr        x22, [sp, #0x40]
1202362c  mov        x20, x0
12023630  cmp        x22, x25
12023634  b.eq       #0x120236d8
12023638  mov        w21, wzr
1202363c  b          #0x12023650
12023640  mov        x22, x9
12023644  add        w21, w21, #1
12023648  cmp        x22, x25
1202364c  b.eq       #0x120236d8
12023650  ldrb       w8, [x22, #0x38]
12023654  add        x11, x22, #0x39
12023658  ldr        x9, [x22, #0x48]
1202365c  mov        x0, x19
12023660  ldr        x10, [x19]
12023664  tst        w8, #1
12023668  csel       x1, x11, x9, eq
1202366c  ldr        x8, [x10, #0x538]
12023670  blr        x8
12023674  ldr        x8, [x19]
12023678  mov        x3, x0
1202367c  mov        x0, x19
12023680  mov        x1, x20
12023684  mov        w2, w21
12023688  ldr        x8, [x8, #0x570]
1202368c  blr        x8
12023690  ldr        x8, [x22, #8]
12023694  cbz        x8, #0x120236a8
12023698  mov        x22, x8
1202369c  ldr        x8, [x8]
120236a0  cbnz       x8, #0x12023698
120236a4  b          #0x12023644
120236a8  mov        x8, x22
120236ac  ldr        x9, [x8, #0x10]!
120236b0  ldr        x10, [x9]
120236b4  cmp        x10, x22
120236b8  b.eq       #0x12023640
120236bc  ldr        x9, [x8]
120236c0  mov        x8, x9
120236c4  ldr        x22, [x8, #0x10]!
120236c8  ldr        x10, [x22]
120236cc  cmp        x10, x9
120236d0  b.ne       #0x120236bc
120236d4  b          #0x12023644
120236d8  ldr        x1, [sp, #0x48]
120236dc  add        x0, sp, #0x40
120236e0  bl         #0x1204d100
120236e4  ldurb      w8, [x29, #-0x28]
120236e8  tbz        w8, #0, #0x120236f4
120236ec  ldur       x0, [x29, #-0x18]
120236f0  bl         #0x1204d0f0
120236f4  ldr        x24, [sp, #8]
120236f8  ldr        x8, [x24, #0x28]
120236fc  ldur       x9, [x29, #-8]
12023700  cmp        x8, x9
12023704  b.ne       #0x1202373c
12023708  mov        x0, x20
1202370c  ldp        x20, x19, [sp, #0xd0]
12023710  ldp        x22, x21, [sp, #0xc0]
12023714  ldp        x24, x23, [sp, #0xb0]
12023718  ldp        x26, x25, [sp, #0xa0]
1202371c  ldp        x28, x27, [sp, #0x90]
12023720  ldp        x29, x30, [sp, #0x80]
12023724  add        sp, sp, #0xe0
12023728  ret        

================================================================================
## _ZN18CNativeConfigStore9setConfigEP7_JNIEnvP8_jstringS3_
## base+0x23740
================================================================================
12023740  sub        sp, sp, #0xe0
12023744  stp        x29, x30, [sp, #0x80]
12023748  add        x29, sp, #0x80
1202374c  stp        x28, x27, [sp, #0x90]
12023750  stp        x26, x25, [sp, #0xa0]
12023754  stp        x24, x23, [sp, #0xb0]
12023758  stp        x22, x21, [sp, #0xc0]
1202375c  stp        x20, x19, [sp, #0xd0]
12023760  adrp       x24, #0x12051000
12023764  mrs        x28, tpidr_el0
12023768  ldr        x8, [x28, #0x28]
1202376c  mov        x19, x3
12023770  mov        x22, x2
12023774  mov        x21, x1
12023778  ldr        x24, [x24, #0xe90]
1202377c  mov        x20, x0
12023780  stur       x8, [x29, #-8]
12023784  ldrb       w8, [x24]
12023788  cbz        w8, #0x120237a4
1202378c  adrp       x1, #0x12015000
12023790  adrp       x2, #0x12015000
12023794  add        x1, x1, #0x34a
12023798  add        x2, x2, #0xa4b
1202379c  movz       w0, #0x4
120237a0  bl         #0x1204d050
120237a4  ldrb       w8, [x20, #0x58]
120237a8  cbz        w8, #0x12023854
120237ac  stur       xzr, [x29, #-0x18]
120237b0  cbz        x22, #0x12023a94
120237b4  ldr        x8, [x21]
120237b8  mov        x0, x21
120237bc  mov        x1, x22
120237c0  mov        x2, xzr
120237c4  ldr        x8, [x8, #0x548]
120237c8  blr        x8
120237cc  mov        x23, x0
120237d0  stur       x0, [x29, #-0x18]
120237d4  stur       xzr, [x29, #-0x20]
120237d8  cbz        x19, #0x12023aa0
120237dc  ldr        x8, [x21]
120237e0  mov        x0, x21
120237e4  mov        x1, x19
120237e8  mov        x2, xzr
120237ec  ldr        x8, [x8, #0x548]
120237f0  blr        x8
120237f4  mov        x4, x0
120237f8  stur       x0, [x29, #-0x20]
120237fc  ldrb       w8, [x24]
12023800  cbz        w8, #0x12023820
12023804  adrp       x1, #0x12015000
12023808  adrp       x2, #0x12015000
1202380c  add        x1, x1, #0x34a
12023810  add        x2, x2, #0x674
12023814  movz       w0, #0x4
12023818  mov        x3, x23
1202381c  bl         #0x1204d050
12023820  mov        x0, x23
12023824  bl         #0x1204d310
12023828  cmn        x0, #0x10
1202382c  b.hs       #0x12023b50
12023830  mov        x24, x0
12023834  cmp        x0, #0x17
12023838  b.hs       #0x1202387c
1202383c  sub        x9, x29, #0x38
12023840  lsl        w8, w24, #1
12023844  orr        x26, x9, #1
12023848  sturb      w8, [x29, #-0x38]
1202384c  cbnz       x24, #0x1202389c
12023850  b          #0x120238ac
12023854  ldrb       w8, [x24]
12023858  cbz        w8, #0x12023874
1202385c  adrp       x1, #0x12015000
12023860  adrp       x2, #0x12015000
12023864  add        x1, x1, #0x34a
12023868  add        x2, x2, #0xe76
1202386c  movz       w0, #0x4
12023870  bl         #0x1204d050
12023874  movn       w19, #0
12023878  b          #0x12023a60
1202387c  add        x8, x24, #0x10
12023880  and        x25, x8, #0xfffffffffffffff0
12023884  mov        x0, x25
12023888  bl         #0x1204d060
1202388c  orr        x8, x25, #1
12023890  mov        x26, x0
12023894  stp        x24, x0, [x29, #-0x30]
12023898  stur       x8, [x29, #-0x38]
1202389c  mov        x0, x26
120238a0  mov        x1, x23
120238a4  mov        x2, x24
120238a8  bl         #0x1204d120
120238ac  ldur       x25, [x29, #-0x20]
120238b0  strb       wzr, [x26, x24]
120238b4  mov        x0, x25
120238b8  bl         #0x1204d310
120238bc  cmn        x0, #0x10
120238c0  b.hs       #0x12023b58
120238c4  mov        x23, x0
120238c8  cmp        x0, #0x17
120238cc  b.hs       #0x120238e8
120238d0  add        x9, sp, #0x30
120238d4  lsl        w8, w23, #1
120238d8  orr        x24, x9, #1
120238dc  strb       w8, [sp, #0x30]
120238e0  cbnz       x23, #0x12023908
120238e4  b          #0x12023918
120238e8  add        x8, x23, #0x10
120238ec  and        x26, x8, #0xfffffffffffffff0
120238f0  mov        x0, x26
120238f4  bl         #0x1204d060
120238f8  orr        x8, x26, #1
120238fc  mov        x24, x0
12023900  stp        x23, x0, [sp, #0x38]
12023904  str        x8, [sp, #0x30]
12023908  mov        x0, x24
1202390c  mov        x1, x25
12023910  mov        x2, x23
12023914  bl         #0x1204d120
12023918  ldur       x25, [x29, #-0x18]
1202391c  strb       wzr, [x24, x23]
12023920  mov        x0, x25
12023924  bl         #0x1204d310
12023928  cmn        x0, #0x10
1202392c  b.hs       #0x12023b60
12023930  mov        x24, x0
12023934  add        x23, x20, #0x28
12023938  cmp        x0, #0x17
1202393c  b.hs       #0x12023958
12023940  mov        x9, sp
12023944  lsl        w8, w24, #1
12023948  orr        x26, x9, #1
1202394c  strb       w8, [sp]
12023950  cbnz       x24, #0x12023978
12023954  b          #0x12023988
12023958  add        x8, x24, #0x10
1202395c  and        x27, x8, #0xfffffffffffffff0
12023960  mov        x0, x27
12023964  bl         #0x1204d060
12023968  orr        x8, x27, #1
1202396c  mov        x26, x0
12023970  stp        x24, x0, [sp, #8]
12023974  str        x8, [sp]
12023978  mov        x0, x26
1202397c  mov        x1, x25
12023980  mov        x2, x24
12023984  bl         #0x1204d120
12023988  mov        x1, sp
1202398c  mov        x0, x23
12023990  strb       wzr, [x26, x24]
12023994  bl         #0x1204d320
12023998  ldrb       w8, [sp]
1202399c  mov        x24, x0
120239a0  tbz        w8, #0, #0x120239ac
120239a4  ldr        x0, [sp, #0x10]
120239a8  bl         #0x1204d0f0
120239ac  add        x8, x20, #0x30
120239b0  cmp        x8, x24
120239b4  b.eq       #0x120239c4
120239b8  mov        x0, x23
120239bc  mov        x1, x24
120239c0  bl         #0x1204d370
120239c4  mov        x0, sp
120239c8  sub        x1, x29, #0x18
120239cc  sub        x2, x29, #0x20
120239d0  bl         #0x1204d380
120239d4  sub        x1, x29, #0x10
120239d8  mov        x2, sp
120239dc  mov        x0, x23
120239e0  bl         #0x1204d350
120239e4  ldr        x8, [x0]
120239e8  cbz        x8, #0x12023ab0
120239ec  ldrb       w8, [sp, #0x18]
120239f0  tbnz       w8, #0, #0x12023b30
120239f4  ldrb       w8, [sp]
120239f8  tbnz       w8, #0, #0x12023b40
120239fc  cbz        x22, #0x12023a18
12023a00  ldr        x8, [x21]
12023a04  mov        x0, x21
12023a08  ldur       x2, [x29, #-0x18]
12023a0c  mov        x1, x22
12023a10  ldr        x8, [x8, #0x550]
12023a14  blr        x8
12023a18  cbz        x19, #0x12023a34
12023a1c  ldr        x8, [x21]
12023a20  mov        x0, x21
12023a24  ldur       x2, [x29, #-0x20]
12023a28  mov        x1, x19
12023a2c  ldr        x8, [x8, #0x550]
12023a30  blr        x8
12023a34  mov        x0, x20
12023a38  bl         #0x1204d260
12023a3c  ldrb       w8, [sp, #0x30]
12023a40  mov        w19, w0
12023a44  tbz        w8, #0, #0x12023a50
12023a48  ldr        x0, [sp, #0x40]
12023a4c  bl         #0x1204d0f0
12023a50  ldurb      w8, [x29, #-0x38]
12023a54  tbz        w8, #0, #0x12023a60
12023a58  ldur       x0, [x29, #-0x28]
12023a5c  bl         #0x1204d0f0
12023a60  ldr        x8, [x28, #0x28]
12023a64  ldur       x9, [x29, #-8]
12023a68  cmp        x8, x9
12023a6c  b.ne       #0x12023b68
12023a70  mov        w0, w19
12023a74  ldp        x20, x19, [sp, #0xd0]
12023a78  ldp        x22, x21, [sp, #0xc0]
12023a7c  ldp        x24, x23, [sp, #0xb0]
12023a80  ldp        x26, x25, [sp, #0xa0]
12023a84  ldp        x28, x27, [sp, #0x90]
12023a88  ldp        x29, x30, [sp, #0x80]
12023a8c  add        sp, sp, #0xe0
12023a90  ret        
12023a94  mov        x23, xzr
12023a98  stur       xzr, [x29, #-0x20]
12023a9c  cbnz       x19, #0x120237dc
12023aa0  mov        x4, xzr
12023aa4  ldrb       w8, [x24]
12023aa8  cbnz       w8, #0x12023804
12023aac  b          #0x12023820
12023ab0  mov        x24, x0
12023ab4  movz       w0, #0x50
12023ab8  bl         #0x1204d060
12023abc  ldr        x8, [sp, #0x10]
12023ac0  stp        xzr, xzr, [x0]
12023ac4  ldr        q0, [sp]
12023ac8  stp        xzr, xzr, [sp]
12023acc  str        x8, [x0, #0x30]
12023ad0  ldr        x8, [sp, #0x28]
12023ad4  str        q0, [x0, #0x20]
12023ad8  ldur       q0, [sp, #0x18]
12023adc  stp        xzr, xzr, [sp, #0x10]
12023ae0  str        x8, [x0, #0x48]
12023ae4  ldur       x8, [x29, #-0x10]
12023ae8  stur       q0, [x0, #0x38]
12023aec  stp        xzr, xzr, [sp, #0x20]
12023af0  str        x8, [x0, #0x10]
12023af4  str        x0, [x24]
12023af8  ldr        x8, [x23]
12023afc  ldr        x8, [x8]
12023b00  cbz        x8, #0x12023b10
12023b04  str        x8, [x23]
12023b08  ldr        x1, [x24]
12023b0c  b          #0x12023b14
12023b10  mov        x1, x0
12023b14  ldr        x0, [x20, #0x30]
12023b18  bl         #0x1204d360
12023b1c  ldr        x8, [x20, #0x38]
12023b20  add        x8, x8, #1
12023b24  str        x8, [x20, #0x38]
12023b28  ldrb       w8, [sp, #0x18]
12023b2c  tbz        w8, #0, #0x120239f4
12023b30  ldr        x0, [sp, #0x28]
12023b34  bl         #0x1204d0f0
12023b38  ldrb       w8, [sp]
12023b3c  tbz        w8, #0, #0x120239fc
12023b40  ldr        x0, [sp, #0x10]
12023b44  bl         #0x1204d0f0
12023b48  cbnz       x22, #0x12023a00
12023b4c  b          #0x12023a18
12023b50  sub        x0, x29, #0x38
12023b54  bl         #0x1204d270
12023b58  add        x0, sp, #0x30
12023b5c  bl         #0x1204d270
12023b60  mov        x0, sp
12023b64  bl         #0x1204d270
12023b68  bl         #0x1204d080
12023b6c  stp        x29, x30, [sp, #-0x40]!
12023b70  stp        x24, x23, [sp, #0x10]
12023b74  mov        x29, sp
12023b78  stp        x22, x21, [sp, #0x20]
12023b7c  stp        x20, x19, [sp, #0x30]
12023b80  ldr        x22, [x1]
12023b84  mov        x19, x0
12023b88  mov        x20, x2
12023b8c  mov        x0, x22
12023b90  bl         #0x1204d310
12023b94  cmn        x0, #0x10
12023b98  b.hs       #0x12023c6c
12023b9c  mov        x21, x0
12023ba0  cmp        x0, #0x17
12023ba4  b.hs       #0x12023bbc
12023ba8  lsl        w8, w21, #1
12023bac  mov        x23, x19
12023bb0  strb       w8, [x23], #1
12023bb4  cbnz       x21, #0x12023bdc
12023bb8  b          #0x12023bec
12023bbc  add        x8, x21, #0x10
12023bc0  and        x24, x8, #0xfffffffffffffff0
12023bc4  mov        x0, x24
12023bc8  bl         #0x1204d060
12023bcc  orr        x8, x24, #1
12023bd0  mov        x23, x0
12023bd4  stp        x21, x0, [x19, #8]
12023bd8  str        x8, [x19]
12023bdc  mov        x0, x23
12023be0  mov        x1, x22
12023be4  mov        x2, x21
12023be8  bl         #0x1204d120
12023bec  strb       wzr, [x23, x21]
12023bf0  add        x21, x19, #0x18
12023bf4  ldr        x22, [x20]
12023bf8  mov        x0, x22
12023bfc  bl         #0x1204d310
12023c00  cmn        x0, #0x10
12023c04  b.hs       #0x12023c74
12023c08  mov        x20, x0
12023c0c  cmp        x0, #0x17
12023c10  b.hs       #0x12023c24
12023c14  lsl        w8, w20, #1
12023c18  strb       w8, [x21], #1
12023c1c  cbnz       x20, #0x12023c44
12023c20  b          #0x12023c54
12023c24  add        x8, x20, #0x10
12023c28  and        x23, x8, #0xfffffffffffffff0
12023c2c  mov        x0, x23
12023c30  bl         #0x1204d060
12023c34  orr        x8, x23, #1
12023c38  mov        x21, x0
12023c3c  stp        x20, x0, [x19, #0x20]
12023c40  str        x8, [x19, #0x18]
12023c44  mov        x0, x21
12023c48  mov        x1, x22
12023c4c  mov        x2, x20
12023c50  bl         #0x1204d120
12023c54  strb       wzr, [x21, x20]
12023c58  ldp        x20, x19, [sp, #0x30]
12023c5c  ldp        x22, x21, [sp, #0x20]
12023c60  ldp        x24, x23, [sp, #0x10]
12023c64  ldp        x29, x30, [sp], #0x40
12023c68  ret        

================================================================================
## _ZN14CConfigStoreSO10SerializeLER13CMSFBufStream
## base+0x23e70
================================================================================
12023e70  sub        sp, sp, #0x50
12023e74  stp        x29, x30, [sp, #0x10]
12023e78  add        x29, sp, #0x10
12023e7c  str        x23, [sp, #0x20]
12023e80  stp        x22, x21, [sp, #0x30]
12023e84  stp        x20, x19, [sp, #0x40]
12023e88  mrs        x21, tpidr_el0
12023e8c  mov        x20, x0
12023e90  ldr        x8, [x21, #0x28]
12023e94  mov        x19, x1
12023e98  movz       w2, #0x4
12023e9c  str        x8, [sp, #8]
12023ea0  ldr        x8, [x0, #0x18]
12023ea4  ldr        x0, [x1, #0x10]
12023ea8  add        x1, sp, #4
12023eac  str        w8, [sp, #4]
12023eb0  bl         #0x1204d130
12023eb4  ldr        w8, [x19, #8]
12023eb8  add        w8, w8, #4
12023ebc  str        w8, [x19, #8]
12023ec0  ldr        x22, [x20, #8]
12023ec4  add        x20, x20, #0x10
12023ec8  b          #0x12023ed0
12023ecc  mov        x22, x9
12023ed0  cmp        x22, x20
12023ed4  b.eq       #0x12023ff0
12023ed8  ldrb       w8, [x22, #0x20]
12023edc  add        x1, sp, #4
12023ee0  ldr        x9, [x22, #0x28]
12023ee4  movz       w2, #0x4
12023ee8  ldr        x0, [x19, #0x10]
12023eec  lsr        x10, x8, #1
12023ef0  tst        w8, #1
12023ef4  csel       x8, x10, x9, eq
12023ef8  str        w8, [sp, #4]
12023efc  bl         #0x1204d130
12023f00  ldr        w8, [x19, #8]
12023f04  add        x11, x22, #0x21
12023f08  ldr        x0, [x19, #0x10]
12023f0c  add        w8, w8, #4
12023f10  str        w8, [x19, #8]
12023f14  ldrb       w8, [x22, #0x20]
12023f18  ldp        x10, x9, [x22, #0x28]
12023f1c  tst        w8, #1
12023f20  lsr        x8, x8, #1
12023f24  csel       x23, x8, x10, eq
12023f28  csel       x1, x11, x9, eq
12023f2c  sxtw       x2, w23
12023f30  bl         #0x1204d130
12023f34  ldr        w8, [x19, #8]
12023f38  add        x1, sp, #4
12023f3c  ldr        x0, [x19, #0x10]
12023f40  movz       w2, #0x4
12023f44  add        w8, w8, w23
12023f48  str        w8, [x19, #8]
12023f4c  ldrb       w8, [x22, #0x38]
12023f50  ldr        x9, [x22, #0x40]
12023f54  lsr        x10, x8, #1
12023f58  tst        w8, #1
12023f5c  csel       x8, x10, x9, eq
12023f60  str        w8, [sp, #4]
12023f64  bl         #0x1204d130
12023f68  ldr        w8, [x19, #8]
12023f6c  add        x11, x22, #0x39
12023f70  ldr        x0, [x19, #0x10]
12023f74  add        w8, w8, #4
12023f78  str        w8, [x19, #8]
12023f7c  ldrb       w8, [x22, #0x38]
12023f80  ldp        x10, x9, [x22, #0x40]
12023f84  tst        w8, #1
12023f88  lsr        x8, x8, #1
12023f8c  csel       x23, x8, x10, eq
12023f90  csel       x1, x11, x9, eq
12023f94  sxtw       x2, w23
12023f98  bl         #0x1204d130
12023f9c  ldr        w8, [x19, #8]
12023fa0  add        w8, w8, w23
12023fa4  str        w8, [x19, #8]
12023fa8  ldr        x8, [x22, #8]
12023fac  cbz        x8, #0x12023fc0
12023fb0  mov        x22, x8
12023fb4  ldr        x8, [x8]
12023fb8  cbnz       x8, #0x12023fb0
12023fbc  b          #0x12023ed0
12023fc0  mov        x8, x22
12023fc4  ldr        x9, [x8, #0x10]!
12023fc8  ldr        x10, [x9]
12023fcc  cmp        x10, x22
12023fd0  b.eq       #0x12023ecc
12023fd4  ldr        x9, [x8]
12023fd8  mov        x8, x9
12023fdc  ldr        x22, [x8, #0x10]!
12023fe0  ldr        x10, [x22]
12023fe4  cmp        x10, x9
12023fe8  b.ne       #0x12023fd4
12023fec  b          #0x12023ed0
12023ff0  ldr        x8, [x21, #0x28]
12023ff4  ldr        x9, [sp, #8]
12023ff8  cmp        x8, x9
12023ffc  b.ne       #0x12024018
12024000  ldp        x20, x19, [sp, #0x40]
12024004  ldp        x22, x21, [sp, #0x30]
12024008  ldp        x29, x30, [sp, #0x10]
1202400c  ldr        x23, [sp, #0x20]
12024010  add        sp, sp, #0x50
12024014  ret        
12024018  bl         #0x1204d080
1202401c  ldr        x9, [x0, #8]
12024020  add        x8, x0, #0x10
12024024  movz       w0, #0x4
12024028  b          #0x1202403c
1202402c  mov        x9, x13
12024030  add        w10, w0, w10
12024034  add        w10, w10, w11
12024038  add        w0, w10, #8
1202403c  cmp        x9, x8
12024040  b.eq       #0x120240b4
12024044  ldrb       w10, [x9, #0x20]
12024048  ldr        w11, [x9, #0x28]
1202404c  ldrb       w12, [x9, #0x38]
12024050  ldr        w13, [x9, #0x40]
12024054  lsr        w14, w10, #1
12024058  tst        w10, #1
1202405c  lsr        w15, w12, #1
12024060  csel       w10, w14, w11, eq
12024064  tst        w12, #1
12024068  ldr        x12, [x9, #8]
1202406c  csel       w11, w15, w13, eq
12024070  cbz        x12, #0x12024084
12024074  mov        x9, x12
12024078  ldr        x12, [x12]
1202407c  cbnz       x12, #0x12024074
12024080  b          #0x12024030
12024084  mov        x12, x9
12024088  ldr        x13, [x12, #0x10]!
1202408c  ldr        x14, [x13]
12024090  cmp        x14, x9
12024094  b.eq       #0x1202402c
12024098  ldr        x13, [x12]
1202409c  mov        x12, x13
120240a0  ldr        x9, [x12, #0x10]!
120240a4  ldr        x14, [x9]
120240a8  cmp        x14, x13
120240ac  b.ne       #0x12024098
120240b0  b          #0x12024030
120240b4  ret        

================================================================================
## _ZN14CConfigStoreSO12DeSerializeLER13CMSFBufStream
## base+0x240b8
================================================================================
120240b8  sub        sp, sp, #0xc0
120240bc  stp        x29, x30, [sp, #0x70]
120240c0  add        x29, sp, #0x70
120240c4  stp        x26, x25, [sp, #0x80]
120240c8  stp        x24, x23, [sp, #0x90]
120240cc  stp        x22, x21, [sp, #0xa0]
120240d0  stp        x20, x19, [sp, #0xb0]
120240d4  mrs        x23, tpidr_el0
120240d8  mov        x24, x0
120240dc  ldr        x8, [x23, #0x28]
120240e0  mov        x21, x1
120240e4  mov        x19, x0
120240e8  stur       x8, [x29, #-8]
120240ec  ldr        x1, [x24, #0x10]!
120240f0  sub        x20, x24, #8
120240f4  mov        x0, x20
120240f8  bl         #0x1204d100
120240fc  stp        x24, xzr, [x24, #-8]
12024100  str        xzr, [x24, #8]
12024104  ldr        x8, [x21, #0x10]
12024108  sturh      wzr, [x29, #-0x20]
1202410c  strh       wzr, [sp, #0x38]
12024110  ldrb       w9, [x8]
12024114  ldr        x10, [x8, #0x10]
12024118  tst        w9, #1
1202411c  ldrsw      x9, [x21, #8]
12024120  csinc      x8, x10, x8, ne
12024124  ldr        w26, [x8, x9]
12024128  add        w8, w9, #4
1202412c  str        w8, [x21, #8]
12024130  cmp        w26, #1
12024134  b.lt       #0x12024224
12024138  sub        x1, x29, #0x20
1202413c  mov        x0, x21
12024140  add        x8, sp, #8
12024144  add        x22, x8, #0x18
12024148  bl         #0x1204d390
1202414c  ldurb      w8, [x29, #-0x20]
12024150  ldur       x9, [x29, #-0x18]
12024154  lsr        x10, x8, #1
12024158  tst        w8, #1
1202415c  csel       x25, x10, x9, eq
12024160  add        x1, sp, #0x38
12024164  mov        x0, x21
12024168  bl         #0x1204d390
1202416c  add        x0, sp, #8
12024170  sub        x1, x29, #0x20
12024174  bl         #0x1204d340
12024178  add        x1, sp, #0x38
1202417c  mov        x0, x22
12024180  bl         #0x1204d340
12024184  add        x1, sp, #8
12024188  add        x2, sp, #8
1202418c  mov        x0, x20
12024190  bl         #0x1204d3a0
12024194  ldrb       w8, [sp, #0x20]
12024198  tbnz       w8, #0, #0x120241d0
1202419c  ldrb       w8, [sp, #8]
120241a0  tbnz       w8, #0, #0x120241e0
120241a4  ldurb      w8, [x29, #-0x20]
120241a8  tbnz       w8, #0, #0x120241f0
120241ac  sturh      wzr, [x29, #-0x20]
120241b0  ldrb       w8, [sp, #0x38]
120241b4  tbz        w8, #0, #0x12024204
120241b8  ldr        x8, [sp, #0x48]
120241bc  strb       wzr, [x8]
120241c0  str        xzr, [sp, #0x40]
120241c4  subs       w26, w26, #1
120241c8  b.ne       #0x12024210
120241cc  b          #0x12024220
120241d0  ldr        x0, [sp, #0x30]
120241d4  bl         #0x1204d0f0
120241d8  ldrb       w8, [sp, #8]
120241dc  tbz        w8, #0, #0x120241a4
120241e0  ldr        x0, [sp, #0x18]
120241e4  bl         #0x1204d0f0
120241e8  ldurb      w8, [x29, #-0x20]
120241ec  tbz        w8, #0, #0x120241ac
120241f0  ldur       x8, [x29, #-0x10]
120241f4  strb       wzr, [x8]
120241f8  stur       xzr, [x29, #-0x18]
120241fc  ldrb       w8, [sp, #0x38]
12024200  tbnz       w8, #0, #0x120241b8
12024204  strh       wzr, [sp, #0x38]
12024208  subs       w26, w26, #1
1202420c  b.eq       #0x12024220
12024210  sub        x1, x29, #0x20
12024214  mov        x0, x21
12024218  bl         #0x1204d390
1202421c  b          #0x12024160
12024220  cbz        x25, #0x12024270
12024224  ldrb       w8, [sp, #0x38]
12024228  tbz        w8, #0, #0x12024234
1202422c  ldr        x0, [sp, #0x48]
12024230  bl         #0x1204d0f0
12024234  ldurb      w8, [x29, #-0x20]
12024238  tbz        w8, #0, #0x12024244
1202423c  ldur       x0, [x29, #-0x10]
12024240  bl         #0x1204d0f0
12024244  ldr        x8, [x23, #0x28]
12024248  ldur       x9, [x29, #-8]
1202424c  cmp        x8, x9
12024250  b.ne       #0x12024290
12024254  ldp        x20, x19, [sp, #0xb0]
12024258  ldp        x22, x21, [sp, #0xa0]
1202425c  ldp        x24, x23, [sp, #0x90]
12024260  ldp        x26, x25, [sp, #0x80]
12024264  ldp        x29, x30, [sp, #0x70]
12024268  add        sp, sp, #0xc0
1202426c  ret        
12024270  ldr        x1, [x19, #0x10]
12024274  mov        x0, x20
12024278  bl         #0x1204d100
1202427c  stp        xzr, xzr, [x19, #0x10]
12024280  str        x24, [x19, #8]
12024284  ldrb       w8, [sp, #0x38]
12024288  tbnz       w8, #0, #0x1202422c
1202428c  b          #0x12024234
12024290  bl         #0x1204d080
12024294  stp        x29, x30, [sp, #-0x20]!
12024298  stp        x20, x19, [sp, #0x10]
1202429c  mov        x29, sp
120242a0  ldr        x8, [x0, #0x10]
120242a4  mov        x20, x0
120242a8  ldrsw      x10, [x0, #8]
120242ac  ldrb       w9, [x8]
120242b0  ldr        x11, [x8, #0x10]
120242b4  tst        w9, #1
120242b8  add        w9, w10, #4
120242bc  csinc      x11, x11, x8, ne
120242c0  ldrsw      x19, [x11, x10]
120242c4  str        w9, [x0, #8]
120242c8  ldrb       w9, [x8]
120242cc  ldr        x10, [x8, #0x10]
120242d0  tst        w9, #1
120242d4  ldrb       w9, [x1]
120242d8  csinc      x8, x10, x8, ne
120242dc  tbnz       w9, #0, #0x120242e8
120242e0  strh       wzr, [x1]
120242e4  b          #0x120242f4
120242e8  ldr        x9, [x1, #0x10]
120242ec  strb       wzr, [x9]
120242f0  str        xzr, [x1, #8]
120242f4  ldr        x9, [x20, #0x10]
120242f8  ldrsw      x4, [x20, #8]
120242fc  ldrb       w10, [x9]
12024300  ldr        w9, [x9, #8]
12024304  lsr        w11, w10, #1
12024308  tst        w10, #1
1202430c  csel       w3, w11, w9, eq
12024310  add        w10, w19, w4
12024314  cmp        w10, w3
12024318  b.le       #0x12024340
1202431c  mov        w5, w19
12024320  adrp       x1, #0x12016000
12024324  ldp        x20, x19, [sp, #0x10]
12024328  adrp       x2, #0x12016000
1202432c  add        x1, x1, #0x69a
12024330  add        x2, x2, #0xab2
12024334  movz       w0, #0x4
12024338  ldp        x29, x30, [sp], #0x20
1202433c  b          #0x1204d050
12024340  add        x8, x8, x4
12024344  mov        x0, x1
12024348  mov        x1, x8
1202434c  mov        x2, x19
12024350  bl         #0x1204d3b0
12024354  ldr        w8, [x20, #8]
12024358  add        w8, w8, w19
1202435c  str        w8, [x20, #8]
12024360  ldp        x20, x19, [sp, #0x10]
12024364  ldp        x29, x30, [sp], #0x20
12024368  ret        

================================================================================
## _ZN12CMSFJavaUtil16IsSignatureValidEP7_JNIEnvP8_jobject
## base+0x25048
================================================================================
12025048  sub        sp, sp, #0xa0
1202504c  stp        x29, x30, [sp, #0x40]
12025050  add        x29, sp, #0x40
12025054  stp        x28, x27, [sp, #0x50]
12025058  stp        x26, x25, [sp, #0x60]
1202505c  stp        x24, x23, [sp, #0x70]
12025060  stp        x22, x21, [sp, #0x80]
12025064  stp        x20, x19, [sp, #0x90]
12025068  adrp       x9, #0x12051000
1202506c  mrs        x22, tpidr_el0
12025070  ldr        x8, [x22, #0x28]
12025074  mov        x20, x1
12025078  mov        x19, x0
1202507c  ldr        x9, [x9, #0xe90]
12025080  stur       x8, [x29, #-8]
12025084  ldrb       w8, [x9]
12025088  cbz        w8, #0x120250a4
1202508c  adrp       x1, #0x12015000
12025090  adrp       x2, #0x12016000
12025094  add        x1, x1, #0x34a
12025098  add        x2, x2, #0x62a
1202509c  movz       w0, #0x4
120250a0  bl         #0x1204d050
120250a4  bl         #0x1204d400
120250a8  adrp       x8, #0x12051000
120250ac  mov        w21, w0
120250b0  ldr        x8, [x8, #0xe90]
120250b4  ldrb       w8, [x8]
120250b8  cbz        w8, #0x120250d8
120250bc  adrp       x1, #0x12015000
120250c0  adrp       x2, #0x12016000
120250c4  add        x1, x1, #0x34a
120250c8  add        x2, x2, #0x2bc
120250cc  movz       w0, #0x4
120250d0  mov        w3, w21
120250d4  bl         #0x1204d050
120250d8  ldr        x8, [x19]
120250dc  mov        x0, x19
120250e0  mov        x1, x20
120250e4  ldr        x8, [x8, #0xf8]
120250e8  blr        x8
120250ec  ldr        x8, [x19]
120250f0  adrp       x2, #0x12015000
120250f4  adrp       x3, #0x12016000
120250f8  mov        x1, x0
120250fc  add        x2, x2, #0xb0d
12025100  add        x3, x3, #0x6c4
12025104  ldr        x8, [x8, #0x108]
12025108  mov        x0, x19
1202510c  blr        x8
12025110  mov        x2, x0
12025114  mov        x0, x19
12025118  mov        x1, x20
1202511c  bl         #0x1204d410
12025120  ldr        x8, [x19]
12025124  mov        x20, x0
12025128  mov        x0, x19
1202512c  mov        x1, x20
12025130  ldr        x8, [x8, #0xf8]
12025134  blr        x8
12025138  ldr        x8, [x19]
1202513c  adrp       x2, #0x12016000
12025140  adrp       x3, #0x12016000
12025144  mov        x1, x0
12025148  add        x2, x2, #0xad8
1202514c  add        x3, x3, #0xb80
12025150  ldr        x8, [x8, #0x108]
12025154  mov        x0, x19
12025158  str        x1, [sp, #0x18]
1202515c  blr        x8
12025160  mov        x2, x0
12025164  mov        x0, x19
12025168  mov        x1, x20
1202516c  mov        w3, w21
12025170  str        x20, [sp, #0x20]
12025174  bl         #0x1204d410
12025178  ldr        x8, [x19]
1202517c  mov        x1, x0
12025180  mov        x0, x19
12025184  ldr        x8, [x8, #0x558]
12025188  str        x1, [sp, #0x10]
1202518c  blr        x8
12025190  cmp        w0, #1
12025194  str        w0, [sp, #0xc]
12025198  b.lt       #0x1202545c
1202519c  adrp       x27, #0x12016000
120251a0  adrp       x28, #0x12015000
120251a4  mov        w24, wzr
120251a8  add        x27, x27, #0x2c5
120251ac  add        x28, x28, #0x7e8
120251b0  str        x22, [sp]
120251b4  b          #0x120251c8
120251b8  ldr        w8, [sp, #0xc]
120251bc  add        w24, w24, #1
120251c0  cmp        w24, w8
120251c4  b.eq       #0x12025490
120251c8  ldr        x8, [x19]
120251cc  mov        x0, x19
120251d0  ldr        x1, [sp, #0x10]
120251d4  mov        w2, w24
120251d8  ldr        x8, [x8, #0x568]
120251dc  blr        x8
120251e0  ldr        x8, [x19]
120251e4  adrp       x2, #0x12015000
120251e8  adrp       x3, #0x12015000
120251ec  mov        x20, x0
120251f0  mov        x0, x19
120251f4  ldr        x1, [sp, #0x18]
120251f8  ldr        x8, [x8, #0x108]
120251fc  add        x2, x2, #0x80b
12025200  add        x3, x3, #0xf15
12025204  blr        x8
12025208  mov        x2, x0
1202520c  mov        x0, x19
12025210  ldr        x1, [sp, #0x20]
12025214  mov        x3, x20
12025218  movz       w4, #0x40
1202521c  bl         #0x1204d410
12025220  ldr        x8, [x19]
12025224  mov        x20, x0
12025228  mov        x0, x19
1202522c  mov        x1, x20
12025230  ldr        x8, [x8, #0xf8]
12025234  blr        x8
12025238  cbz        x0, #0x120251b8
1202523c  ldr        x8, [x19]
12025240  adrp       x2, #0x12015000
12025244  adrp       x3, #0x12015000
12025248  mov        x1, x0
1202524c  mov        x0, x19
12025250  add        x2, x2, #0x457
12025254  ldr        x8, [x8, #0x2f0]
12025258  add        x3, x3, #0xfd6
1202525c  blr        x8
12025260  ldr        x8, [x19]
12025264  mov        x2, x0
12025268  mov        x0, x19
1202526c  mov        x1, x20
12025270  ldr        x8, [x8, #0x2f8]
12025274  blr        x8
12025278  cbz        x0, #0x120251b8
1202527c  ldr        x8, [x19]
12025280  mov        x26, x0
12025284  mov        x0, x19
12025288  mov        x1, x26
1202528c  ldr        x8, [x8, #0x558]
12025290  blr        x8
12025294  cmp        w0, #1
12025298  b.lt       #0x120251b8
1202529c  mov        w25, w0
120252a0  mov        w21, wzr
120252a4  b          #0x120252b4
120252a8  add        w21, w21, #1
120252ac  cmp        w25, w21
120252b0  b.eq       #0x120251b8
120252b4  ldr        x8, [x19]
120252b8  mov        x0, x19
120252bc  mov        x1, x26
120252c0  mov        w2, w21
120252c4  ldr        x8, [x8, #0x568]
120252c8  blr        x8
120252cc  ldr        x8, [x19]
120252d0  mov        x20, x0
120252d4  mov        x0, x19
120252d8  mov        x1, x20
120252dc  ldr        x8, [x8, #0xf8]
120252e0  blr        x8
120252e4  ldr        x8, [x19]
120252e8  mov        x1, x0
120252ec  mov        x0, x19
120252f0  mov        x2, x27
120252f4  mov        x3, x28
120252f8  ldr        x8, [x8, #0x108]
120252fc  blr        x8
12025300  mov        x2, x0
12025304  mov        x0, x19
12025308  mov        x1, x20
1202530c  bl         #0x1204d410
12025310  cbz        x0, #0x120252a8
12025314  ldr        x8, [x19]
12025318  mov        x23, x0
1202531c  mov        x0, x19
12025320  mov        x1, x23
12025324  mov        x2, xzr
12025328  ldr        x8, [x8, #0x548]
1202532c  blr        x8
12025330  mov        x22, x0
12025334  bl         #0x1204d310
12025338  adrp       x8, #0x12051000
1202533c  mov        x20, x0
12025340  ldr        x8, [x8, #0xe90]
12025344  ldrb       w8, [x8]
12025348  cbz        w8, #0x12025394
1202534c  adrp       x1, #0x12015000
12025350  adrp       x2, #0x12015000
12025354  movz       w0, #0x4
12025358  add        x1, x1, #0x34a
1202535c  add        x2, x2, #0x462
12025360  mov        x3, x22
12025364  bl         #0x1204d050
12025368  adrp       x8, #0x12051000
1202536c  ldr        x8, [x8, #0xe90]
12025370  ldrb       w8, [x8]
12025374  cbz        w8, #0x12025394
12025378  adrp       x1, #0x12015000
1202537c  adrp       x2, #0x12015000
12025380  movz       w0, #0x4
12025384  add        x1, x1, #0x34a
12025388  add        x2, x2, #0xf4b
1202538c  mov        w3, w20
12025390  bl         #0x1204d050
12025394  sub        x0, x29, #0x18
12025398  mov        x1, x22
1202539c  mov        w2, w20
120253a0  stp        xzr, xzr, [x29, #-0x18]
120253a4  bl         #0x1204d420
120253a8  ldr        x8, [x19]
120253ac  mov        x0, x19
120253b0  mov        x1, x23
120253b4  mov        x2, x22
120253b8  ldr        x8, [x8, #0x550]
120253bc  blr        x8
120253c0  ldp        x8, x9, [x29, #-0x18]
120253c4  movz       x10, #0x1979
120253c8  movk       x10, #0x9d16, lsl #16
120253cc  movk       x10, #0xc65c, lsl #32
120253d0  movk       x10, #0x598b, lsl #48
120253d4  eor        x8, x8, x10
120253d8  movz       x10, #0x88f
120253dc  movk       x10, #0xb1a2, lsl #16
120253e0  movk       x10, #0xfd26, lsl #32
120253e4  movk       x10, #0xfa57, lsl #48
120253e8  eor        x9, x9, x10
120253ec  orr        x8, x8, x9
120253f0  cbz        x8, #0x12025428
120253f4  ldp        x8, x9, [x29, #-0x18]
120253f8  movz       x10, #0xf40f
120253fc  movk       x10, #0x33c2, lsl #16
12025400  movk       x10, #0xf4e9, lsl #32
12025404  movk       x10, #0x7e6a, lsl #48
12025408  eor        x8, x8, x10
1202540c  movz       x10, #0xe32
12025410  movk       x10, #0xe788, lsl #16
12025414  movk       x10, #0xae81, lsl #32
12025418  movk       x10, #0x214f, lsl #48
1202541c  eor        x9, x9, x10
12025420  orr        x8, x8, x9
12025424  cbnz       x8, #0x120252a8
12025428  adrp       x8, #0x12051000
1202542c  ldr        x8, [x8, #0xe90]
12025430  ldrb       w8, [x8]
12025434  cbz        w8, #0x12025450
12025438  adrp       x1, #0x12015000
1202543c  adrp       x2, #0x12016000
12025440  add        x1, x1, #0x34a
12025444  add        x2, x2, #0x82f
12025448  movz       w0, #0x4
1202544c  bl         #0x1204d050
12025450  movz       w0, #0x1
12025454  ldr        x22, [sp]
12025458  b          #0x12025460
1202545c  mov        w0, wzr
12025460  ldr        x8, [x22, #0x28]
12025464  ldur       x9, [x29, #-8]
12025468  cmp        x8, x9
1202546c  b.ne       #0x12025498
12025470  ldp        x20, x19, [sp, #0x90]
12025474  ldp        x22, x21, [sp, #0x80]
12025478  ldp        x24, x23, [sp, #0x70]
1202547c  ldp        x26, x25, [sp, #0x60]
12025480  ldp        x28, x27, [sp, #0x50]
12025484  ldp        x29, x30, [sp, #0x40]
12025488  add        sp, sp, #0xa0
1202548c  ret        
12025490  mov        w0, wzr
12025494  b          #0x12025454
12025498  bl         #0x1204d080
1202549c  sub        sp, sp, #0x120
120254a0  stp        x29, x30, [sp, #0x100]
120254a4  add        x29, sp, #0x100
120254a8  stp        x28, x19, [sp, #0x110]
120254ac  stp        x3, x4, [x29, #-0x78]
120254b0  sub        x9, x29, #0x78
120254b4  stp        x5, x6, [x29, #-0x68]
120254b8  movn       x11, #0x27
120254bc  stur       x7, [x29, #-0x58]
120254c0  mov        x12, sp
120254c4  stp        q0, q1, [sp]
120254c8  add        x9, x9, #0x28
120254cc  stp        q2, q3, [sp, #0x20]
120254d0  movk       x11, #0xff80, lsl #32
120254d4  stp        q4, q5, [sp, #0x40]
120254d8  add        x12, x12, #0x80
120254dc  stp        q6, q7, [sp, #0x60]
120254e0  mrs        x19, tpidr_el0
120254e4  ldr        x8, [x19, #0x28]
120254e8  sub        x10, x29, #0x28
120254ec  sub        x3, x29, #0x50
120254f0  stur       x8, [x29, #-8]
120254f4  add        x8, x29, #0x20
120254f8  stp        x12, x11, [x29, #-0x18]
120254fc  stp        x8, x9, [x29, #-0x28]
12025500  ldr        x8, [x0]
12025504  ldp        q0, q1, [x10]
12025508  ldr        x8, [x8, #0x118]
1202550c  stp        q0, q1, [x29, #-0x50]
12025510  blr        x8
12025514  ldr        x8, [x19, #0x28]
12025518  ldur       x9, [x29, #-8]
1202551c  cmp        x8, x9
12025520  b.ne       #0x12025534
12025524  ldp        x28, x19, [sp, #0x110]
12025528  ldp        x29, x30, [sp, #0x100]
1202552c  add        sp, sp, #0x120
12025530  ret        

================================================================================
## _ZN12CMSFJavaUtil7getIMEIEP7_JNIEnvP8_jobjectRNSt6__ndk112basic_stringIcNS4_11char_traitsIcEENS4_9allocatorIcEEEEi
## base+0x24d50
================================================================================
12024d50  sub        sp, sp, #0x60
12024d54  stp        x29, x30, [sp, #0x20]
12024d58  add        x29, sp, #0x20
12024d5c  stp        x24, x23, [sp, #0x30]
12024d60  stp        x22, x21, [sp, #0x40]
12024d64  stp        x20, x19, [sp, #0x50]
12024d68  adrp       x24, #0x12051000
12024d6c  mrs        x23, tpidr_el0
12024d70  mov        x19, x2
12024d74  ldr        x8, [x23, #0x28]
12024d78  cmp        w3, #1
12024d7c  ldr        x24, [x24, #0xe90]
12024d80  stur       x8, [x29, #-8]
12024d84  b.eq       #0x12024e34
12024d88  cbnz       w3, #0x12024f40
12024d8c  ldr        x8, [x0]
12024d90  adrp       x1, #0x12015000
12024d94  add        x1, x1, #0xe8d
12024d98  mov        x20, x0
12024d9c  ldr        x8, [x8, #0x30]
12024da0  blr        x8
12024da4  cbz        x0, #0x12024f40
12024da8  ldr        x8, [x20]
12024dac  mov        x21, x0
12024db0  adrp       x2, #0x12016000
12024db4  adrp       x3, #0x12015000
12024db8  add        x2, x2, #0x6b6
12024dbc  add        x3, x3, #0x7e8
12024dc0  ldr        x8, [x8, #0x388]
12024dc4  mov        x0, x20
12024dc8  mov        x1, x21
12024dcc  blr        x8
12024dd0  cbz        x0, #0x12024f40
12024dd4  mov        x2, x0
12024dd8  mov        x0, x20
12024ddc  mov        x1, x21
12024de0  mov        x3, xzr
12024de4  bl         #0x1204d3e0
12024de8  cbz        x0, #0x12024f40
12024dec  ldr        x8, [x20]
12024df0  mov        x21, x0
12024df4  mov        x0, x20
12024df8  mov        x1, x21
12024dfc  mov        x2, xzr
12024e00  ldr        x8, [x8, #0x548]
12024e04  blr        x8
12024e08  mov        x22, x0
12024e0c  mov        x0, x19
12024e10  mov        x1, x22
12024e14  bl         #0x1204d110
12024e18  ldr        x8, [x20]
12024e1c  mov        x0, x20
12024e20  mov        x1, x21
12024e24  mov        x2, x22
12024e28  ldr        x8, [x8, #0x550]
12024e2c  blr        x8
12024e30  b          #0x12024f50
12024e34  adrp       x0, #0x12016000
12024e38  adrp       x1, #0x12016000
12024e3c  add        x0, x0, #0xb55
12024e40  add        x1, x1, #0x2b0
12024e44  bl         #0x1204d140
12024e48  stp        xzr, xzr, [sp, #8]
12024e4c  cbz        x0, #0x12024ed0
12024e50  mov        x1, xzr
12024e54  movz       w2, #0x2
12024e58  mov        x20, x0
12024e5c  bl         #0x1204d170
12024e60  mov        x0, x20
12024e64  bl         #0x1204d180
12024e68  cmp        x0, #0x15
12024e6c  b.lt       #0x12024ef4
12024e70  mov        x0, x20
12024e74  mov        x1, xzr
12024e78  mov        w2, wzr
12024e7c  bl         #0x1204d170
12024e80  adrp       x1, #0x12015000
12024e84  add        x2, sp, #8
12024e88  add        x1, x1, #0xd1e
12024e8c  mov        x0, x20
12024e90  bl         #0x1204d3f0
12024e94  ldrb       w8, [x24]
12024e98  cbz        w0, #0x12024f1c
12024e9c  cbz        w8, #0x12024eb8
12024ea0  adrp       x1, #0x12015000
12024ea4  adrp       x2, #0x12015000
12024ea8  add        x1, x1, #0x34a
12024eac  add        x2, x2, #0x7fd
12024eb0  movz       w0, #0x6
12024eb4  bl         #0x1204d050
12024eb8  add        x1, sp, #8
12024ebc  mov        x0, x19
12024ec0  bl         #0x1204d110
12024ec4  mov        x0, x20
12024ec8  bl         #0x1204d150
12024ecc  b          #0x12024f50
12024ed0  ldrb       w8, [x24]
12024ed4  cbz        w8, #0x12024f40
12024ed8  adrp       x1, #0x12015000
12024edc  adrp       x2, #0x12015000
12024ee0  add        x1, x1, #0x34a
12024ee4  add        x2, x2, #0x77c
12024ee8  movz       w0, #0x6
12024eec  bl         #0x1204d050
12024ef0  b          #0x12024f40
12024ef4  ldrb       w8, [x24]
12024ef8  cbz        w8, #0x12024f38
12024efc  adrp       x1, #0x12015000
12024f00  adrp       x2, #0x12016000
12024f04  mov        x3, x0
12024f08  add        x1, x1, #0x34a
12024f0c  add        x2, x2, #0x4e7
12024f10  movz       w0, #0x6
12024f14  bl         #0x1204d050
12024f18  b          #0x12024f38
12024f1c  cbz        w8, #0x12024f38
12024f20  adrp       x1, #0x12015000
12024f24  adrp       x2, #0x12015000
12024f28  add        x1, x1, #0x34a
12024f2c  add        x2, x2, #0x5c1
12024f30  movz       w0, #0x6
12024f34  bl         #0x1204d050
12024f38  mov        x0, x20
12024f3c  bl         #0x1204d150
12024f40  adrp       x1, #0x12016000
12024f44  mov        x0, x19
12024f48  add        x1, x1, #0xd52
12024f4c  bl         #0x1204d110
12024f50  ldrb       w8, [x24]
12024f54  cbz        w8, #0x12024f80
12024f58  ldrb       w8, [x19]
12024f5c  adrp       x1, #0x12015000
12024f60  ldr        x9, [x19, #0x10]
12024f64  adrp       x2, #0x12016000
12024f68  add        x1, x1, #0x34a
12024f6c  add        x2, x2, #0x2b2
12024f70  tst        w8, #1
12024f74  movz       w0, #0x4
12024f78  csinc      x3, x9, x19, ne
12024f7c  bl         #0x1204d050
12024f80  ldr        x8, [x23, #0x28]
12024f84  ldur       x9, [x29, #-8]
12024f88  cmp        x8, x9
12024f8c  b.ne       #0x12024fa8
12024f90  ldp        x20, x19, [sp, #0x50]
12024f94  ldp        x22, x21, [sp, #0x40]
12024f98  ldp        x24, x23, [sp, #0x30]
12024f9c  ldp        x29, x30, [sp, #0x20]
12024fa0  add        sp, sp, #0x60
12024fa4  ret        
12024fa8  bl         #0x1204d080
12024fac  sub        sp, sp, #0x120
12024fb0  stp        x29, x30, [sp, #0x100]
12024fb4  add        x29, sp, #0x100
12024fb8  stp        x28, x19, [sp, #0x110]
12024fbc  stp        x3, x4, [x29, #-0x78]
12024fc0  sub        x9, x29, #0x78
12024fc4  stp        x5, x6, [x29, #-0x68]
12024fc8  movn       x11, #0x27
12024fcc  stur       x7, [x29, #-0x58]
12024fd0  mov        x12, sp
12024fd4  stp        q0, q1, [sp]
12024fd8  add        x9, x9, #0x28
12024fdc  stp        q2, q3, [sp, #0x20]
12024fe0  movk       x11, #0xff80, lsl #32
12024fe4  stp        q4, q5, [sp, #0x40]
12024fe8  add        x12, x12, #0x80
12024fec  stp        q6, q7, [sp, #0x60]
12024ff0  mrs        x19, tpidr_el0
12024ff4  ldr        x8, [x19, #0x28]
12024ff8  sub        x10, x29, #0x28
12024ffc  sub        x3, x29, #0x50
12025000  stur       x8, [x29, #-8]
12025004  add        x8, x29, #0x20
12025008  stp        x12, x11, [x29, #-0x18]
1202500c  stp        x8, x9, [x29, #-0x28]
12025010  ldr        x8, [x0]
12025014  ldp        q0, q1, [x10]
12025018  ldr        x8, [x8, #0x398]
1202501c  stp        q0, q1, [x29, #-0x50]
12025020  blr        x8
12025024  ldr        x8, [x19, #0x28]
12025028  ldur       x9, [x29, #-8]
1202502c  cmp        x8, x9
12025030  b.ne       #0x12025044
12025034  ldp        x28, x19, [sp, #0x110]
12025038  ldp        x29, x30, [sp, #0x100]
1202503c  add        sp, sp, #0x120
12025040  ret        

