# libtsmqqsc.so — 腾讯支付国密库 反汇编
# base = 0x12000000  size = 0xc0000

================================================================================
## JNI_OnLoad
## base+0x31900
================================================================================
12031900  sub        sp, sp, #0x40
12031904  stp        x29, x30, [sp, #0x10]
12031908  str        x21, [sp, #0x20]
1203190c  stp        x20, x19, [sp, #0x30]
12031910  add        x29, sp, #0x10
12031914  mrs        x21, tpidr_el0
12031918  movz       w2, #0x6
1203191c  movz       w19, #0x6
12031920  ldr        x8, [x21, #0x28]
12031924  mov        x1, sp
12031928  movk       w2, #0x1, lsl #16
1203192c  movk       w19, #0x1, lsl #16
12031930  str        x8, [sp, #8]
12031934  ldr        x8, [x0]
12031938  str        xzr, [sp]
1203193c  ldr        x8, [x8, #0x30]
12031940  blr        x8
12031944  cbz        w0, #0x12031950
12031948  movn       w19, #0
1203194c  b          #0x120319a4
12031950  ldr        x0, [sp]
12031954  nop        
12031958  adr        x1, #0x1201586d
1203195c  ldr        x8, [x0]
12031960  ldr        x8, [x8, #0x30]
12031964  blr        x8
12031968  cbz        x0, #0x12031948
1203196c  mov        x20, x0
12031970  ldr        x0, [sp]
12031974  mov        x1, x20
12031978  ldr        x8, [x0]
1203197c  ldr        x8, [x8, #0xa8]
12031980  blr        x8
12031984  adrp       x9, #0x120be000
12031988  ldr        x8, [sp]
1203198c  mov        x1, x20
12031990  str        x0, [x9, #0xdb8]
12031994  ldr        x9, [x8]
12031998  mov        x0, x8
1203199c  ldr        x9, [x9, #0xb8]
120319a0  blr        x9
120319a4  ldr        x8, [x21, #0x28]
120319a8  ldr        x9, [sp, #8]
120319ac  cmp        x8, x9
120319b0  b.ne       #0x120319cc
120319b4  mov        w0, w19
120319b8  ldp        x20, x19, [sp, #0x30]
120319bc  ldr        x21, [sp, #0x20]
120319c0  ldp        x29, x30, [sp, #0x10]
120319c4  add        sp, sp, #0x40
120319c8  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_getVersion
## base+0x319d0
================================================================================
120319d0  stp        x29, x30, [sp, #-0x20]!
120319d4  str        x19, [sp, #0x10]
120319d8  mov        x29, sp
120319dc  mov        x19, x0
120319e0  bl         #0x12038d00
120319e4  mov        x1, x0
120319e8  mov        x0, x19
120319ec  ldr        x19, [sp, #0x10]
120319f0  ldp        x29, x30, [sp], #0x20
120319f4  b          #0x120363c0
120319f8  adrp       x8, #0x120be000
120319fc  ldr        w0, [x8, #0xdc0]
12031a00  cbz        w0, #0x12031a08
12031a04  ret        
12031a08  stp        x29, x30, [sp, #-0x10]!
12031a0c  mov        x29, sp
12031a10  bl         #0x12035fe4
12031a14  cbz        w0, #0x12031a24
12031a18  bl         #0x12035fe4
12031a1c  add        w8, w0, #0x989, lsl #12
12031a20  add        w0, w8, #0x680
12031a24  ldp        x29, x30, [sp], #0x10
12031a28  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_getLastError
## base+0x319f8
================================================================================
120319f8  adrp       x8, #0x120be000
120319fc  ldr        w0, [x8, #0xdc0]
12031a00  cbz        w0, #0x12031a08
12031a04  ret        
12031a08  stp        x29, x30, [sp, #-0x10]!
12031a0c  mov        x29, sp
12031a10  bl         #0x12035fe4
12031a14  cbz        w0, #0x12031a24
12031a18  bl         #0x12035fe4
12031a1c  add        w8, w0, #0x989, lsl #12
12031a20  add        w0, w8, #0x680
12031a24  ldp        x29, x30, [sp], #0x10
12031a28  ret        
12031a2c  stp        x29, x30, [sp, #-0x60]!
12031a30  stp        x28, x27, [sp, #0x10]
12031a34  stp        x26, x25, [sp, #0x20]
12031a38  stp        x24, x23, [sp, #0x30]
12031a3c  stp        x22, x21, [sp, #0x40]
12031a40  stp        x20, x19, [sp, #0x50]
12031a44  mov        x29, sp
12031a48  adrp       x8, #0x120bf000
12031a4c  mov        x20, x0
12031a50  adrp       x28, #0x120be000
12031a54  str        x0, [x8, #0x90]
12031a58  nop        
12031a5c  adr        x0, #0x12031c6c
12031a60  mov        x19, x5
12031a64  mov        x21, x4
12031a68  mov        x22, x3
12031a6c  mov        x23, x2
12031a70  str        wzr, [x28, #0xdc0]
12031a74  bl         #0x12038ce8
12031a78  nop        
12031a7c  adr        x0, #0x120bedc4
12031a80  mov        w1, wzr
12031a84  movz       w2, #0x2c8
12031a88  bl         #0x120aa400
12031a8c  mov        x0, x20
12031a90  mov        x1, x23
12031a94  bl         #0x12036280
12031a98  mov        x24, x0
12031a9c  mov        x0, x20
12031aa0  mov        x1, x22
12031aa4  bl         #0x12036280
12031aa8  mov        x25, x0
12031aac  mov        x0, x20
12031ab0  mov        x1, x21
12031ab4  bl         #0x12036280
12031ab8  mov        x26, x0
12031abc  mov        x0, x20
12031ac0  mov        x1, x19
12031ac4  bl         #0x12036280
12031ac8  mov        x27, x0
12031acc  cbz        x24, #0x12031b24
12031ad0  ldrb       w8, [x24]
12031ad4  cbz        w8, #0x12031b24
12031ad8  cmp        x25, #0
12031adc  adrp       x8, #0x12015000
12031ae0  add        x8, x8, #0x684
12031ae4  csel       x1, x8, x25, eq
12031ae8  adrp       x0, #0x120be000
12031aec  add        x0, x0, #0xfc4
12031af0  movz       w2, #0x41
12031af4  bl         #0x12036ae0
12031af8  adrp       x28, #0x120bf000
12031afc  cbz        x26, #0x12031b98
12031b00  ldrb       w8, [x26]
12031b04  cbz        w8, #0x12031b98
12031b08  adrp       x0, #0x120bf000
12031b0c  add        x0, x0, #5
12031b10  mov        x1, x26
12031b14  movz       w2, #0x41
12031b18  bl         #0x12036ae0
12031b1c  cbnz       x27, #0x12031ba8
12031b20  b          #0x12031bc8
12031b24  movz       w8, #0x65d8
12031b28  movk       w8, #0xfffe, lsl #16
12031b2c  str        w8, [x28, #0xdc0]
12031b30  mov        x0, x20
12031b34  mov        x1, x23
12031b38  mov        x2, x24
12031b3c  bl         #0x120362ac
12031b40  mov        x0, x20
12031b44  mov        x1, x22
12031b48  mov        x2, x25
12031b4c  bl         #0x120362ac
12031b50  mov        x0, x20
12031b54  mov        x1, x21
12031b58  mov        x2, x26
12031b5c  bl         #0x120362ac
12031b60  mov        x0, x20
12031b64  mov        x1, x19
12031b68  mov        x2, x27
12031b6c  bl         #0x120362ac
12031b70  ldr        w8, [x28, #0xdc0]
12031b74  cmp        w8, #0
12031b78  cset       w0, eq
12031b7c  ldp        x20, x19, [sp, #0x50]
12031b80  ldp        x22, x21, [sp, #0x40]
12031b84  ldp        x24, x23, [sp, #0x30]
12031b88  ldp        x26, x25, [sp, #0x20]
12031b8c  ldp        x28, x27, [sp, #0x10]
12031b90  ldp        x29, x30, [sp], #0x60
12031b94  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_init
## base+0x31a2c
================================================================================
12031a2c  stp        x29, x30, [sp, #-0x60]!
12031a30  stp        x28, x27, [sp, #0x10]
12031a34  stp        x26, x25, [sp, #0x20]
12031a38  stp        x24, x23, [sp, #0x30]
12031a3c  stp        x22, x21, [sp, #0x40]
12031a40  stp        x20, x19, [sp, #0x50]
12031a44  mov        x29, sp
12031a48  adrp       x8, #0x120bf000
12031a4c  mov        x20, x0
12031a50  adrp       x28, #0x120be000
12031a54  str        x0, [x8, #0x90]
12031a58  nop        
12031a5c  adr        x0, #0x12031c6c
12031a60  mov        x19, x5
12031a64  mov        x21, x4
12031a68  mov        x22, x3
12031a6c  mov        x23, x2
12031a70  str        wzr, [x28, #0xdc0]
12031a74  bl         #0x12038ce8
12031a78  nop        
12031a7c  adr        x0, #0x120bedc4
12031a80  mov        w1, wzr
12031a84  movz       w2, #0x2c8
12031a88  bl         #0x120aa400
12031a8c  mov        x0, x20
12031a90  mov        x1, x23
12031a94  bl         #0x12036280
12031a98  mov        x24, x0
12031a9c  mov        x0, x20
12031aa0  mov        x1, x22
12031aa4  bl         #0x12036280
12031aa8  mov        x25, x0
12031aac  mov        x0, x20
12031ab0  mov        x1, x21
12031ab4  bl         #0x12036280
12031ab8  mov        x26, x0
12031abc  mov        x0, x20
12031ac0  mov        x1, x19
12031ac4  bl         #0x12036280
12031ac8  mov        x27, x0
12031acc  cbz        x24, #0x12031b24
12031ad0  ldrb       w8, [x24]
12031ad4  cbz        w8, #0x12031b24
12031ad8  cmp        x25, #0
12031adc  adrp       x8, #0x12015000
12031ae0  add        x8, x8, #0x684
12031ae4  csel       x1, x8, x25, eq
12031ae8  adrp       x0, #0x120be000
12031aec  add        x0, x0, #0xfc4
12031af0  movz       w2, #0x41
12031af4  bl         #0x12036ae0
12031af8  adrp       x28, #0x120bf000
12031afc  cbz        x26, #0x12031b98
12031b00  ldrb       w8, [x26]
12031b04  cbz        w8, #0x12031b98
12031b08  adrp       x0, #0x120bf000
12031b0c  add        x0, x0, #5
12031b10  mov        x1, x26
12031b14  movz       w2, #0x41
12031b18  bl         #0x12036ae0
12031b1c  cbnz       x27, #0x12031ba8
12031b20  b          #0x12031bc8
12031b24  movz       w8, #0x65d8
12031b28  movk       w8, #0xfffe, lsl #16
12031b2c  str        w8, [x28, #0xdc0]
12031b30  mov        x0, x20
12031b34  mov        x1, x23
12031b38  mov        x2, x24
12031b3c  bl         #0x120362ac
12031b40  mov        x0, x20
12031b44  mov        x1, x22
12031b48  mov        x2, x25
12031b4c  bl         #0x120362ac
12031b50  mov        x0, x20
12031b54  mov        x1, x21
12031b58  mov        x2, x26
12031b5c  bl         #0x120362ac
12031b60  mov        x0, x20
12031b64  mov        x1, x19
12031b68  mov        x2, x27
12031b6c  bl         #0x120362ac
12031b70  ldr        w8, [x28, #0xdc0]
12031b74  cmp        w8, #0
12031b78  cset       w0, eq
12031b7c  ldp        x20, x19, [sp, #0x50]
12031b80  ldp        x22, x21, [sp, #0x40]
12031b84  ldp        x24, x23, [sp, #0x30]
12031b88  ldp        x26, x25, [sp, #0x20]
12031b8c  ldp        x28, x27, [sp, #0x10]
12031b90  ldp        x29, x30, [sp], #0x60
12031b94  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_initTsm
## base+0x31cd4
================================================================================
12031cd4  stp        x29, x30, [sp, #-0x50]!
12031cd8  str        x28, [sp, #0x10]
12031cdc  stp        x24, x23, [sp, #0x20]
12031ce0  stp        x22, x21, [sp, #0x30]
12031ce4  stp        x20, x19, [sp, #0x40]
12031ce8  mov        x29, sp
12031cec  sub        sp, sp, #0x410
12031cf0  mrs        x21, tpidr_el0
12031cf4  adrp       x24, #0x120bf000
12031cf8  mov        x19, x0
12031cfc  ldr        x8, [x21, #0x28]
12031d00  adrp       x22, #0x120be000
12031d04  stur       x8, [x29, #-8]
12031d08  str        x0, [x24, #0x90]
12031d0c  nop        
12031d10  adr        x0, #0x12031c6c
12031d14  str        wzr, [x22, #0xdc0]
12031d18  bl         #0x12038ce8
12031d1c  bl         #0x12038d0c
12031d20  adrp       x23, #0x120be000
12031d24  str        w0, [x22, #0xdc0]
12031d28  cbz        w0, #0x12031e8c
12031d2c  ldr        x8, [x24, #0x90]
12031d30  cbz        x8, #0x12031d94
12031d34  ldr        x8, [x23, #0xdb8]
12031d38  cbz        x8, #0x12031d94
12031d3c  mov        w20, w0
12031d40  add        x0, sp, #8
12031d44  mov        w1, wzr
12031d48  movz       w2, #0x400
12031d4c  bl         #0x120aa400
12031d50  adrp       x3, #0x12015000
12031d54  add        x3, x3, #0xda8
12031d58  adrp       x4, #0x12015000
12031d5c  add        x4, x4, #0xa17
12031d60  add        x0, sp, #8
12031d64  movz       w1, #0x400
12031d68  movz       w2, #0x400
12031d6c  mov        w5, wzr
12031d70  bl         #0x12032dfc
12031d74  add        x1, sp, #8
12031d78  mov        x0, x19
12031d7c  bl         #0x120363c0
12031d80  ldr        x1, [x23, #0xdb8]
12031d84  mov        x3, x0
12031d88  mov        x0, x19
12031d8c  mov        w2, w20
12031d90  bl         #0x1203614c
12031d94  bl         #0x12038d0c
12031d98  mov        w20, w0
12031d9c  str        w0, [x22, #0xdc0]
12031da0  cbz        w0, #0x12031e90
12031da4  ldr        x8, [x24, #0x90]
12031da8  cbz        x8, #0x12031e08
12031dac  ldr        x8, [x23, #0xdb8]
12031db0  cbz        x8, #0x12031e08
12031db4  add        x0, sp, #8
12031db8  mov        w1, wzr
12031dbc  movz       w2, #0x400
12031dc0  bl         #0x120aa400
12031dc4  adrp       x3, #0x12015000
12031dc8  add        x3, x3, #0xda8
12031dcc  adrp       x4, #0x12015000
12031dd0  add        x4, x4, #0xa17
12031dd4  add        x0, sp, #8
12031dd8  movz       w1, #0x400
12031ddc  movz       w2, #0x400
12031de0  movz       w5, #0x1
12031de4  bl         #0x12032dfc
12031de8  add        x1, sp, #8
12031dec  mov        x0, x19
12031df0  bl         #0x120363c0
12031df4  ldr        x1, [x23, #0xdb8]
12031df8  mov        x3, x0
12031dfc  mov        x0, x19
12031e00  mov        w2, w20
12031e04  bl         #0x1203614c
12031e08  bl         #0x12038d0c
12031e0c  mov        w20, w0
12031e10  str        w0, [x22, #0xdc0]
12031e14  cbz        w0, #0x12031e90
12031e18  ldr        x8, [x24, #0x90]
12031e1c  cbz        x8, #0x12031e7c
12031e20  ldr        x8, [x23, #0xdb8]
12031e24  cbz        x8, #0x12031e7c
12031e28  add        x0, sp, #8
12031e2c  mov        w1, wzr
12031e30  movz       w2, #0x400
12031e34  bl         #0x120aa400
12031e38  adrp       x3, #0x12015000
12031e3c  add        x3, x3, #0xda8
12031e40  adrp       x4, #0x12015000
12031e44  add        x4, x4, #0xa17
12031e48  add        x0, sp, #8
12031e4c  movz       w1, #0x400
12031e50  movz       w2, #0x400
12031e54  movz       w5, #0x2
12031e58  bl         #0x12032dfc
12031e5c  add        x1, sp, #8
12031e60  mov        x0, x19
12031e64  bl         #0x120363c0
12031e68  ldr        x1, [x23, #0xdb8]
12031e6c  mov        x3, x0
12031e70  mov        x0, x19
12031e74  mov        w2, w20
12031e78  bl         #0x1203614c
12031e7c  bl         #0x12038d0c
12031e80  mov        w20, w0
12031e84  str        w0, [x22, #0xdc0]
12031e88  b          #0x12031e90
12031e8c  mov        w20, wzr
12031e90  ldr        x8, [x24, #0x90]
12031e94  cbz        x8, #0x12031ec8
12031e98  ldr        x8, [x23, #0xdb8]
12031e9c  cbz        x8, #0x12031ec8
12031ea0  adrp       x1, #0x12015000
12031ea4  add        x1, x1, #0x783
12031ea8  mov        x0, x19
12031eac  bl         #0x120363c0
12031eb0  ldr        x1, [x23, #0xdb8]
12031eb4  mov        x3, x0
12031eb8  mov        x0, x19
12031ebc  mov        w2, w20
12031ec0  bl         #0x1203614c
12031ec4  ldr        w20, [x22, #0xdc0]
12031ec8  ldr        x8, [x21, #0x28]
12031ecc  ldur       x9, [x29, #-8]
12031ed0  cmp        w20, #0
12031ed4  cset       w0, eq
12031ed8  cmp        x8, x9
12031edc  b.ne       #0x12031efc
12031ee0  add        sp, sp, #0x410
12031ee4  ldp        x20, x19, [sp, #0x40]
12031ee8  ldr        x28, [sp, #0x10]
12031eec  ldp        x22, x21, [sp, #0x30]
12031ef0  ldp        x24, x23, [sp, #0x20]
12031ef4  ldp        x29, x30, [sp], #0x50
12031ef8  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm3
## base+0x338b8
================================================================================
120338b8  sub        sp, sp, #0x70
120338bc  stp        x29, x30, [sp, #0x30]
120338c0  str        x23, [sp, #0x40]
120338c4  stp        x22, x21, [sp, #0x50]
120338c8  stp        x20, x19, [sp, #0x60]
120338cc  add        x29, sp, #0x30
120338d0  mrs        x22, tpidr_el0
120338d4  adrp       x9, #0x120bf000
120338d8  mov        x1, x2
120338dc  ldr        x8, [x22, #0x28]
120338e0  mov        x20, x2
120338e4  mov        x19, x0
120338e8  stur       x8, [x29, #-8]
120338ec  str        x0, [x9, #0x90]
120338f0  bl         #0x120362e0
120338f4  mov        x21, x0
120338f8  mov        x0, x19
120338fc  mov        x1, x20
12033900  bl         #0x12036268
12033904  movi       v0.2d, #0000000000000000
12033908  mov        w1, w0
1203390c  mov        x2, sp
12033910  mov        x0, x21
12033914  stp        q0, q0, [sp]
12033918  bl         #0x120396e0
1203391c  adrp       x23, #0x120be000
12033920  mov        x1, x20
12033924  mov        x2, x21
12033928  str        w0, [x23, #0xdc0]
1203392c  mov        x0, x19
12033930  bl         #0x1203630c
12033934  ldr        w8, [x23, #0xdc0]
12033938  cbz        w8, #0x12033944
1203393c  mov        x0, xzr
12033940  b          #0x12033954
12033944  mov        x1, sp
12033948  mov        x0, x19
1203394c  movz       w2, #0x20
12033950  bl         #0x12036344
12033954  ldr        x8, [x22, #0x28]
12033958  ldur       x9, [x29, #-8]
1203395c  cmp        x8, x9
12033960  b.ne       #0x1203397c
12033964  ldp        x20, x19, [sp, #0x60]
12033968  ldr        x23, [sp, #0x40]
1203396c  ldp        x22, x21, [sp, #0x50]
12033970  ldp        x29, x30, [sp, #0x30]
12033974  add        sp, sp, #0x70
12033978  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_md5
## base+0x337f8
================================================================================
120337f8  sub        sp, sp, #0x60
120337fc  stp        x29, x30, [sp, #0x20]
12033800  str        x23, [sp, #0x30]
12033804  stp        x22, x21, [sp, #0x40]
12033808  stp        x20, x19, [sp, #0x50]
1203380c  add        x29, sp, #0x20
12033810  mrs        x22, tpidr_el0
12033814  adrp       x9, #0x120bf000
12033818  mov        x1, x2
1203381c  ldr        x8, [x22, #0x28]
12033820  mov        x20, x2
12033824  mov        x19, x0
12033828  stur       x8, [x29, #-8]
1203382c  str        x0, [x9, #0x90]
12033830  bl         #0x120362e0
12033834  mov        x21, x0
12033838  mov        x0, x19
1203383c  mov        x1, x20
12033840  bl         #0x12036268
12033844  mov        w1, w0
12033848  add        x2, sp, #8
1203384c  mov        x0, x21
12033850  stp        xzr, xzr, [sp, #8]
12033854  bl         #0x12036c38
12033858  adrp       x23, #0x120be000
1203385c  mov        x1, x20
12033860  mov        x2, x21
12033864  str        w0, [x23, #0xdc0]
12033868  mov        x0, x19
1203386c  bl         #0x1203630c
12033870  ldr        w8, [x23, #0xdc0]
12033874  mov        x0, xzr
12033878  cbnz       w8, #0x1203388c
1203387c  add        x1, sp, #8
12033880  mov        x0, x19
12033884  movz       w2, #0x10
12033888  bl         #0x12036344
1203388c  ldr        x8, [x22, #0x28]
12033890  ldur       x9, [x29, #-8]
12033894  cmp        x8, x9
12033898  b.ne       #0x120338b4
1203389c  ldp        x20, x19, [sp, #0x50]
120338a0  ldr        x23, [sp, #0x30]
120338a4  ldp        x22, x21, [sp, #0x40]
120338a8  ldp        x29, x30, [sp, #0x20]
120338ac  add        sp, sp, #0x60
120338b0  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sha1
## base+0x33734
================================================================================
12033734  sub        sp, sp, #0x60
12033738  stp        x29, x30, [sp, #0x20]
1203373c  str        x23, [sp, #0x30]
12033740  stp        x22, x21, [sp, #0x40]
12033744  stp        x20, x19, [sp, #0x50]
12033748  add        x29, sp, #0x20
1203374c  mrs        x22, tpidr_el0
12033750  adrp       x9, #0x120bf000
12033754  mov        x1, x2
12033758  ldr        x8, [x22, #0x28]
1203375c  mov        x20, x2
12033760  mov        x19, x0
12033764  stur       x8, [x29, #-8]
12033768  str        x0, [x9, #0x90]
1203376c  bl         #0x120362e0
12033770  mov        x21, x0
12033774  mov        x0, x19
12033778  mov        x1, x20
1203377c  bl         #0x12036268
12033780  mov        w1, w0
12033784  mov        x2, sp
12033788  mov        x0, x21
1203378c  stp        xzr, xzr, [sp]
12033790  str        wzr, [sp, #0x10]
12033794  bl         #0x12036bac
12033798  adrp       x23, #0x120be000
1203379c  mov        x1, x20
120337a0  mov        x2, x21
120337a4  str        w0, [x23, #0xdc0]
120337a8  mov        x0, x19
120337ac  bl         #0x1203630c
120337b0  ldr        w8, [x23, #0xdc0]
120337b4  mov        x0, xzr
120337b8  cbnz       w8, #0x120337cc
120337bc  mov        x1, sp
120337c0  mov        x0, x19
120337c4  movz       w2, #0x14
120337c8  bl         #0x12036344
120337cc  ldr        x8, [x22, #0x28]
120337d0  ldur       x9, [x29, #-8]
120337d4  cmp        x8, x9
120337d8  b.ne       #0x120337f4
120337dc  ldp        x20, x19, [sp, #0x50]
120337e0  ldr        x23, [sp, #0x30]
120337e4  ldp        x22, x21, [sp, #0x40]
120337e8  ldp        x29, x30, [sp, #0x20]
120337ec  add        sp, sp, #0x60
120337f0  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sha256
## base+0x3366c
================================================================================
1203366c  sub        sp, sp, #0x70
12033670  stp        x29, x30, [sp, #0x30]
12033674  str        x23, [sp, #0x40]
12033678  stp        x22, x21, [sp, #0x50]
1203367c  stp        x20, x19, [sp, #0x60]
12033680  add        x29, sp, #0x30
12033684  mrs        x22, tpidr_el0
12033688  adrp       x9, #0x120bf000
1203368c  mov        x1, x2
12033690  ldr        x8, [x22, #0x28]
12033694  mov        x20, x2
12033698  mov        x19, x0
1203369c  stur       x8, [x29, #-8]
120336a0  str        x0, [x9, #0x90]
120336a4  bl         #0x120362e0
120336a8  mov        x21, x0
120336ac  mov        x0, x19
120336b0  mov        x1, x20
120336b4  bl         #0x12036268
120336b8  movi       v0.2d, #0000000000000000
120336bc  mov        w1, w0
120336c0  mov        x2, sp
120336c4  mov        x0, x21
120336c8  stp        q0, q0, [sp]
120336cc  bl         #0x12036b20
120336d0  adrp       x23, #0x120be000
120336d4  mov        x1, x20
120336d8  mov        x2, x21
120336dc  str        w0, [x23, #0xdc0]
120336e0  mov        x0, x19
120336e4  bl         #0x1203630c
120336e8  ldr        w8, [x23, #0xdc0]
120336ec  cbz        w8, #0x120336f8
120336f0  mov        x0, xzr
120336f4  b          #0x12033708
120336f8  mov        x1, sp
120336fc  mov        x0, x19
12033700  movz       w2, #0x20
12033704  bl         #0x12036344
12033708  ldr        x8, [x22, #0x28]
1203370c  ldur       x9, [x29, #-8]
12033710  cmp        x8, x9
12033714  b.ne       #0x12033730
12033718  ldp        x20, x19, [sp, #0x60]
1203371c  ldr        x23, [sp, #0x40]
12033720  ldp        x22, x21, [sp, #0x50]
12033724  ldp        x29, x30, [sp, #0x30]
12033728  add        sp, sp, #0x70
1203372c  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm3Hmac
## base+0x33980
================================================================================
12033980  sub        sp, sp, #0x80
12033984  stp        x29, x30, [sp, #0x30]
12033988  str        x25, [sp, #0x40]
1203398c  stp        x24, x23, [sp, #0x50]
12033990  stp        x22, x21, [sp, #0x60]
12033994  stp        x20, x19, [sp, #0x70]
12033998  add        x29, sp, #0x30
1203399c  mrs        x25, tpidr_el0
120339a0  adrp       x9, #0x120bf000
120339a4  mov        x1, x2
120339a8  ldr        x8, [x25, #0x28]
120339ac  mov        x20, x3
120339b0  mov        x21, x2
120339b4  mov        x19, x0
120339b8  stur       x8, [x29, #-8]
120339bc  str        x0, [x9, #0x90]
120339c0  bl         #0x120362e0
120339c4  mov        x22, x0
120339c8  mov        x0, x19
120339cc  mov        x1, x20
120339d0  bl         #0x120362e0
120339d4  mov        x23, x0
120339d8  mov        x0, x19
120339dc  mov        x1, x21
120339e0  bl         #0x12036268
120339e4  mov        w24, w0
120339e8  mov        x0, x19
120339ec  mov        x1, x20
120339f0  bl         #0x12036268
120339f4  movi       v0.2d, #0000000000000000
120339f8  mov        w3, w0
120339fc  mov        x4, sp
12033a00  mov        x0, x22
12033a04  mov        w1, w24
12033a08  mov        x2, x23
12033a0c  stp        q0, q0, [sp]
12033a10  bl         #0x120396e8
12033a14  adrp       x24, #0x120be000
12033a18  mov        x1, x21
12033a1c  mov        x2, x22
12033a20  str        w0, [x24, #0xdc0]
12033a24  mov        x0, x19
12033a28  bl         #0x1203630c
12033a2c  mov        x0, x19
12033a30  mov        x1, x20
12033a34  mov        x2, x23
12033a38  bl         #0x1203630c
12033a3c  ldr        w8, [x24, #0xdc0]
12033a40  cbz        w8, #0x12033a4c
12033a44  mov        x0, xzr
12033a48  b          #0x12033a5c
12033a4c  mov        x1, sp
12033a50  mov        x0, x19
12033a54  movz       w2, #0x20
12033a58  bl         #0x12036344
12033a5c  ldr        x8, [x25, #0x28]
12033a60  ldur       x9, [x29, #-8]
12033a64  cmp        x8, x9
12033a68  b.ne       #0x12033a88
12033a6c  ldp        x20, x19, [sp, #0x70]
12033a70  ldr        x25, [sp, #0x40]
12033a74  ldp        x22, x21, [sp, #0x60]
12033a78  ldp        x24, x23, [sp, #0x50]
12033a7c  ldp        x29, x30, [sp, #0x30]
12033a80  add        sp, sp, #0x80
12033a84  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm3Kdf
## base+0x33a8c
================================================================================
12033a8c  stp        x29, x30, [sp, #-0x40]!
12033a90  stp        x24, x23, [sp, #0x10]
12033a94  stp        x22, x21, [sp, #0x20]
12033a98  stp        x20, x19, [sp, #0x30]
12033a9c  mov        x29, sp
12033aa0  cmp        w3, #0
12033aa4  b.le       #0x12033b30
12033aa8  mov        w23, w3
12033aac  mov        x21, x0
12033ab0  mov        w20, w3
12033ab4  mov        x0, x23
12033ab8  mov        x22, x2
12033abc  bl         #0x120aa304
12033ac0  mov        w1, wzr
12033ac4  mov        x2, x23
12033ac8  mov        x19, x0
12033acc  bl         #0x120aa400
12033ad0  movz       w0, #0x1
12033ad4  bl         #0x12035fd0
12033ad8  mov        x0, x21
12033adc  mov        x1, x22
12033ae0  bl         #0x120362e0
12033ae4  mov        x23, x0
12033ae8  mov        x0, x21
12033aec  mov        x1, x22
12033af0  bl         #0x12036268
12033af4  mov        w1, w0
12033af8  mov        x0, x23
12033afc  mov        x2, x19
12033b00  mov        w3, w20
12033b04  bl         #0x12039700
12033b08  adrp       x24, #0x120be000
12033b0c  mov        x1, x22
12033b10  mov        x2, x23
12033b14  str        w0, [x24, #0xdc0]
12033b18  mov        x0, x21
12033b1c  bl         #0x1203630c
12033b20  ldr        w8, [x24, #0xdc0]
12033b24  cbz        w8, #0x12033b48
12033b28  mov        x20, xzr
12033b2c  b          #0x12033b5c
12033b30  movz       w9, #0x65d8
12033b34  adrp       x8, #0x120be000
12033b38  mov        x20, xzr
12033b3c  movk       w9, #0xfffe, lsl #16
12033b40  str        w9, [x8, #0xdc0]
12033b44  b          #0x12033b6c
12033b48  mov        x0, x21
12033b4c  mov        x1, x19
12033b50  mov        w2, w20
12033b54  bl         #0x12036344
12033b58  mov        x20, x0
12033b5c  mov        x0, x19
12033b60  bl         #0x1208be10
12033b64  movn       w0, #0
12033b68  bl         #0x12035fd0
12033b6c  mov        x0, x20
12033b70  ldp        x20, x19, [sp, #0x30]
12033b74  ldp        x22, x21, [sp, #0x20]
12033b78  ldp        x24, x23, [sp, #0x10]
12033b7c  ldp        x29, x30, [sp], #0x40
12033b80  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_randomBytes
## base+0x33b84
================================================================================
12033b84  stp        x29, x30, [sp, #-0x30]!
12033b88  stp        x22, x21, [sp, #0x10]
12033b8c  stp        x20, x19, [sp, #0x20]
12033b90  mov        x29, sp
12033b94  adrp       x8, #0x120bf000
12033b98  cmp        w2, #0
12033b9c  str        x0, [x8, #0x90]
12033ba0  b.le       #0x12033bf0
12033ba4  mov        w22, w2
12033ba8  mov        x21, x0
12033bac  mov        w19, w2
12033bb0  mov        x0, x22
12033bb4  bl         #0x120aa304
12033bb8  mov        w1, wzr
12033bbc  mov        x2, x22
12033bc0  mov        x20, x0
12033bc4  bl         #0x120aa400
12033bc8  movz       w0, #0x1
12033bcc  bl         #0x12035fd0
12033bd0  mov        x0, x20
12033bd4  mov        w1, w19
12033bd8  bl         #0x12039728
12033bdc  adrp       x8, #0x120be000
12033be0  str        w0, [x8, #0xdc0]
12033be4  cbz        w0, #0x12033c08
12033be8  mov        x19, xzr
12033bec  b          #0x12033c1c
12033bf0  movz       w9, #0x65d8
12033bf4  adrp       x8, #0x120be000
12033bf8  mov        x19, xzr
12033bfc  movk       w9, #0xfffe, lsl #16
12033c00  str        w9, [x8, #0xdc0]
12033c04  b          #0x12033c2c
12033c08  mov        x0, x21
12033c0c  mov        x1, x20
12033c10  mov        w2, w19
12033c14  bl         #0x12036344
12033c18  mov        x19, x0
12033c1c  mov        x0, x20
12033c20  bl         #0x1208be10
12033c24  movn       w0, #0
12033c28  bl         #0x12035fd0
12033c2c  mov        x0, x19
12033c30  ldp        x20, x19, [sp, #0x20]
12033c34  ldp        x22, x21, [sp, #0x10]
12033c38  ldp        x29, x30, [sp], #0x30
12033c3c  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_encryptPassword
## base+0x329a8
================================================================================
120329a8  stp        x29, x30, [sp, #-0x60]!
120329ac  stp        x28, x27, [sp, #0x10]
120329b0  stp        x26, x25, [sp, #0x20]
120329b4  stp        x24, x23, [sp, #0x30]
120329b8  stp        x22, x21, [sp, #0x40]
120329bc  stp        x20, x19, [sp, #0x50]
120329c0  mov        x29, sp
120329c4  sub        sp, sp, #0x830
120329c8  str        w6, [sp, #0x1c]
120329cc  mrs        x8, tpidr_el0
120329d0  mov        x21, x5
120329d4  stp        x8, x4, [sp]
120329d8  mov        x19, x0
120329dc  mov        x23, x3
120329e0  ldr        x8, [x8, #0x28]
120329e4  mov        x24, x2
120329e8  adrp       x27, #0x120bf000
120329ec  adrp       x20, #0x120be000
120329f0  stur       x8, [x29, #-0x10]
120329f4  str        x0, [x27, #0x90]
120329f8  cbz        x0, #0x12032a58
120329fc  ldr        x8, [x20, #0xdb8]
12032a00  cbz        x8, #0x12032a58
12032a04  add        x0, sp, #0x420
12032a08  mov        w1, wzr
12032a0c  movz       w2, #0x400
12032a10  bl         #0x120aa400
12032a14  ldr        w5, [sp, #0x1c]
12032a18  adrp       x3, #0x12015000
12032a1c  add        x3, x3, #0xda8
12032a20  adrp       x4, #0x12015000
12032a24  add        x4, x4, #0xfb4
12032a28  add        x0, sp, #0x420
12032a2c  movz       w1, #0x400
12032a30  movz       w2, #0x400
12032a34  bl         #0x12032dfc
12032a38  add        x1, sp, #0x420
12032a3c  mov        x0, x19
12032a40  bl         #0x120363c0
12032a44  ldr        x1, [x20, #0xdb8]
12032a48  mov        x3, x0
12032a4c  mov        x0, x19
12032a50  mov        w2, wzr
12032a54  bl         #0x1203614c
12032a58  mov        x0, x19
12032a5c  mov        x1, x24
12032a60  bl         #0x120362e0
12032a64  mov        x26, x0
12032a68  mov        x0, x19
12032a6c  mov        x1, x21
12032a70  bl         #0x12036280
12032a74  mov        x25, x0
12032a78  mov        x0, x19
12032a7c  mov        x1, x24
12032a80  bl         #0x12036268
12032a84  mov        w28, w0
12032a88  cbz        x23, #0x12032ab0
12032a8c  mov        x0, x19
12032a90  mov        x1, x23
12032a94  bl         #0x120362e0
12032a98  mov        x22, x0
12032a9c  mov        x0, x19
12032aa0  mov        x1, x23
12032aa4  bl         #0x12036268
12032aa8  mov        w20, w0
12032aac  b          #0x12032ab8
12032ab0  mov        x22, xzr
12032ab4  mov        w20, wzr
12032ab8  add        x0, sp, #0x20
12032abc  mov        w1, wzr
12032ac0  movz       w2, #0x400
12032ac4  bl         #0x120aa400
12032ac8  ldr        x4, [sp, #8]
12032acc  ldr        w6, [sp, #0x1c]
12032ad0  add        x7, sp, #0x20
12032ad4  mov        x0, x26
12032ad8  mov        w1, w28
12032adc  mov        x2, x22
12032ae0  mov        w3, w20
12032ae4  mov        x5, x25
12032ae8  str        x22, [sp, #0x10]
12032aec  bl         #0x1203e54c
12032af0  ldr        x8, [x27, #0x90]
12032af4  mov        w22, w0
12032af8  adrp       x9, #0x120be000
12032afc  str        w0, [x9, #0xdc0]
12032b00  cbz        x8, #0x12032b40
12032b04  adrp       x27, #0x120be000
12032b08  ldr        x8, [x27, #0xdb8]
12032b0c  cbz        x8, #0x12032b3c
12032b10  adrp       x1, #0x12015000
12032b14  add        x1, x1, #0x63e
12032b18  mov        x0, x19
12032b1c  bl         #0x120363c0
12032b20  ldr        x1, [x27, #0xdb8]
12032b24  mov        x3, x0
12032b28  mov        x0, x19
12032b2c  mov        w2, w22
12032b30  bl         #0x1203614c
12032b34  adrp       x8, #0x120be000
12032b38  ldr        w22, [x8, #0xdc0]
12032b3c  adrp       x27, #0x120bf000
12032b40  cbz        w22, #0x12032c04
12032b44  bl         #0x12038d0c
12032b48  ldr        x8, [x27, #0x90]
12032b4c  adrp       x9, #0x120be000
12032b50  str        w0, [x9, #0xdc0]
12032b54  cbz        x8, #0x12032b90
12032b58  adrp       x8, #0x120be000
12032b5c  ldr        x8, [x8, #0xdb8]
12032b60  cbz        x8, #0x12032b90
12032b64  mov        w22, w0
12032b68  adrp       x1, #0x12015000
12032b6c  add        x1, x1, #0xcbf
12032b70  mov        x0, x19
12032b74  bl         #0x120363c0
12032b78  adrp       x8, #0x120be000
12032b7c  mov        x3, x0
12032b80  mov        x0, x19
12032b84  ldr        x1, [x8, #0xdb8]
12032b88  mov        w2, w22
12032b8c  bl         #0x1203614c
12032b90  ldp        x4, x2, [sp, #8]
12032b94  add        x7, sp, #0x20
12032b98  ldr        w6, [sp, #0x1c]
12032b9c  mov        x0, x26
12032ba0  mov        w1, w28
12032ba4  mov        w3, w20
12032ba8  mov        x5, x25
12032bac  bl         #0x1203e54c
12032bb0  ldr        x8, [x27, #0x90]
12032bb4  mov        w20, w0
12032bb8  adrp       x28, #0x120be000
12032bbc  adrp       x22, #0x120be000
12032bc0  str        w0, [x28, #0xdc0]
12032bc4  cbz        x8, #0x12032bf8
12032bc8  ldr        x8, [x22, #0xdb8]
12032bcc  cbz        x8, #0x12032bf8
12032bd0  adrp       x1, #0x12014000
12032bd4  add        x1, x1, #0x86b
12032bd8  mov        x0, x19
12032bdc  bl         #0x120363c0
12032be0  ldr        x1, [x22, #0xdb8]
12032be4  mov        x3, x0
12032be8  mov        x0, x19
12032bec  mov        w2, w20
12032bf0  bl         #0x1203614c
12032bf4  ldr        w20, [x28, #0xdc0]
12032bf8  ldr        x8, [x27, #0x90]
12032bfc  cbnz       x8, #0x12032c18
12032c00  b          #0x12032c48
12032c04  mov        w20, wzr
12032c08  adrp       x22, #0x120be000
12032c0c  adrp       x28, #0x120be000
12032c10  ldr        x8, [x27, #0x90]
12032c14  cbz        x8, #0x12032c48
12032c18  ldr        x8, [x22, #0xdb8]
12032c1c  cbz        x8, #0x12032c48
12032c20  adrp       x1, #0x12015000
12032c24  add        x1, x1, #0x13
12032c28  mov        x0, x19
12032c2c  bl         #0x120363c0
12032c30  ldr        x1, [x22, #0xdb8]
12032c34  mov        x3, x0
12032c38  mov        x0, x19
12032c3c  mov        w2, w20
12032c40  bl         #0x1203614c
12032c44  ldr        w20, [x28, #0xdc0]
12032c48  cbnz       w20, #0x12032cc0
12032c4c  add        x0, sp, #0x20
12032c50  movz       w1, #0x400
12032c54  bl         #0x120aa430
12032c58  ldr        x8, [x27, #0x90]
12032c5c  cbz        x8, #0x12032cc0
12032c60  ldr        x8, [x22, #0xdb8]
12032c64  cbz        x8, #0x12032cc0
12032c68  mov        x20, x0
12032c6c  add        x0, sp, #0x420
12032c70  mov        w1, wzr
12032c74  movz       w2, #0x400
12032c78  bl         #0x120aa400
12032c7c  adrp       x3, #0x12015000
12032c80  add        x3, x3, #0xda8
12032c84  adrp       x4, #0x12014000
12032c88  add        x4, x4, #0xf25
12032c8c  add        x0, sp, #0x420
12032c90  movz       w1, #0x400
12032c94  movz       w2, #0x400
12032c98  mov        w5, w20
12032c9c  bl         #0x12032dfc
12032ca0  add        x1, sp, #0x420
12032ca4  mov        x0, x19
12032ca8  bl         #0x120363c0
12032cac  ldr        x1, [x22, #0xdb8]
12032cb0  mov        x3, x0
12032cb4  mov        x0, x19
12032cb8  mov        w2, wzr
12032cbc  bl         #0x1203614c
12032cc0  mov        x0, x19
12032cc4  mov        x1, x24
12032cc8  mov        x2, x26
12032ccc  bl         #0x1203630c
12032cd0  ldr        x2, [sp, #0x10]
12032cd4  mov        x0, x19
12032cd8  mov        x1, x23
12032cdc  bl         #0x1203630c
12032ce0  mov        x0, x19
12032ce4  mov        x1, x21
12032ce8  mov        x2, x25
12032cec  bl         #0x120362ac
12032cf0  ldr        w2, [x28, #0xdc0]
12032cf4  cbz        w2, #0x12032d10
12032cf8  adrp       x1, #0x12015000
12032cfc  add        x1, x1, #0xfd2
12032d00  mov        x0, x19
12032d04  bl         #0x12035ff0
12032d08  mov        x0, xzr
12032d0c  b          #0x12032d20
12032d10  add        x1, sp, #0x20
12032d14  mov        x0, x19
12032d18  bl         #0x120363c0
12032d1c  cbz        x0, #0x12032d54
12032d20  ldr        x8, [sp]
12032d24  ldr        x8, [x8, #0x28]
12032d28  ldur       x9, [x29, #-0x10]
12032d2c  cmp        x8, x9
12032d30  b.ne       #0x12032df8
12032d34  add        sp, sp, #0x830
12032d38  ldp        x20, x19, [sp, #0x50]
12032d3c  ldp        x22, x21, [sp, #0x40]
12032d40  ldp        x24, x23, [sp, #0x30]
12032d44  ldp        x26, x25, [sp, #0x20]
12032d48  ldp        x28, x27, [sp, #0x10]
12032d4c  ldp        x29, x30, [sp], #0x60
12032d50  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm4CbcEncrypt
## base+0x35430
================================================================================
12035430  sub        sp, sp, #0x80
12035434  stp        x29, x30, [sp, #0x20]
12035438  stp        x28, x27, [sp, #0x30]
1203543c  stp        x26, x25, [sp, #0x40]
12035440  stp        x24, x23, [sp, #0x50]
12035444  stp        x22, x21, [sp, #0x60]
12035448  stp        x20, x19, [sp, #0x70]
1203544c  add        x29, sp, #0x20
12035450  mrs        x25, tpidr_el0
12035454  adrp       x9, #0x120bf000
12035458  ldr        x8, [x25, #0x28]
1203545c  stur       x8, [x29, #-8]
12035460  str        x0, [x9, #0x90]
12035464  cbz        x2, #0x12035560
12035468  mov        x21, x3
1203546c  cbz        x3, #0x12035560
12035470  mov        x20, x4
12035474  cbz        x4, #0x12035560
12035478  mov        x1, x2
1203547c  mov        x22, x2
12035480  mov        x19, x0
12035484  str        w5, [sp, #4]
12035488  bl         #0x120362e0
1203548c  str        x0, [sp, #8]
12035490  mov        x0, x19
12035494  mov        x1, x21
12035498  bl         #0x120362e0
1203549c  mov        x26, x0
120354a0  mov        x0, x19
120354a4  mov        x1, x20
120354a8  bl         #0x120362e0
120354ac  mov        x27, x0
120354b0  mov        x0, x19
120354b4  mov        x1, x22
120354b8  bl         #0x12036268
120354bc  add        w8, w0, #0x10
120354c0  mov        w28, w0
120354c4  sxtw       x24, w8
120354c8  stur       w8, [x29, #-0xc]
120354cc  mov        x0, x24
120354d0  bl         #0x120aa304
120354d4  mov        w1, wzr
120354d8  mov        x2, x24
120354dc  mov        x23, x0
120354e0  bl         #0x120aa400
120354e4  movz       w0, #0x1
120354e8  bl         #0x12035fd0
120354ec  ldr        w8, [sp, #4]
120354f0  ldr        x24, [sp, #8]
120354f4  sub        x3, x29, #0xc
120354f8  mov        w1, w28
120354fc  mov        x2, x23
12035500  mov        x4, x26
12035504  tst        w8, #0xff
12035508  mov        x0, x24
1203550c  mov        x5, x27
12035510  cset       w6, ne
12035514  bl         #0x1203973c
12035518  adrp       x28, #0x120be000
1203551c  mov        x1, x22
12035520  mov        x2, x24
12035524  str        w0, [x28, #0xdc0]
12035528  mov        x0, x19
1203552c  bl         #0x1203630c
12035530  mov        x0, x19
12035534  mov        x1, x21
12035538  mov        x2, x26
1203553c  bl         #0x1203630c
12035540  mov        x0, x19
12035544  mov        x1, x20
12035548  mov        x2, x27
1203554c  bl         #0x1203630c
12035550  ldr        w8, [x28, #0xdc0]
12035554  cbz        w8, #0x12035578
12035558  mov        x19, xzr
1203555c  b          #0x1203558c
12035560  movz       w9, #0x65d8
12035564  adrp       x8, #0x120be000
12035568  mov        x19, xzr
1203556c  movk       w9, #0xfffe, lsl #16
12035570  str        w9, [x8, #0xdc0]
12035574  b          #0x1203559c
12035578  ldur       w2, [x29, #-0xc]
1203557c  mov        x0, x19
12035580  mov        x1, x23
12035584  bl         #0x12036344
12035588  mov        x19, x0
1203558c  mov        x0, x23
12035590  bl         #0x1208be10
12035594  movn       w0, #0
12035598  bl         #0x12035fd0
1203559c  ldr        x8, [x25, #0x28]
120355a0  ldur       x9, [x29, #-8]
120355a4  cmp        x8, x9
120355a8  b.ne       #0x120355d0
120355ac  mov        x0, x19
120355b0  ldp        x20, x19, [sp, #0x70]
120355b4  ldp        x22, x21, [sp, #0x60]
120355b8  ldp        x24, x23, [sp, #0x50]
120355bc  ldp        x26, x25, [sp, #0x40]
120355c0  ldp        x28, x27, [sp, #0x30]
120355c4  ldp        x29, x30, [sp, #0x20]
120355c8  add        sp, sp, #0x80
120355cc  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm4CbcDecrypt
## base+0x355d4
================================================================================
120355d4  sub        sp, sp, #0x80
120355d8  stp        x29, x30, [sp, #0x20]
120355dc  stp        x28, x27, [sp, #0x30]
120355e0  stp        x26, x25, [sp, #0x40]
120355e4  stp        x24, x23, [sp, #0x50]
120355e8  stp        x22, x21, [sp, #0x60]
120355ec  stp        x20, x19, [sp, #0x70]
120355f0  add        x29, sp, #0x20
120355f4  mrs        x25, tpidr_el0
120355f8  adrp       x9, #0x120bf000
120355fc  ldr        x8, [x25, #0x28]
12035600  stur       x8, [x29, #-8]
12035604  str        x0, [x9, #0x90]
12035608  cbz        x2, #0x12035700
1203560c  mov        x21, x3
12035610  cbz        x3, #0x12035700
12035614  mov        x20, x4
12035618  cbz        x4, #0x12035700
1203561c  mov        x1, x2
12035620  mov        x22, x2
12035624  mov        x19, x0
12035628  str        w5, [sp, #4]
1203562c  bl         #0x120362e0
12035630  str        x0, [sp, #8]
12035634  mov        x0, x19
12035638  mov        x1, x21
1203563c  bl         #0x120362e0
12035640  mov        x26, x0
12035644  mov        x0, x19
12035648  mov        x1, x20
1203564c  bl         #0x120362e0
12035650  mov        x27, x0
12035654  mov        x0, x19
12035658  mov        x1, x22
1203565c  bl         #0x12036268
12035660  mov        w28, w0
12035664  stur       w0, [x29, #-0xc]
12035668  sxtw       x24, w28
1203566c  mov        x0, x24
12035670  bl         #0x120aa304
12035674  mov        w1, wzr
12035678  mov        x2, x24
1203567c  mov        x23, x0
12035680  bl         #0x120aa400
12035684  movz       w0, #0x1
12035688  bl         #0x12035fd0
1203568c  ldr        w8, [sp, #4]
12035690  ldr        x24, [sp, #8]
12035694  sub        x3, x29, #0xc
12035698  mov        w1, w28
1203569c  mov        x2, x23
120356a0  mov        x4, x26
120356a4  tst        w8, #0xff
120356a8  mov        x0, x24
120356ac  mov        x5, x27
120356b0  cset       w6, ne
120356b4  bl         #0x120397b4
120356b8  adrp       x28, #0x120be000
120356bc  mov        x1, x22
120356c0  mov        x2, x24
120356c4  str        w0, [x28, #0xdc0]
120356c8  mov        x0, x19
120356cc  bl         #0x1203630c
120356d0  mov        x0, x19
120356d4  mov        x1, x21
120356d8  mov        x2, x26
120356dc  bl         #0x1203630c
120356e0  mov        x0, x19
120356e4  mov        x1, x20
120356e8  mov        x2, x27
120356ec  bl         #0x1203630c
120356f0  ldr        w8, [x28, #0xdc0]
120356f4  cbz        w8, #0x12035718
120356f8  mov        x19, xzr
120356fc  b          #0x1203572c
12035700  movz       w9, #0x65d8
12035704  adrp       x8, #0x120be000
12035708  mov        x19, xzr
1203570c  movk       w9, #0xfffe, lsl #16
12035710  str        w9, [x8, #0xdc0]
12035714  b          #0x1203573c
12035718  ldur       w2, [x29, #-0xc]
1203571c  mov        x0, x19
12035720  mov        x1, x23
12035724  bl         #0x12036344
12035728  mov        x19, x0
1203572c  mov        x0, x23
12035730  bl         #0x1208be10
12035734  movn       w0, #0
12035738  bl         #0x12035fd0
1203573c  ldr        x8, [x25, #0x28]
12035740  ldur       x9, [x29, #-8]
12035744  cmp        x8, x9
12035748  b.ne       #0x12035770
1203574c  mov        x0, x19
12035750  ldp        x20, x19, [sp, #0x70]
12035754  ldp        x22, x21, [sp, #0x60]
12035758  ldp        x24, x23, [sp, #0x50]
1203575c  ldp        x26, x25, [sp, #0x40]
12035760  ldp        x28, x27, [sp, #0x30]
12035764  ldp        x29, x30, [sp, #0x20]
12035768  add        sp, sp, #0x80
1203576c  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm4GcmEncrypt
## base+0x35a98
================================================================================
12035a98  sub        sp, sp, #0xd0
12035a9c  stp        x29, x30, [sp, #0x70]
12035aa0  stp        x28, x27, [sp, #0x80]
12035aa4  stp        x26, x25, [sp, #0x90]
12035aa8  stp        x24, x23, [sp, #0xa0]
12035aac  stp        x22, x21, [sp, #0xb0]
12035ab0  stp        x20, x19, [sp, #0xc0]
12035ab4  add        x29, sp, #0x70
12035ab8  mrs        x10, tpidr_el0
12035abc  adrp       x9, #0x120bf000
12035ac0  ldr        x8, [x10, #0x28]
12035ac4  stur       x8, [x29, #-8]
12035ac8  str        x0, [x9, #0x90]
12035acc  cbz        x2, #0x12035d48
12035ad0  mov        x23, x3
12035ad4  cbz        x3, #0x12035d48
12035ad8  mov        x22, x4
12035adc  cbz        x4, #0x12035d48
12035ae0  mov        x1, x2
12035ae4  mov        x21, x5
12035ae8  mov        x24, x2
12035aec  mov        x19, x0
12035af0  stur       x10, [x29, #-0x30]
12035af4  bl         #0x120362e0
12035af8  str        x0, [sp, #0x38]
12035afc  mov        x0, x19
12035b00  mov        x1, x23
12035b04  bl         #0x120362e0
12035b08  str        x0, [sp, #0x30]
12035b0c  mov        x0, x19
12035b10  mov        x1, x22
12035b14  bl         #0x120362e0
12035b18  str        x0, [sp, #0x28]
12035b1c  mov        x0, x19
12035b20  mov        x1, x21
12035b24  bl         #0x120362e0
12035b28  mov        x28, x0
12035b2c  mov        x0, x19
12035b30  mov        x1, x24
12035b34  bl         #0x12036268
12035b38  mov        w20, w0
12035b3c  mov        x0, x19
12035b40  mov        x1, x22
12035b44  bl         #0x12036268
12035b48  str        w0, [sp, #0x24]
12035b4c  mov        x0, x19
12035b50  mov        x1, x21
12035b54  bl         #0x12036268
12035b58  add        w8, w20, #0x10
12035b5c  mov        w27, w0
12035b60  sxtw       x26, w8
12035b64  stur       w8, [x29, #-0x1c]
12035b68  mov        x0, x26
12035b6c  bl         #0x120aa304
12035b70  mov        w1, wzr
12035b74  mov        x2, x26
12035b78  mov        x25, x0
12035b7c  bl         #0x120aa400
12035b80  movz       w0, #0x1
12035b84  bl         #0x12035fd0
12035b88  str        w27, [sp, #0x10]
12035b8c  mov        x2, x25
12035b90  movz       w8, #0x10
12035b94  stur       x25, [x29, #-0x28]
12035b98  ldp        x25, x27, [sp, #0x28]
12035b9c  ldr        x26, [sp, #0x38]
12035ba0  stur       w8, [x29, #-0x20]
12035ba4  sub        x3, x29, #0x1c
12035ba8  ldr        w8, [sp, #0x24]
12035bac  sub        x4, x29, #0x18
12035bb0  sub        x5, x29, #0x20
12035bb4  mov        x0, x26
12035bb8  mov        w1, w20
12035bbc  mov        x6, x27
12035bc0  mov        x7, x25
12035bc4  stp        xzr, xzr, [x29, #-0x18]
12035bc8  str        x28, [sp, #8]
12035bcc  str        w8, [sp]
12035bd0  bl         #0x1203991c
12035bd4  adrp       x20, #0x120be000
12035bd8  mov        x1, x24
12035bdc  mov        x2, x26
12035be0  str        w0, [x20, #0xdc0]
12035be4  mov        x0, x19
12035be8  bl         #0x1203630c
12035bec  mov        x0, x19
12035bf0  mov        x1, x23
12035bf4  mov        x2, x27
12035bf8  bl         #0x1203630c
12035bfc  mov        x0, x19
12035c00  mov        x1, x22
12035c04  mov        x2, x25
12035c08  bl         #0x1203630c
12035c0c  mov        x0, x19
12035c10  mov        x1, x21
12035c14  mov        x2, x28
12035c18  bl         #0x1203630c
12035c1c  ldr        w8, [x20, #0xdc0]
12035c20  mov        x21, xzr
12035c24  cbnz       w8, #0x12035d30
12035c28  ldr        x8, [x19]
12035c2c  adrp       x1, #0x12015000
12035c30  add        x1, x1, #0xb92
12035c34  mov        x0, x19
12035c38  ldr        x8, [x8, #0x30]
12035c3c  blr        x8
12035c40  ldr        x8, [x19]
12035c44  mov        x2, x0
12035c48  mov        x0, x19
12035c4c  movz       w1, #0x2
12035c50  mov        x3, xzr
12035c54  ldr        x8, [x8, #0x560]
12035c58  blr        x8
12035c5c  ldr        x8, [x19]
12035c60  ldur       w1, [x29, #-0x1c]
12035c64  mov        x21, x0
12035c68  mov        x0, x19
12035c6c  ldr        x8, [x8, #0x580]
12035c70  blr        x8
12035c74  ldr        x8, [x19]
12035c78  ldur       w3, [x29, #-0x1c]
12035c7c  mov        x20, x0
12035c80  ldur       x4, [x29, #-0x28]
12035c84  mov        x0, x19
12035c88  mov        x1, x20
12035c8c  ldr        x8, [x8, #0x680]
12035c90  mov        w2, wzr
12035c94  blr        x8
12035c98  ldr        x8, [x19]
12035c9c  mov        x0, x19
12035ca0  mov        x1, x21
12035ca4  mov        w2, wzr
12035ca8  mov        x3, x20
12035cac  ldr        x8, [x8, #0x570]
12035cb0  blr        x8
12035cb4  ldr        x8, [x19]
12035cb8  mov        x0, x19
12035cbc  mov        x1, x20
12035cc0  ldr        x8, [x8, #0xb8]
12035cc4  blr        x8
12035cc8  ldr        x8, [x19]
12035ccc  ldur       w1, [x29, #-0x20]
12035cd0  mov        x0, x19
12035cd4  ldr        x8, [x8, #0x580]
12035cd8  blr        x8
12035cdc  ldr        x8, [x19]
12035ce0  ldur       w3, [x29, #-0x20]
12035ce4  mov        x20, x0
12035ce8  sub        x4, x29, #0x18
12035cec  mov        x0, x19
12035cf0  mov        x1, x20
12035cf4  ldr        x8, [x8, #0x680]
12035cf8  mov        w2, wzr
12035cfc  blr        x8
12035d00  ldr        x8, [x19]
12035d04  mov        x0, x19
12035d08  mov        x1, x21
12035d0c  movz       w2, #0x1
12035d10  mov        x3, x20
12035d14  ldr        x8, [x8, #0x570]
12035d18  blr        x8
12035d1c  ldr        x8, [x19]
12035d20  mov        x0, x19
12035d24  mov        x1, x20
12035d28  ldr        x8, [x8, #0xb8]
12035d2c  blr        x8
12035d30  ldur       x0, [x29, #-0x28]
12035d34  bl         #0x1208be10
12035d38  movn       w0, #0
12035d3c  bl         #0x12035fd0
12035d40  ldur       x10, [x29, #-0x30]
12035d44  b          #0x12035d5c
12035d48  movz       w9, #0x65d8
12035d4c  adrp       x8, #0x120be000
12035d50  mov        x21, xzr
12035d54  movk       w9, #0xfffe, lsl #16
12035d58  str        w9, [x8, #0xdc0]
12035d5c  ldr        x8, [x10, #0x28]
12035d60  ldur       x9, [x29, #-8]
12035d64  cmp        x8, x9
12035d68  b.ne       #0x12035d90
12035d6c  mov        x0, x21
12035d70  ldp        x20, x19, [sp, #0xc0]
12035d74  ldp        x22, x21, [sp, #0xb0]
12035d78  ldp        x24, x23, [sp, #0xa0]
12035d7c  ldp        x26, x25, [sp, #0x90]
12035d80  ldp        x28, x27, [sp, #0x80]
12035d84  ldp        x29, x30, [sp, #0x70]
12035d88  add        sp, sp, #0xd0
12035d8c  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm4CtrEncrypt
## base+0x35774
================================================================================
12035774  sub        sp, sp, #0x80
12035778  stp        x29, x30, [sp, #0x20]
1203577c  stp        x28, x27, [sp, #0x30]
12035780  stp        x26, x25, [sp, #0x40]
12035784  stp        x24, x23, [sp, #0x50]
12035788  stp        x22, x21, [sp, #0x60]
1203578c  stp        x20, x19, [sp, #0x70]
12035790  add        x29, sp, #0x20
12035794  mrs        x24, tpidr_el0
12035798  adrp       x9, #0x120bf000
1203579c  ldr        x8, [x24, #0x28]
120357a0  stur       x8, [x29, #-8]
120357a4  str        x0, [x9, #0x90]
120357a8  cbz        x2, #0x12035894
120357ac  mov        x21, x3
120357b0  cbz        x3, #0x12035894
120357b4  mov        x20, x4
120357b8  cbz        x4, #0x12035894
120357bc  mov        x1, x2
120357c0  mov        x22, x2
120357c4  mov        x19, x0
120357c8  bl         #0x120362e0
120357cc  str        x0, [sp, #8]
120357d0  mov        x0, x19
120357d4  mov        x1, x21
120357d8  bl         #0x120362e0
120357dc  mov        x25, x0
120357e0  mov        x0, x19
120357e4  mov        x1, x20
120357e8  bl         #0x120362e0
120357ec  mov        x26, x0
120357f0  mov        x0, x19
120357f4  mov        x1, x22
120357f8  bl         #0x12036268
120357fc  add        w8, w0, #0x10
12035800  mov        w27, w0
12035804  sxtw       x28, w8
12035808  stur       w8, [x29, #-0xc]
1203580c  mov        x0, x28
12035810  bl         #0x120aa304
12035814  mov        w1, wzr
12035818  mov        x2, x28
1203581c  mov        x23, x0
12035820  bl         #0x120aa400
12035824  movz       w0, #0x1
12035828  bl         #0x12035fd0
1203582c  ldr        x28, [sp, #8]
12035830  sub        x3, x29, #0xc
12035834  mov        w1, w27
12035838  mov        x2, x23
1203583c  mov        x4, x25
12035840  mov        x5, x26
12035844  mov        x0, x28
12035848  bl         #0x1203982c
1203584c  adrp       x27, #0x120be000
12035850  mov        x1, x22
12035854  mov        x2, x28
12035858  str        w0, [x27, #0xdc0]
1203585c  mov        x0, x19
12035860  bl         #0x1203630c
12035864  mov        x0, x19
12035868  mov        x1, x21
1203586c  mov        x2, x25
12035870  bl         #0x1203630c
12035874  mov        x0, x19
12035878  mov        x1, x20
1203587c  mov        x2, x26
12035880  bl         #0x1203630c
12035884  ldr        w8, [x27, #0xdc0]
12035888  cbz        w8, #0x120358ac
1203588c  mov        x19, xzr
12035890  b          #0x120358c0
12035894  movz       w9, #0x65d8
12035898  adrp       x8, #0x120be000
1203589c  mov        x19, xzr
120358a0  movk       w9, #0xfffe, lsl #16
120358a4  str        w9, [x8, #0xdc0]
120358a8  b          #0x120358d0
120358ac  ldur       w2, [x29, #-0xc]
120358b0  mov        x0, x19
120358b4  mov        x1, x23
120358b8  bl         #0x12036344
120358bc  mov        x19, x0
120358c0  mov        x0, x23
120358c4  bl         #0x1208be10
120358c8  movn       w0, #0
120358cc  bl         #0x12035fd0
120358d0  ldr        x8, [x24, #0x28]
120358d4  ldur       x9, [x29, #-8]
120358d8  cmp        x8, x9
120358dc  b.ne       #0x12035904
120358e0  mov        x0, x19
120358e4  ldp        x20, x19, [sp, #0x70]
120358e8  ldp        x22, x21, [sp, #0x60]
120358ec  ldp        x24, x23, [sp, #0x50]
120358f0  ldp        x26, x25, [sp, #0x40]
120358f4  ldp        x28, x27, [sp, #0x30]
120358f8  ldp        x29, x30, [sp, #0x20]
120358fc  add        sp, sp, #0x80
12035900  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm2GenKeyPair
## base+0x33c40
================================================================================
12033c40  sub        sp, sp, #0x1a0
12033c44  stp        x29, x30, [sp, #0x150]
12033c48  str        x28, [sp, #0x160]
12033c4c  stp        x24, x23, [sp, #0x170]
12033c50  stp        x22, x21, [sp, #0x180]
12033c54  stp        x20, x19, [sp, #0x190]
12033c58  add        x29, sp, #0x150
12033c5c  mrs        x24, tpidr_el0
12033c60  movi       v0.2d, #0000000000000000
12033c64  mov        x19, x0
12033c68  ldr        x8, [x24, #0x28]
12033c6c  add        x1, sp, #0x70
12033c70  stur       x8, [x29, #-8]
12033c74  adrp       x8, #0x120bf000
12033c78  str        x0, [x8, #0x90]
12033c7c  sub        x0, x29, #0x50
12033c80  sturb      wzr, [x29, #-0x10]
12033c84  stp        q0, q0, [x29, #-0x50]
12033c88  stp        q0, q0, [x29, #-0x30]
12033c8c  stur       wzr, [sp, #0xef]
12033c90  stp        q0, q0, [sp, #0x70]
12033c94  stp        q0, q0, [sp, #0x90]
12033c98  stp        q0, q0, [sp, #0xb0]
12033c9c  stp        q0, q0, [sp, #0xd0]
12033ca0  bl         #0x12038d28
12033ca4  adrp       x8, #0x120be000
12033ca8  str        w0, [x8, #0xdc0]
12033cac  cbz        w0, #0x12033cb8
12033cb0  mov        x0, xzr
12033cb4  b          #0x12033e30
12033cb8  movi       v0.2d, #0000000000000000
12033cbc  sub        x0, x29, #0x50
12033cc0  movz       w1, #0x41
12033cc4  strb       wzr, [sp, #0x40]
12033cc8  stp        q0, q0, [sp]
12033ccc  stp        q0, q0, [sp, #0x20]
12033cd0  stp        q0, q0, [sp, #0x50]
12033cd4  bl         #0x120aa430
12033cd8  mov        x20, x0
12033cdc  add        x0, sp, #0x70
12033ce0  movz       w1, #0x83
12033ce4  bl         #0x120aa430
12033ce8  mov        x21, x0
12033cec  sub        x0, x29, #0x50
12033cf0  add        x2, sp, #0x50
12033cf4  mov        w1, w20
12033cf8  bl         #0x120366c8
12033cfc  add        x0, sp, #0x70
12033d00  mov        x2, sp
12033d04  mov        w1, w21
12033d08  bl         #0x120366c8
12033d0c  cmp        w20, #0
12033d10  ldr        x9, [x19]
12033d14  adrp       x1, #0x12015000
12033d18  add        x1, x1, #0xb92
12033d1c  cinc       w8, w20, lt
12033d20  cmp        w21, #0
12033d24  asr        w22, w8, #1
12033d28  ldr        x8, [x9, #0x30]
12033d2c  cinc       w10, w21, lt
12033d30  mov        x0, x19
12033d34  asr        w20, w10, #1
12033d38  blr        x8
12033d3c  ldr        x8, [x19]
12033d40  mov        x2, x0
12033d44  mov        x0, x19
12033d48  movz       w1, #0x2
12033d4c  mov        x3, xzr
12033d50  ldr        x8, [x8, #0x560]
12033d54  blr        x8
12033d58  ldr        x8, [x19]
12033d5c  mov        x21, x0
12033d60  mov        x0, x19
12033d64  mov        w1, w22
12033d68  ldr        x8, [x8, #0x580]
12033d6c  blr        x8
12033d70  ldr        x8, [x19]
12033d74  mov        x23, x0
12033d78  add        x4, sp, #0x50
12033d7c  mov        x0, x19
12033d80  mov        x1, x23
12033d84  mov        w2, wzr
12033d88  ldr        x8, [x8, #0x680]
12033d8c  mov        w3, w22
12033d90  blr        x8
12033d94  ldr        x8, [x19]
12033d98  mov        x0, x19
12033d9c  mov        x1, x21
12033da0  mov        w2, wzr
12033da4  mov        x3, x23
12033da8  ldr        x8, [x8, #0x570]
12033dac  blr        x8
12033db0  ldr        x8, [x19]
12033db4  mov        x0, x19
12033db8  mov        x1, x23
12033dbc  ldr        x8, [x8, #0xb8]
12033dc0  blr        x8
12033dc4  ldr        x8, [x19]
12033dc8  mov        x0, x19
12033dcc  mov        w1, w20
12033dd0  ldr        x8, [x8, #0x580]
12033dd4  blr        x8
12033dd8  ldr        x8, [x19]
12033ddc  mov        x22, x0
12033de0  mov        x4, sp
12033de4  mov        x0, x19
12033de8  mov        x1, x22
12033dec  mov        w2, wzr
12033df0  ldr        x8, [x8, #0x680]
12033df4  mov        w3, w20
12033df8  blr        x8
12033dfc  ldr        x8, [x19]
12033e00  mov        x0, x19
12033e04  mov        x1, x21
12033e08  movz       w2, #0x1
12033e0c  mov        x3, x22
12033e10  ldr        x8, [x8, #0x570]
12033e14  blr        x8
12033e18  ldr        x8, [x19]
12033e1c  mov        x0, x19
12033e20  mov        x1, x22
12033e24  ldr        x8, [x8, #0xb8]
12033e28  blr        x8
12033e2c  mov        x0, x21
12033e30  ldr        x8, [x24, #0x28]
12033e34  ldur       x9, [x29, #-8]
12033e38  cmp        x8, x9
12033e3c  b.ne       #0x12033e5c
12033e40  ldp        x20, x19, [sp, #0x190]
12033e44  ldr        x28, [sp, #0x160]
12033e48  ldp        x22, x21, [sp, #0x180]
12033e4c  ldp        x24, x23, [sp, #0x170]
12033e50  ldp        x29, x30, [sp, #0x150]
12033e54  add        sp, sp, #0x1a0
12033e58  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm2GenPublicKey
## base+0x33e60
================================================================================
12033e60  sub        sp, sp, #0x180
12033e64  stp        x29, x30, [sp, #0x130]
12033e68  str        x28, [sp, #0x140]
12033e6c  stp        x24, x23, [sp, #0x150]
12033e70  stp        x22, x21, [sp, #0x160]
12033e74  stp        x20, x19, [sp, #0x170]
12033e78  add        x29, sp, #0x130
12033e7c  mrs        x23, tpidr_el0
12033e80  adrp       x9, #0x120bf000
12033e84  mov        x1, x2
12033e88  ldr        x8, [x23, #0x28]
12033e8c  mov        x20, x2
12033e90  mov        x19, x0
12033e94  stur       x8, [x29, #-8]
12033e98  str        x0, [x9, #0x90]
12033e9c  bl         #0x12036268
12033ea0  cmp        w0, #0x21
12033ea4  b.lt       #0x12033ec0
12033ea8  movz       w9, #0x65d8
12033eac  adrp       x8, #0x120be000
12033eb0  mov        x0, xzr
12033eb4  movk       w9, #0xfffe, lsl #16
12033eb8  str        w9, [x8, #0xdc0]
12033ebc  b          #0x12033f80
12033ec0  mov        w22, w0
12033ec4  mov        x0, x19
12033ec8  mov        x1, x20
12033ecc  bl         #0x120362e0
12033ed0  movi       v0.2d, #0000000000000000
12033ed4  sub        x2, x29, #0x50
12033ed8  mov        w1, w22
12033edc  mov        x21, x0
12033ee0  sturb      wzr, [x29, #-0x10]
12033ee4  stur       wzr, [sp, #0xcf]
12033ee8  stp        q0, q0, [x29, #-0x50]
12033eec  stp        q0, q0, [x29, #-0x30]
12033ef0  stp        q0, q0, [sp, #0x50]
12033ef4  stp        q0, q0, [sp, #0x70]
12033ef8  stp        q0, q0, [sp, #0x90]
12033efc  stp        q0, q0, [sp, #0xb0]
12033f00  bl         #0x120364c4
12033f04  sub        x0, x29, #0x50
12033f08  add        x1, sp, #0x50
12033f0c  bl         #0x12038da4
12033f10  movi       v0.2d, #0000000000000000
12033f14  adrp       x24, #0x120be000
12033f18  movz       w1, #0x83
12033f1c  str        w0, [x24, #0xdc0]
12033f20  add        x0, sp, #0x50
12033f24  strb       wzr, [sp, #0x40]
12033f28  stp        q0, q0, [sp]
12033f2c  stp        q0, q0, [sp, #0x20]
12033f30  bl         #0x120aa430
12033f34  mov        x22, x0
12033f38  add        x0, sp, #0x50
12033f3c  mov        x2, sp
12033f40  mov        w1, w22
12033f44  bl         #0x120366c8
12033f48  mov        x0, x19
12033f4c  mov        x1, x20
12033f50  mov        x2, x21
12033f54  bl         #0x1203630c
12033f58  ldr        w8, [x24, #0xdc0]
12033f5c  cbz        w8, #0x12033f68
12033f60  mov        x0, xzr
12033f64  b          #0x12033f80
12033f68  cmp        w22, #0
12033f6c  mov        x1, sp
12033f70  mov        x0, x19
12033f74  cinc       w8, w22, lt
12033f78  asr        w2, w8, #1
12033f7c  bl         #0x12036344
12033f80  ldr        x8, [x23, #0x28]
12033f84  ldur       x9, [x29, #-8]
12033f88  cmp        x8, x9
12033f8c  b.ne       #0x12033fac
12033f90  ldp        x20, x19, [sp, #0x170]
12033f94  ldr        x28, [sp, #0x140]
12033f98  ldp        x22, x21, [sp, #0x160]
12033f9c  ldp        x24, x23, [sp, #0x150]
12033fa0  ldp        x29, x30, [sp, #0x130]
12033fa4  add        sp, sp, #0x180
12033fa8  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm2Sign
## base+0x34644
================================================================================
12034644  stp        x29, x30, [sp, #-0x60]!
12034648  stp        x28, x27, [sp, #0x10]
1203464c  stp        x26, x25, [sp, #0x20]
12034650  stp        x24, x23, [sp, #0x30]
12034654  stp        x22, x21, [sp, #0x40]
12034658  stp        x20, x19, [sp, #0x50]
1203465c  mov        x29, sp
12034660  sub        sp, sp, #0x1b0
12034664  mrs        x24, tpidr_el0
12034668  adrp       x9, #0x120bf000
1203466c  mov        x1, x4
12034670  ldr        x8, [x24, #0x28]
12034674  mov        x20, x5
12034678  mov        x21, x4
1203467c  mov        x22, x3
12034680  mov        x19, x0
12034684  mov        x23, x2
12034688  stur       x8, [x29, #-0x18]
1203468c  str        x0, [x9, #0x90]
12034690  bl         #0x12036268
12034694  mov        w27, w0
12034698  mov        x0, x19
1203469c  mov        x1, x20
120346a0  bl         #0x12036268
120346a4  cmp        w27, #0x20
120346a8  b.gt       #0x120347e8
120346ac  cmp        w0, #0x42
120346b0  b.ge       #0x120347e8
120346b4  mov        x0, x19
120346b8  mov        x1, x23
120346bc  str        x24, [sp, #0x28]
120346c0  add        x25, sp, #0xc0
120346c4  bl         #0x120362e0
120346c8  str        x0, [sp, #0x40]
120346cc  mov        x0, x19
120346d0  mov        x1, x21
120346d4  bl         #0x120362e0
120346d8  mov        x24, x0
120346dc  mov        x0, x19
120346e0  mov        x1, x22
120346e4  bl         #0x120362e0
120346e8  str        x0, [sp, #0x30]
120346ec  mov        x0, x19
120346f0  mov        x1, x23
120346f4  bl         #0x12036268
120346f8  str        w0, [sp, #0x1c]
120346fc  mov        x0, x19
12034700  mov        x1, x22
12034704  str        x22, [sp, #0x20]
12034708  bl         #0x12036268
1203470c  movi       v0.2d, #0000000000000000
12034710  str        w0, [sp, #0x18]
12034714  sub        x2, x29, #0x60
12034718  mov        x0, x24
1203471c  mov        w1, w27
12034720  sturb      wzr, [x29, #-0x20]
12034724  str        x24, [sp, #0x38]
12034728  stp        q0, q0, [x25, #0x90]
1203472c  stp        q0, q0, [x25, #0xb0]
12034730  bl         #0x120364c4
12034734  movi       v0.2d, #0000000000000000
12034738  adrp       x22, #0x120be000
1203473c  stur       wzr, [x25, #0x7f]
12034740  str        wzr, [sp, #0xb0]
12034744  str        wzr, [sp, #0x4c]
12034748  stp        q0, q0, [x25, #0x20]
1203474c  stp        q0, q0, [x25, #0x40]
12034750  stp        q0, q0, [x25, #0x60]
12034754  str        q0, [x25, #0x10]
12034758  str        q0, [sp, #0xc0]
1203475c  stp        q0, q0, [sp, #0x50]
12034760  stp        q0, q0, [sp, #0x70]
12034764  stp        q0, q0, [sp, #0x90]
12034768  cbz        x20, #0x12034800
1203476c  mov        x0, x19
12034770  mov        x1, x20
12034774  bl         #0x120362e0
12034778  mov        x25, x0
1203477c  mov        x0, x19
12034780  mov        x1, x20
12034784  bl         #0x12036268
12034788  mov        w1, w0
1203478c  add        x2, sp, #0xc0
12034790  mov        x0, x25
12034794  bl         #0x120364c4
12034798  ldr        x24, [sp, #0x40]
1203479c  ldr        x26, [sp, #0x30]
120347a0  add        x0, sp, #0xc0
120347a4  movz       w1, #0x83
120347a8  lsl        w27, w27, #1
120347ac  bl         #0x120aa430
120347b0  ldp        w3, w1, [sp, #0x18]
120347b4  mov        x5, x0
120347b8  add        x8, sp, #0x4c
120347bc  add        x9, sp, #0x50
120347c0  add        x4, sp, #0xc0
120347c4  sub        x6, x29, #0x60
120347c8  mov        x0, x24
120347cc  mov        x2, x26
120347d0  mov        w7, w27
120347d4  stp        x9, x8, [sp]
120347d8  bl         #0x12039160
120347dc  mov        x28, x25
120347e0  str        w0, [x22, #0xdc0]
120347e4  b          #0x12034824
120347e8  movz       w9, #0x65d8
120347ec  adrp       x8, #0x120be000
120347f0  mov        x0, xzr
120347f4  movk       w9, #0xfffe, lsl #16
120347f8  str        w9, [x8, #0xdc0]
120347fc  b          #0x12034888
12034800  sub        x0, x29, #0x60
12034804  add        x1, sp, #0xc0
12034808  bl         #0x12038da4
1203480c  ldr        x24, [sp, #0x40]
12034810  ldr        x26, [sp, #0x30]
12034814  mov        x25, xzr
12034818  mov        x28, xzr
1203481c  str        w0, [x22, #0xdc0]
12034820  cbz        w0, #0x120347a0
12034824  mov        x0, x19
12034828  mov        x1, x23
1203482c  mov        x2, x24
12034830  bl         #0x1203630c
12034834  ldr        x1, [sp, #0x20]
12034838  mov        x0, x19
1203483c  mov        x2, x26
12034840  bl         #0x1203630c
12034844  ldr        x2, [sp, #0x38]
12034848  mov        x0, x19
1203484c  mov        x1, x21
12034850  bl         #0x1203630c
12034854  mov        x0, x19
12034858  mov        x1, x20
1203485c  mov        x2, x28
12034860  bl         #0x1203630c
12034864  ldr        w8, [x22, #0xdc0]
12034868  cbz        w8, #0x12034874
1203486c  mov        x0, xzr
12034870  b          #0x12034884
12034874  ldr        w2, [sp, #0x4c]
12034878  add        x1, sp, #0x50
1203487c  mov        x0, x19
12034880  bl         #0x12036344
12034884  ldr        x24, [sp, #0x28]
12034888  ldr        x8, [x24, #0x28]
1203488c  ldur       x9, [x29, #-0x18]
12034890  cmp        x8, x9
12034894  b.ne       #0x120348b8
12034898  add        sp, sp, #0x1b0
1203489c  ldp        x20, x19, [sp, #0x50]
120348a0  ldp        x22, x21, [sp, #0x40]
120348a4  ldp        x24, x23, [sp, #0x30]
120348a8  ldp        x26, x25, [sp, #0x20]
120348ac  ldp        x28, x27, [sp, #0x10]
120348b0  ldp        x29, x30, [sp], #0x60
120348b4  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm2Verify
## base+0x348bc
================================================================================
120348bc  sub        sp, sp, #0x130
120348c0  stp        x29, x30, [sp, #0xd0]
120348c4  stp        x28, x27, [sp, #0xe0]
120348c8  stp        x26, x25, [sp, #0xf0]
120348cc  stp        x24, x23, [sp, #0x100]
120348d0  stp        x22, x21, [sp, #0x110]
120348d4  stp        x20, x19, [sp, #0x120]
120348d8  add        x29, sp, #0xd0
120348dc  mrs        x24, tpidr_el0
120348e0  adrp       x9, #0x120bf000
120348e4  mov        x1, x5
120348e8  ldr        x8, [x24, #0x28]
120348ec  mov        x19, x5
120348f0  mov        x21, x4
120348f4  mov        x22, x3
120348f8  mov        x20, x0
120348fc  mov        x23, x2
12034900  stur       x8, [x29, #-0x10]
12034904  str        x0, [x9, #0x90]
12034908  bl         #0x12036268
1203490c  cmp        w0, #0x42
12034910  b.lt       #0x1203492c
12034914  movz       w9, #0x65d8
12034918  adrp       x8, #0x120be000
1203491c  mov        w0, wzr
12034920  movk       w9, #0xfffe, lsl #16
12034924  str        w9, [x8, #0xdc0]
12034928  b          #0x12034a4c
1203492c  mov        w28, w0
12034930  mov        x0, x20
12034934  mov        x1, x23
12034938  bl         #0x120362e0
1203493c  mov        x26, x0
12034940  mov        x0, x20
12034944  mov        x1, x22
12034948  bl         #0x120362e0
1203494c  str        x0, [sp, #0x28]
12034950  mov        x0, x20
12034954  mov        x1, x21
12034958  bl         #0x120362e0
1203495c  str        x0, [sp, #0x20]
12034960  mov        x0, x20
12034964  mov        x1, x19
12034968  bl         #0x120362e0
1203496c  mov        x25, x0
12034970  str        x0, [sp, #0x10]
12034974  mov        x0, x20
12034978  mov        x1, x23
1203497c  bl         #0x12036268
12034980  str        w0, [sp, #0x1c]
12034984  mov        x0, x20
12034988  mov        x1, x22
1203498c  bl         #0x12036268
12034990  str        w0, [sp, #0xc]
12034994  mov        x0, x20
12034998  mov        x1, x21
1203499c  bl         #0x12036268
120349a0  movi       v0.2d, #0000000000000000
120349a4  str        w0, [sp, #8]
120349a8  add        x2, sp, #0x30
120349ac  mov        x0, x25
120349b0  mov        w1, w28
120349b4  stur       wzr, [sp, #0xaf]
120349b8  lsl        w27, w28, #1
120349bc  stp        q0, q0, [sp, #0x30]
120349c0  stp        q0, q0, [sp, #0x50]
120349c4  stp        q0, q0, [sp, #0x70]
120349c8  stp        q0, q0, [sp, #0x90]
120349cc  bl         #0x120364c4
120349d0  mov        x28, x26
120349d4  mov        x0, x26
120349d8  ldr        w1, [sp, #0x1c]
120349dc  ldp        x26, x25, [sp, #0x20]
120349e0  add        x6, sp, #0x30
120349e4  ldp        w5, w3, [sp, #8]
120349e8  mov        w7, w27
120349ec  mov        x2, x25
120349f0  mov        x4, x26
120349f4  bl         #0x12039258
120349f8  adrp       x27, #0x120be000
120349fc  mov        x1, x23
12034a00  mov        x2, x28
12034a04  str        w0, [x27, #0xdc0]
12034a08  mov        x0, x20
12034a0c  bl         #0x1203630c
12034a10  mov        x0, x20
12034a14  mov        x1, x22
12034a18  mov        x2, x25
12034a1c  bl         #0x1203630c
12034a20  mov        x0, x20
12034a24  mov        x1, x21
12034a28  mov        x2, x26
12034a2c  bl         #0x1203630c
12034a30  ldr        x2, [sp, #0x10]
12034a34  mov        x0, x20
12034a38  mov        x1, x19
12034a3c  bl         #0x1203630c
12034a40  ldr        w8, [x27, #0xdc0]
12034a44  cmp        w8, #0
12034a48  cset       w0, eq
12034a4c  ldr        x8, [x24, #0x28]
12034a50  ldur       x9, [x29, #-0x10]
12034a54  cmp        x8, x9
12034a58  b.ne       #0x12034a7c
12034a5c  ldp        x20, x19, [sp, #0x120]
12034a60  ldp        x22, x21, [sp, #0x110]
12034a64  ldp        x24, x23, [sp, #0x100]
12034a68  ldp        x26, x25, [sp, #0xf0]
12034a6c  ldp        x28, x27, [sp, #0xe0]
12034a70  ldp        x29, x30, [sp, #0xd0]
12034a74  add        sp, sp, #0x130
12034a78  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm2Encrypt
## base+0x33fb0
================================================================================
12033fb0  sub        sp, sp, #0x100
12033fb4  stp        x29, x30, [sp, #0xa0]
12033fb8  stp        x28, x27, [sp, #0xb0]
12033fbc  stp        x26, x25, [sp, #0xc0]
12033fc0  stp        x24, x23, [sp, #0xd0]
12033fc4  stp        x22, x21, [sp, #0xe0]
12033fc8  stp        x20, x19, [sp, #0xf0]
12033fcc  add        x29, sp, #0xa0
12033fd0  mrs        x28, tpidr_el0
12033fd4  adrp       x9, #0x120bf000
12033fd8  mov        x1, x3
12033fdc  ldr        x8, [x28, #0x28]
12033fe0  mov        x20, x3
12033fe4  mov        x21, x2
12033fe8  mov        x19, x0
12033fec  stur       x8, [x29, #-8]
12033ff0  str        x0, [x9, #0x90]
12033ff4  bl         #0x12036268
12033ff8  cmp        w0, #0x42
12033ffc  b.lt       #0x12034018
12034000  movz       w9, #0x65d8
12034004  adrp       x8, #0x120be000
12034008  mov        x19, xzr
1203400c  movk       w9, #0xfffe, lsl #16
12034010  str        w9, [x8, #0xdc0]
12034014  b          #0x12034120
12034018  mov        w24, w0
1203401c  mov        x0, x19
12034020  mov        x1, x21
12034024  add        x26, sp, #0x10
12034028  bl         #0x120362e0
1203402c  mov        x22, x0
12034030  mov        x0, x19
12034034  mov        x1, x20
12034038  bl         #0x120362e0
1203403c  mov        x23, x0
12034040  mov        x0, x19
12034044  mov        x1, x21
12034048  bl         #0x12036268
1203404c  movi       v0.2d, #0000000000000000
12034050  mov        w25, w0
12034054  add        x2, sp, #0x10
12034058  mov        x0, x23
1203405c  mov        w1, w24
12034060  stur       wzr, [x26, #0x7f]
12034064  lsl        w26, w24, #1
12034068  stp        q0, q0, [sp, #0x10]
1203406c  stp        q0, q0, [sp, #0x30]
12034070  stp        q0, q0, [sp, #0x50]
12034074  stp        q0, q0, [sp, #0x70]
12034078  bl         #0x120364c4
1203407c  add        w8, w25, #0xc8
12034080  sxtw       x27, w8
12034084  str        w8, [sp, #0xc]
12034088  mov        x0, x27
1203408c  bl         #0x120aa304
12034090  mov        w1, wzr
12034094  mov        x2, x27
12034098  mov        x24, x0
1203409c  bl         #0x120aa400
120340a0  movz       w0, #0x1
120340a4  bl         #0x12035fd0
120340a8  add        x2, sp, #0x10
120340ac  add        x5, sp, #0xc
120340b0  mov        x0, x22
120340b4  mov        w1, w25
120340b8  mov        w3, w26
120340bc  mov        x4, x24
120340c0  bl         #0x12038e20
120340c4  adrp       x25, #0x120be000
120340c8  mov        x1, x21
120340cc  mov        x2, x22
120340d0  str        w0, [x25, #0xdc0]
120340d4  mov        x0, x19
120340d8  bl         #0x1203630c
120340dc  mov        x0, x19
120340e0  mov        x1, x20
120340e4  mov        x2, x23
120340e8  bl         #0x1203630c
120340ec  ldr        w8, [x25, #0xdc0]
120340f0  cbz        w8, #0x120340fc
120340f4  mov        x19, xzr
120340f8  b          #0x12034110
120340fc  ldr        w2, [sp, #0xc]
12034100  mov        x0, x19
12034104  mov        x1, x24
12034108  bl         #0x12036344
1203410c  mov        x19, x0
12034110  mov        x0, x24
12034114  bl         #0x1208be10
12034118  movn       w0, #0
1203411c  bl         #0x12035fd0
12034120  ldr        x8, [x28, #0x28]
12034124  ldur       x9, [x29, #-8]
12034128  cmp        x8, x9
1203412c  b.ne       #0x12034154
12034130  mov        x0, x19
12034134  ldp        x20, x19, [sp, #0xf0]
12034138  ldp        x22, x21, [sp, #0xe0]
1203413c  ldp        x24, x23, [sp, #0xd0]
12034140  ldp        x26, x25, [sp, #0xc0]
12034144  ldp        x28, x27, [sp, #0xb0]
12034148  ldp        x29, x30, [sp, #0xa0]
1203414c  add        sp, sp, #0x100
12034150  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm2Decrypt
## base+0x34158
================================================================================
12034158  sub        sp, sp, #0xc0
1203415c  stp        x29, x30, [sp, #0x60]
12034160  stp        x28, x27, [sp, #0x70]
12034164  stp        x26, x25, [sp, #0x80]
12034168  stp        x24, x23, [sp, #0x90]
1203416c  stp        x22, x21, [sp, #0xa0]
12034170  stp        x20, x19, [sp, #0xb0]
12034174  add        x29, sp, #0x60
12034178  mrs        x28, tpidr_el0
1203417c  adrp       x9, #0x120bf000
12034180  mov        x1, x3
12034184  ldr        x8, [x28, #0x28]
12034188  mov        x20, x3
1203418c  mov        x21, x2
12034190  mov        x19, x0
12034194  stur       x8, [x29, #-8]
12034198  str        x0, [x9, #0x90]
1203419c  bl         #0x12036268
120341a0  cmp        w0, #0x21
120341a4  b.lt       #0x120341c0
120341a8  movz       w9, #0x65d8
120341ac  adrp       x8, #0x120be000
120341b0  mov        x19, xzr
120341b4  movk       w9, #0xfffe, lsl #16
120341b8  str        w9, [x8, #0xdc0]
120341bc  b          #0x120342b8
120341c0  mov        w24, w0
120341c4  mov        x0, x19
120341c8  mov        x1, x21
120341cc  bl         #0x120362e0
120341d0  mov        x22, x0
120341d4  mov        x0, x19
120341d8  mov        x1, x20
120341dc  bl         #0x120362e0
120341e0  mov        x23, x0
120341e4  mov        x0, x19
120341e8  mov        x1, x21
120341ec  bl         #0x12036268
120341f0  movi       v0.2d, #0000000000000000
120341f4  mov        w25, w0
120341f8  add        x2, sp, #0x10
120341fc  mov        x0, x23
12034200  mov        w1, w24
12034204  strb       wzr, [sp, #0x50]
12034208  lsl        w26, w24, #1
1203420c  stp        q0, q0, [sp, #0x10]
12034210  stp        q0, q0, [sp, #0x30]
12034214  bl         #0x120364c4
12034218  sxtw       x27, w25
1203421c  str        w25, [sp, #0xc]
12034220  mov        x0, x27
12034224  bl         #0x120aa304
12034228  mov        w1, wzr
1203422c  mov        x2, x27
12034230  mov        x24, x0
12034234  bl         #0x120aa400
12034238  movz       w0, #0x1
1203423c  bl         #0x12035fd0
12034240  add        x2, sp, #0x10
12034244  add        x5, sp, #0xc
12034248  mov        x0, x22
1203424c  mov        w1, w25
12034250  mov        w3, w26
12034254  mov        x4, x24
12034258  bl         #0x12038eec
1203425c  adrp       x25, #0x120be000
12034260  mov        x1, x21
12034264  mov        x2, x22
12034268  str        w0, [x25, #0xdc0]
1203426c  mov        x0, x19
12034270  bl         #0x1203630c
12034274  mov        x0, x19
12034278  mov        x1, x20
1203427c  mov        x2, x23
12034280  bl         #0x1203630c
12034284  ldr        w8, [x25, #0xdc0]
12034288  cbz        w8, #0x12034294
1203428c  mov        x19, xzr
12034290  b          #0x120342a8
12034294  ldr        w2, [sp, #0xc]
12034298  mov        x0, x19
1203429c  mov        x1, x24
120342a0  bl         #0x12036344
120342a4  mov        x19, x0
120342a8  mov        x0, x24
120342ac  bl         #0x1208be10
120342b0  movn       w0, #0
120342b4  bl         #0x12035fd0
120342b8  ldr        x8, [x28, #0x28]
120342bc  ldur       x9, [x29, #-8]
120342c0  cmp        x8, x9
120342c4  b.ne       #0x120342ec
120342c8  mov        x0, x19
120342cc  ldp        x20, x19, [sp, #0xb0]
120342d0  ldp        x22, x21, [sp, #0xa0]
120342d4  ldp        x24, x23, [sp, #0x90]
120342d8  ldp        x26, x25, [sp, #0x80]
120342dc  ldp        x28, x27, [sp, #0x70]
120342e0  ldp        x29, x30, [sp, #0x60]
120342e4  add        sp, sp, #0xc0
120342e8  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm2CalcSharedKey
## base+0x34ed8
================================================================================
12034ed8  sub        sp, sp, #0xc0
12034edc  stp        x29, x30, [sp, #0x60]
12034ee0  stp        x28, x27, [sp, #0x70]
12034ee4  stp        x26, x25, [sp, #0x80]
12034ee8  stp        x24, x23, [sp, #0x90]
12034eec  stp        x22, x21, [sp, #0xa0]
12034ef0  stp        x20, x19, [sp, #0xb0]
12034ef4  add        x29, sp, #0x60
12034ef8  ldr        w8, [x29, #0x70]
12034efc  ldp        x27, x26, [x29, #0x60]
12034f00  mov        x1, x2
12034f04  mov        x21, x7
12034f08  mov        x22, x6
12034f0c  mov        x23, x5
12034f10  mov        x24, x4
12034f14  mov        x25, x3
12034f18  stur       x8, [x29, #-0x10]
12034f1c  mov        x20, x0
12034f20  bl         #0x120363dc
12034f24  stur       x0, [x29, #-0x28]
12034f28  mov        x0, x20
12034f2c  mov        x1, x25
12034f30  bl         #0x120363dc
12034f34  stur       x0, [x29, #-8]
12034f38  mov        x0, x20
12034f3c  mov        x1, x24
12034f40  bl         #0x120363dc
12034f44  stur       x0, [x29, #-0x20]
12034f48  mov        x0, x20
12034f4c  mov        x1, x23
12034f50  bl         #0x120363dc
12034f54  stur       x0, [x29, #-0x18]
12034f58  mov        x0, x20
12034f5c  mov        x1, x22
12034f60  bl         #0x120363dc
12034f64  mov        x24, x0
12034f68  mov        x0, x20
12034f6c  mov        x1, x21
12034f70  bl         #0x120363dc
12034f74  mov        x28, x0
12034f78  mov        x0, x20
12034f7c  mov        x1, x27
12034f80  bl         #0x120363dc
12034f84  mov        x22, x0
12034f88  mov        x0, x20
12034f8c  mov        x1, x26
12034f90  bl         #0x120363dc
12034f94  mov        x21, x0
12034f98  cbz        x22, #0x12034fac
12034f9c  mov        x0, x22
12034fa0  bl         #0x120aa450
12034fa4  str        x0, [sp, #0x28]
12034fa8  b          #0x12034fb0
12034fac  str        xzr, [sp, #0x28]
12034fb0  ldrb       w27, [x29, #0x78]
12034fb4  str        x24, [sp, #0x30]
12034fb8  cbz        x21, #0x12034fcc
12034fbc  mov        x0, x21
12034fc0  bl         #0x120aa450
12034fc4  mov        x24, x0
12034fc8  b          #0x12034fd0
12034fcc  mov        w24, wzr
12034fd0  ldur       x23, [x29, #-0x10]
12034fd4  sxtw       x26, w23
12034fd8  mov        x0, x26
12034fdc  bl         #0x120aa304
12034fe0  mov        w1, wzr
12034fe4  mov        x2, x26
12034fe8  mov        x25, x0
12034fec  bl         #0x120aa400
12034ff0  movz       w0, #0x1
12034ff4  bl         #0x12035fd0
12034ff8  and        w8, w27, #0xff
12034ffc  str        w24, [sp, #8]
12035000  ldur       x26, [x29, #-0x18]
12035004  ldp        x19, x27, [x29, #-0x28]
12035008  mov        x5, x28
1203500c  ldp        x7, x24, [sp, #0x28]
12035010  mov        x3, x26
12035014  ldur       x1, [x29, #-8]
12035018  mov        x6, x22
1203501c  str        x25, [sp, #0x20]
12035020  mov        x0, x19
12035024  mov        x2, x27
12035028  str        w8, [sp, #0x18]
1203502c  mov        x4, x24
12035030  str        w23, [sp, #0x10]
12035034  str        x21, [sp]
12035038  bl         #0x120394f0
1203503c  cbz        x19, #0x12035050
12035040  mov        x0, x19
12035044  bl         #0x120aa420
12035048  movn       w0, #0
1203504c  bl         #0x12035fd0
12035050  ldur       x0, [x29, #-8]
12035054  cbz        x0, #0x12035064
12035058  bl         #0x120aa420
1203505c  movn       w0, #0
12035060  bl         #0x12035fd0
12035064  cbz        x27, #0x12035078
12035068  mov        x0, x27
1203506c  bl         #0x120aa420
12035070  movn       w0, #0
12035074  bl         #0x12035fd0
12035078  cbz        x26, #0x1203508c
1203507c  mov        x0, x26
12035080  bl         #0x120aa420
12035084  movn       w0, #0
12035088  bl         #0x12035fd0
1203508c  cbz        x24, #0x120350a0
12035090  mov        x0, x24
12035094  bl         #0x120aa420
12035098  movn       w0, #0
1203509c  bl         #0x12035fd0
120350a0  cbz        x28, #0x120350b4
120350a4  mov        x0, x28
120350a8  bl         #0x120aa420
120350ac  movn       w0, #0
120350b0  bl         #0x12035fd0
120350b4  cbz        x22, #0x120350c8
120350b8  mov        x0, x22
120350bc  bl         #0x120aa420
120350c0  movn       w0, #0
120350c4  bl         #0x12035fd0
120350c8  cbz        x21, #0x120350dc
120350cc  mov        x0, x21
120350d0  bl         #0x120aa420
120350d4  movn       w0, #0
120350d8  bl         #0x12035fd0
120350dc  adrp       x8, #0x120be000
120350e0  ldr        w8, [x8, #0xdc0]
120350e4  cbz        w8, #0x120350f0
120350e8  mov        x19, xzr
120350ec  b          #0x12035104
120350f0  mov        x0, x20
120350f4  mov        x1, x25
120350f8  ldur       x2, [x29, #-0x10]
120350fc  bl         #0x12036344
12035100  mov        x19, x0
12035104  mov        x0, x25
12035108  bl         #0x1208be10
1203510c  movn       w0, #0
12035110  bl         #0x12035fd0
12035114  mov        x0, x19
12035118  ldp        x20, x19, [sp, #0xb0]
1203511c  ldp        x22, x21, [sp, #0xa0]
12035120  ldp        x24, x23, [sp, #0x90]
12035124  ldp        x26, x25, [sp, #0x80]
12035128  ldp        x28, x27, [sp, #0x70]
1203512c  ldp        x29, x30, [sp, #0x60]
12035130  add        sp, sp, #0xc0
12035134  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm2SealEnvelope
## base+0x35138
================================================================================
12035138  sub        sp, sp, #0x70
1203513c  stp        x29, x30, [sp, #0x10]
12035140  stp        x28, x27, [sp, #0x20]
12035144  stp        x26, x25, [sp, #0x30]
12035148  stp        x24, x23, [sp, #0x40]
1203514c  stp        x22, x21, [sp, #0x50]
12035150  stp        x20, x19, [sp, #0x60]
12035154  add        x29, sp, #0x10
12035158  str        w4, [sp]
1203515c  mrs        x22, tpidr_el0
12035160  adrp       x9, #0x120bf000
12035164  ldr        x8, [x22, #0x28]
12035168  mov        x1, x2
1203516c  mov        x20, x3
12035170  mov        x21, x2
12035174  mov        x19, x0
12035178  str        x8, [sp, #8]
1203517c  str        x0, [x9, #0x90]
12035180  bl         #0x120362e0
12035184  mov        x24, x0
12035188  mov        x0, x19
1203518c  mov        x1, x20
12035190  bl         #0x120362e0
12035194  mov        x25, x0
12035198  mov        x0, x19
1203519c  mov        x1, x21
120351a0  bl         #0x12036268
120351a4  mov        w26, w0
120351a8  mov        x0, x19
120351ac  mov        x1, x20
120351b0  bl         #0x12036268
120351b4  add        w8, w26, #0x1f4
120351b8  mov        w27, w0
120351bc  sxtw       x28, w8
120351c0  str        w8, [sp, #4]
120351c4  mov        x0, x28
120351c8  bl         #0x120aa304
120351cc  mov        w1, wzr
120351d0  mov        x2, x28
120351d4  mov        x23, x0
120351d8  bl         #0x120aa400
120351dc  movz       w0, #0x1
120351e0  bl         #0x12035fd0
120351e4  ldr        w4, [sp]
120351e8  add        x6, sp, #4
120351ec  mov        x0, x24
120351f0  mov        w1, w26
120351f4  mov        x2, x25
120351f8  mov        w3, w27
120351fc  mov        x5, x23
12035200  bl         #0x120395ec
12035204  adrp       x26, #0x120be000
12035208  mov        x1, x21
1203520c  mov        x2, x24
12035210  str        w0, [x26, #0xdc0]
12035214  mov        x0, x19
12035218  bl         #0x1203630c
1203521c  mov        x0, x19
12035220  mov        x1, x20
12035224  mov        x2, x25
12035228  bl         #0x1203630c
1203522c  ldr        w8, [x26, #0xdc0]
12035230  cbz        w8, #0x1203523c
12035234  mov        x19, xzr
12035238  b          #0x12035250
1203523c  ldr        w2, [sp, #4]
12035240  mov        x0, x19
12035244  mov        x1, x23
12035248  bl         #0x12036344
1203524c  mov        x19, x0
12035250  mov        x0, x23
12035254  bl         #0x1208be10
12035258  movn       w0, #0
1203525c  bl         #0x12035fd0
12035260  ldr        x8, [x22, #0x28]
12035264  ldr        x9, [sp, #8]
12035268  cmp        x8, x9
1203526c  b.ne       #0x12035294
12035270  mov        x0, x19
12035274  ldp        x20, x19, [sp, #0x60]
12035278  ldp        x22, x21, [sp, #0x50]
1203527c  ldp        x24, x23, [sp, #0x40]
12035280  ldp        x26, x25, [sp, #0x30]
12035284  ldp        x28, x27, [sp, #0x20]
12035288  ldp        x29, x30, [sp, #0x10]
1203528c  add        sp, sp, #0x70
12035290  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_sm2UnsealEnvelope
## base+0x35298
================================================================================
12035298  sub        sp, sp, #0xc0
1203529c  stp        x29, x30, [sp, #0x60]
120352a0  stp        x28, x27, [sp, #0x70]
120352a4  stp        x26, x25, [sp, #0x80]
120352a8  stp        x24, x23, [sp, #0x90]
120352ac  stp        x22, x21, [sp, #0xa0]
120352b0  stp        x20, x19, [sp, #0xb0]
120352b4  add        x29, sp, #0x60
120352b8  mrs        x28, tpidr_el0
120352bc  adrp       x9, #0x120bf000
120352c0  mov        x1, x3
120352c4  ldr        x8, [x28, #0x28]
120352c8  mov        x20, x3
120352cc  mov        x21, x2
120352d0  mov        x19, x0
120352d4  stur       x8, [x29, #-8]
120352d8  str        x0, [x9, #0x90]
120352dc  bl         #0x12036268
120352e0  cmp        w0, #0x21
120352e4  b.lt       #0x12035300
120352e8  movz       w9, #0x65d8
120352ec  adrp       x8, #0x120be000
120352f0  mov        x19, xzr
120352f4  movk       w9, #0xfffe, lsl #16
120352f8  str        w9, [x8, #0xdc0]
120352fc  b          #0x120353f8
12035300  mov        w24, w0
12035304  mov        x0, x19
12035308  mov        x1, x21
1203530c  bl         #0x120362e0
12035310  mov        x22, x0
12035314  mov        x0, x19
12035318  mov        x1, x20
1203531c  bl         #0x120362e0
12035320  mov        x23, x0
12035324  mov        x0, x19
12035328  mov        x1, x21
1203532c  bl         #0x12036268
12035330  movi       v0.2d, #0000000000000000
12035334  mov        w25, w0
12035338  add        x2, sp, #0x10
1203533c  mov        x0, x23
12035340  mov        w1, w24
12035344  strb       wzr, [sp, #0x50]
12035348  lsl        w26, w24, #1
1203534c  stp        q0, q0, [sp, #0x10]
12035350  stp        q0, q0, [sp, #0x30]
12035354  bl         #0x120364c4
12035358  sxtw       x27, w25
1203535c  str        w25, [sp, #0xc]
12035360  mov        x0, x27
12035364  bl         #0x120aa304
12035368  mov        w1, wzr
1203536c  mov        x2, x27
12035370  mov        x24, x0
12035374  bl         #0x120aa400
12035378  movz       w0, #0x1
1203537c  bl         #0x12035fd0
12035380  add        x2, sp, #0x10
12035384  add        x5, sp, #0xc
12035388  mov        x0, x22
1203538c  mov        w1, w25
12035390  mov        w3, w26
12035394  mov        x4, x24
12035398  bl         #0x12039668
1203539c  adrp       x25, #0x120be000
120353a0  mov        x1, x21
120353a4  mov        x2, x22
120353a8  str        w0, [x25, #0xdc0]
120353ac  mov        x0, x19
120353b0  bl         #0x1203630c
120353b4  mov        x0, x19
120353b8  mov        x1, x20
120353bc  mov        x2, x23
120353c0  bl         #0x1203630c
120353c4  ldr        w8, [x25, #0xdc0]
120353c8  cbz        w8, #0x120353d4
120353cc  mov        x19, xzr
120353d0  b          #0x120353e8
120353d4  ldr        w2, [sp, #0xc]
120353d8  mov        x0, x19
120353dc  mov        x1, x24
120353e0  bl         #0x12036344
120353e4  mov        x19, x0
120353e8  mov        x0, x24
120353ec  bl         #0x1208be10
120353f0  movn       w0, #0
120353f4  bl         #0x12035fd0
120353f8  ldr        x8, [x28, #0x28]
120353fc  ldur       x9, [x29, #-8]
12035400  cmp        x8, x9
12035404  b.ne       #0x1203542c
12035408  mov        x0, x19
1203540c  ldp        x20, x19, [sp, #0xb0]
12035410  ldp        x22, x21, [sp, #0xa0]
12035414  ldp        x24, x23, [sp, #0x90]
12035418  ldp        x26, x25, [sp, #0x80]
1203541c  ldp        x28, x27, [sp, #0x70]
12035420  ldp        x29, x30, [sp, #0x60]
12035424  add        sp, sp, #0xc0
12035428  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_getToken
## base+0x32f40
================================================================================
12032f40  stp        x29, x30, [sp, #-0x40]!
12032f44  stp        x28, x23, [sp, #0x10]
12032f48  stp        x22, x21, [sp, #0x20]
12032f4c  stp        x20, x19, [sp, #0x30]
12032f50  mov        x29, sp
12032f54  sub        sp, sp, #0x810
12032f58  mrs        x22, tpidr_el0
12032f5c  adrp       x9, #0x120bf000
12032f60  mov        x1, x2
12032f64  ldr        x8, [x22, #0x28]
12032f68  mov        x20, x2
12032f6c  mov        x19, x0
12032f70  stur       x8, [x29, #-8]
12032f74  str        x0, [x9, #0x90]
12032f78  bl         #0x12036280
12032f7c  mov        x21, x0
12032f80  add        x0, sp, #8
12032f84  mov        w1, wzr
12032f88  movz       w2, #0x800
12032f8c  bl         #0x120aa400
12032f90  nop        
12032f94  adr        x0, #0x120bedc4
12032f98  add        x3, sp, #8
12032f9c  mov        x1, x21
12032fa0  movz       w2, #0x1
12032fa4  bl         #0x1203e830
12032fa8  adrp       x23, #0x120be000
12032fac  mov        x1, x20
12032fb0  mov        x2, x21
12032fb4  str        w0, [x23, #0xdc0]
12032fb8  mov        x0, x19
12032fbc  bl         #0x120362ac
12032fc0  ldr        w8, [x23, #0xdc0]
12032fc4  cbz        w8, #0x12032fd0
12032fc8  mov        x0, xzr
12032fcc  b          #0x12032fdc
12032fd0  add        x1, sp, #8
12032fd4  mov        x0, x19
12032fd8  bl         #0x120363c0
12032fdc  ldr        x8, [x22, #0x28]
12032fe0  ldur       x9, [x29, #-8]
12032fe4  cmp        x8, x9
12032fe8  b.ne       #0x12033004
12032fec  add        sp, sp, #0x810
12032ff0  ldp        x20, x19, [sp, #0x30]
12032ff4  ldp        x22, x21, [sp, #0x20]
12032ff8  ldp        x28, x23, [sp, #0x10]
12032ffc  ldp        x29, x30, [sp], #0x40
12033000  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_setToken
## base+0x32ea0
================================================================================
12032ea0  stp        x29, x30, [sp, #-0x40]!
12032ea4  stp        x24, x23, [sp, #0x10]
12032ea8  stp        x22, x21, [sp, #0x20]
12032eac  stp        x20, x19, [sp, #0x30]
12032eb0  mov        x29, sp
12032eb4  adrp       x8, #0x120bf000
12032eb8  mov        x1, x2
12032ebc  mov        x19, x3
12032ec0  mov        x20, x2
12032ec4  mov        x21, x0
12032ec8  str        x0, [x8, #0x90]
12032ecc  bl         #0x12036280
12032ed0  mov        x22, x0
12032ed4  mov        x0, x21
12032ed8  mov        x1, x19
12032edc  bl         #0x12036280
12032ee0  mov        x23, x0
12032ee4  nop        
12032ee8  adr        x0, #0x120bedc4
12032eec  mov        x1, x22
12032ef0  mov        x2, x23
12032ef4  bl         #0x1203e618
12032ef8  adrp       x24, #0x120be000
12032efc  mov        x1, x20
12032f00  mov        x2, x22
12032f04  str        w0, [x24, #0xdc0]
12032f08  mov        x0, x21
12032f0c  bl         #0x120362ac
12032f10  mov        x0, x21
12032f14  mov        x1, x19
12032f18  mov        x2, x23
12032f1c  bl         #0x120362ac
12032f20  ldr        w8, [x24, #0xdc0]
12032f24  cmp        w8, #0
12032f28  cset       w0, eq
12032f2c  ldp        x20, x19, [sp, #0x30]
12032f30  ldp        x22, x21, [sp, #0x20]
12032f34  ldp        x24, x23, [sp, #0x10]
12032f38  ldp        x29, x30, [sp], #0x40
12032f3c  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_getValue
## base+0x3347c
================================================================================
1203347c  stp        x29, x30, [sp, #-0x40]!
12033480  stp        x28, x23, [sp, #0x10]
12033484  stp        x22, x21, [sp, #0x20]
12033488  stp        x20, x19, [sp, #0x30]
1203348c  mov        x29, sp
12033490  sub        sp, sp, #2, lsl #12
12033494  sub        sp, sp, #0x10
12033498  mrs        x22, tpidr_el0
1203349c  adrp       x9, #0x120bf000
120334a0  mov        x1, x2
120334a4  ldr        x8, [x22, #0x28]
120334a8  mov        x20, x2
120334ac  mov        x19, x0
120334b0  stur       x8, [x29, #-8]
120334b4  str        x0, [x9, #0x90]
120334b8  bl         #0x12036280
120334bc  mov        x21, x0
120334c0  add        x0, sp, #8
120334c4  mov        w1, wzr
120334c8  movz       w2, #0x2000
120334cc  bl         #0x120aa400
120334d0  nop        
120334d4  adr        x0, #0x120bedc4
120334d8  add        x2, sp, #8
120334dc  add        x3, sp, #4
120334e0  mov        x1, x21
120334e4  str        wzr, [sp, #4]
120334e8  bl         #0x1203bd70
120334ec  adrp       x23, #0x120be000
120334f0  mov        x1, x20
120334f4  mov        x2, x21
120334f8  str        w0, [x23, #0xdc0]
120334fc  mov        x0, x19
12033500  bl         #0x120362ac
12033504  ldr        w8, [x23, #0xdc0]
12033508  cbz        w8, #0x12033514
1203350c  mov        x0, xzr
12033510  b          #0x12033524
12033514  ldr        w2, [sp, #4]
12033518  add        x1, sp, #8
1203351c  mov        x0, x19
12033520  bl         #0x12036344
12033524  ldr        x8, [x22, #0x28]
12033528  ldur       x9, [x29, #-8]
1203352c  cmp        x8, x9
12033530  b.ne       #0x12033550
12033534  add        sp, sp, #2, lsl #12
12033538  add        sp, sp, #0x10
1203353c  ldp        x20, x19, [sp, #0x30]
12033540  ldp        x22, x21, [sp, #0x20]
12033544  ldp        x28, x23, [sp, #0x10]
12033548  ldp        x29, x30, [sp], #0x40
1203354c  ret        

================================================================================
## Java_com_tenpay_qqsc_FitScUtil_setValue
## base+0x333cc
================================================================================
120333cc  stp        x29, x30, [sp, #-0x40]!
120333d0  stp        x24, x23, [sp, #0x10]
120333d4  stp        x22, x21, [sp, #0x20]
120333d8  stp        x20, x19, [sp, #0x30]
120333dc  mov        x29, sp
120333e0  adrp       x8, #0x120bf000
120333e4  mov        x1, x2
120333e8  mov        x19, x3
120333ec  mov        x20, x2
120333f0  mov        x21, x0
120333f4  str        x0, [x8, #0x90]
120333f8  bl         #0x12036280
120333fc  mov        x22, x0
12033400  mov        x0, x21
12033404  mov        x1, x19
12033408  bl         #0x120362e0
1203340c  mov        x23, x0
12033410  mov        x0, x21
12033414  mov        x1, x19
12033418  bl         #0x12036268
1203341c  mov        w3, w0
12033420  nop        
12033424  adr        x0, #0x120bedc4
12033428  mov        x1, x22
1203342c  mov        x2, x23
12033430  bl         #0x1203bc78
12033434  adrp       x24, #0x120be000
12033438  mov        x1, x20
1203343c  mov        x2, x22
12033440  str        w0, [x24, #0xdc0]
12033444  mov        x0, x21
12033448  bl         #0x120362ac
1203344c  mov        x0, x21
12033450  mov        x1, x19
12033454  mov        x2, x23
12033458  bl         #0x1203630c
1203345c  ldr        w8, [x24, #0xdc0]
12033460  cmp        w8, #0
12033464  cset       w0, eq
12033468  ldp        x20, x19, [sp, #0x30]
1203346c  ldp        x22, x21, [sp, #0x20]
12033470  ldp        x24, x23, [sp, #0x10]
12033474  ldp        x29, x30, [sp], #0x40
12033478  ret        

