
# qhasm: int64 input_0

# qhasm: int64 input_1

# qhasm: int64 input_2

# qhasm: int64 input_3

# qhasm: int64 input_4

# qhasm: int64 input_5

# qhasm: stack64 input_6

# qhasm: stack64 input_7

# qhasm: int64 caller_r11

# qhasm: int64 caller_r12

# qhasm: int64 caller_r13

# qhasm: int64 caller_r14

# qhasm: int64 caller_r15

# qhasm: int64 caller_rbx

# qhasm: int64 caller_rbp

# qhasm: int64 r0

# qhasm: int64 r1

# qhasm: int64 r2

# qhasm: int64 r3

# qhasm: reg256 mask0

# qhasm: reg256 mask1

# qhasm: reg256 mask2

# qhasm: reg256 mask3

# qhasm: reg256 mask4

# qhasm: reg256 mask5

# qhasm: reg256 mask6

# qhasm: reg256 mask7

# qhasm: reg256 mask8

# qhasm: reg256 v

# qhasm: reg256 s

# qhasm: reg256 t

# qhasm: reg256 z

# qhasm: reg256 t0

# qhasm: reg256 t1

# qhasm: reg256 t2

# qhasm: reg256 t3

# qhasm: reg256 i

# qhasm: reg256 flip

# qhasm: reg256 res0

# qhasm: reg256 res1

# qhasm: reg256 mask

# qhasm: reg256 _mask

# qhasm: reg256 allone

# qhasm: reg256 one

# qhasm: reg256 F0

# qhasm: reg256 mzero

# qhasm: stack256 buf

# qhasm: int64 ptr

# qhasm: enter ge4x_lookup_asm
.p2align 5
.global _ge4x_lookup_asm
.global ge4x_lookup_asm
_ge4x_lookup_asm:
ge4x_lookup_asm:
mov %rsp,%r11
and $31,%r11
add $32,%r11
sub %r11,%rsp

# qhasm: ptr = &buf
# asm 1: leaq <buf=stack256#1,>ptr=int64#4
# asm 2: leaq <buf=0(%rsp),>ptr=%rcx
leaq 0(%rsp),%rcx

# qhasm: r0 ^= r0
# asm 1: xor  <r0=int64#5,<r0=int64#5
# asm 2: xor  <r0=%r8,<r0=%r8
xor  %r8,%r8

# qhasm: r0 = *(uint8  *) (input_2 + 0)
# asm 1: movzbq 0(<input_2=int64#3),>r0=int64#5
# asm 2: movzbq 0(<input_2=%rdx),>r0=%r8
movzbq 0(%rdx),%r8

# qhasm: r1 ^= r1
# asm 1: xor  <r1=int64#6,<r1=int64#6
# asm 2: xor  <r1=%r9,<r1=%r9
xor  %r9,%r9

# qhasm: r1 = *(uint8  *) (input_2 + 1)
# asm 1: movzbq 1(<input_2=int64#3),>r1=int64#6
# asm 2: movzbq 1(<input_2=%rdx),>r1=%r9
movzbq 1(%rdx),%r9

# qhasm: r2 ^= r2
# asm 1: xor  <r2=int64#7,<r2=int64#7
# asm 2: xor  <r2=%rax,<r2=%rax
xor  %rax,%rax

# qhasm: r2 = *(uint8  *) (input_2 + 2)
# asm 1: movzbq 2(<input_2=int64#3),>r2=int64#7
# asm 2: movzbq 2(<input_2=%rdx),>r2=%rax
movzbq 2(%rdx),%rax

# qhasm: r3 ^= r3
# asm 1: xor  <r3=int64#8,<r3=int64#8
# asm 2: xor  <r3=%r10,<r3=%r10
xor  %r10,%r10

# qhasm: r3 = *(uint8  *) (input_2 + 3)
# asm 1: movzbq 3(<input_2=int64#3),>r3=int64#3
# asm 2: movzbq 3(<input_2=%rdx),>r3=%rdx
movzbq 3(%rdx),%rdx

# qhasm: *(uint64  *) (ptr + 0) = r0
# asm 1: movq   <r0=int64#5,0(<ptr=int64#4)
# asm 2: movq   <r0=%r8,0(<ptr=%rcx)
movq   %r8,0(%rcx)

# qhasm: *(uint64  *) (ptr + 8) = r1
# asm 1: movq   <r1=int64#6,8(<ptr=int64#4)
# asm 2: movq   <r1=%r9,8(<ptr=%rcx)
movq   %r9,8(%rcx)

# qhasm: *(uint64  *) (ptr + 16) = r2
# asm 1: movq   <r2=int64#7,16(<ptr=int64#4)
# asm 2: movq   <r2=%rax,16(<ptr=%rcx)
movq   %rax,16(%rcx)

# qhasm: *(uint64  *) (ptr + 24) = r3
# asm 1: movq   <r3=int64#3,24(<ptr=int64#4)
# asm 2: movq   <r3=%rdx,24(<ptr=%rcx)
movq   %rdx,24(%rcx)

# qhasm: v = buf
# asm 1: vmovapd <buf=stack256#1,>v=reg256#1
# asm 2: vmovapd <buf=0(%rsp),>v=%ymm0
vmovapd 0(%rsp),%ymm0

# qhasm: allone aligned= mem256[_allone]
# asm 1: vmovapd _allone,>allone=reg256#2
# asm 2: vmovapd _allone,>allone=%ymm1
vmovapd _allone,%ymm1

# qhasm: i aligned= mem256[_idx0]
# asm 1: vmovapd _idx0,>i=reg256#3
# asm 2: vmovapd _idx0,>i=%ymm2
vmovapd _idx0,%ymm2

# qhasm: mask0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#3,>mask0=reg256#3
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm2,>mask0=%ymm2
vcmpeqpd %ymm0,%ymm2,%ymm2

# qhasm: i aligned= mem256[_idx_1]
# asm 1: vmovapd _idx_1,>i=reg256#4
# asm 2: vmovapd _idx_1,>i=%ymm3
vmovapd _idx_1,%ymm3

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#4,>res0=reg256#4
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm3,>res0=%ymm3
vcmpeqpd %ymm0,%ymm3,%ymm3

# qhasm: i aligned= mem256[_idx1]
# asm 1: vmovapd _idx1,>i=reg256#5
# asm 2: vmovapd _idx1,>i=%ymm4
vmovapd _idx1,%ymm4

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#5,>res1=reg256#5
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm4,>res1=%ymm4
vcmpeqpd %ymm0,%ymm4,%ymm4

# qhasm: mask1 = res0 | res1
# asm 1: vorpd  <res0=reg256#4,<res1=reg256#5,>mask1=reg256#4
# asm 2: vorpd  <res0=%ymm3,<res1=%ymm4,>mask1=%ymm3
vorpd  %ymm3,%ymm4,%ymm3

# qhasm: i aligned= mem256[_idx_2]
# asm 1: vmovapd _idx_2,>i=reg256#5
# asm 2: vmovapd _idx_2,>i=%ymm4
vmovapd _idx_2,%ymm4

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#5,>res0=reg256#5
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm4,>res0=%ymm4
vcmpeqpd %ymm0,%ymm4,%ymm4

# qhasm: i aligned= mem256[_idx2]
# asm 1: vmovapd _idx2,>i=reg256#6
# asm 2: vmovapd _idx2,>i=%ymm5
vmovapd _idx2,%ymm5

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#6,>res1=reg256#6
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm5,>res1=%ymm5
vcmpeqpd %ymm0,%ymm5,%ymm5

# qhasm: mask2 = res0 | res1
# asm 1: vorpd  <res0=reg256#5,<res1=reg256#6,>mask2=reg256#5
# asm 2: vorpd  <res0=%ymm4,<res1=%ymm5,>mask2=%ymm4
vorpd  %ymm4,%ymm5,%ymm4

# qhasm: i aligned= mem256[_idx_3]
# asm 1: vmovapd _idx_3,>i=reg256#6
# asm 2: vmovapd _idx_3,>i=%ymm5
vmovapd _idx_3,%ymm5

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#6,>res0=reg256#6
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm5,>res0=%ymm5
vcmpeqpd %ymm0,%ymm5,%ymm5

# qhasm: i aligned= mem256[_idx3]
# asm 1: vmovapd _idx3,>i=reg256#7
# asm 2: vmovapd _idx3,>i=%ymm6
vmovapd _idx3,%ymm6

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#7,>res1=reg256#7
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm6,>res1=%ymm6
vcmpeqpd %ymm0,%ymm6,%ymm6

# qhasm: mask3 = res0 | res1
# asm 1: vorpd  <res0=reg256#6,<res1=reg256#7,>mask3=reg256#6
# asm 2: vorpd  <res0=%ymm5,<res1=%ymm6,>mask3=%ymm5
vorpd  %ymm5,%ymm6,%ymm5

# qhasm: i aligned= mem256[_idx_4]
# asm 1: vmovapd _idx_4,>i=reg256#7
# asm 2: vmovapd _idx_4,>i=%ymm6
vmovapd _idx_4,%ymm6

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#7,>res0=reg256#7
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm6,>res0=%ymm6
vcmpeqpd %ymm0,%ymm6,%ymm6

# qhasm: i aligned= mem256[_idx4]
# asm 1: vmovapd _idx4,>i=reg256#8
# asm 2: vmovapd _idx4,>i=%ymm7
vmovapd _idx4,%ymm7

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#8,>res1=reg256#8
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm7,>res1=%ymm7
vcmpeqpd %ymm0,%ymm7,%ymm7

# qhasm: mask4 = res0 | res1
# asm 1: vorpd  <res0=reg256#7,<res1=reg256#8,>mask4=reg256#7
# asm 2: vorpd  <res0=%ymm6,<res1=%ymm7,>mask4=%ymm6
vorpd  %ymm6,%ymm7,%ymm6

# qhasm: i aligned= mem256[_idx_5]
# asm 1: vmovapd _idx_5,>i=reg256#8
# asm 2: vmovapd _idx_5,>i=%ymm7
vmovapd _idx_5,%ymm7

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#8,>res0=reg256#8
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm7,>res0=%ymm7
vcmpeqpd %ymm0,%ymm7,%ymm7

# qhasm: i aligned= mem256[_idx5]
# asm 1: vmovapd _idx5,>i=reg256#9
# asm 2: vmovapd _idx5,>i=%ymm8
vmovapd _idx5,%ymm8

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#9,>res1=reg256#9
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm8,>res1=%ymm8
vcmpeqpd %ymm0,%ymm8,%ymm8

# qhasm: mask5 = res0 | res1
# asm 1: vorpd  <res0=reg256#8,<res1=reg256#9,>mask5=reg256#8
# asm 2: vorpd  <res0=%ymm7,<res1=%ymm8,>mask5=%ymm7
vorpd  %ymm7,%ymm8,%ymm7

# qhasm: i aligned= mem256[_idx_6]
# asm 1: vmovapd _idx_6,>i=reg256#9
# asm 2: vmovapd _idx_6,>i=%ymm8
vmovapd _idx_6,%ymm8

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#9,>res0=reg256#9
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm8,>res0=%ymm8
vcmpeqpd %ymm0,%ymm8,%ymm8

# qhasm: i aligned= mem256[_idx6]
# asm 1: vmovapd _idx6,>i=reg256#10
# asm 2: vmovapd _idx6,>i=%ymm9
vmovapd _idx6,%ymm9

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#10,>res1=reg256#10
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm9,>res1=%ymm9
vcmpeqpd %ymm0,%ymm9,%ymm9

# qhasm: mask6 = res0 | res1
# asm 1: vorpd  <res0=reg256#9,<res1=reg256#10,>mask6=reg256#9
# asm 2: vorpd  <res0=%ymm8,<res1=%ymm9,>mask6=%ymm8
vorpd  %ymm8,%ymm9,%ymm8

# qhasm: i aligned= mem256[_idx_7]
# asm 1: vmovapd _idx_7,>i=reg256#10
# asm 2: vmovapd _idx_7,>i=%ymm9
vmovapd _idx_7,%ymm9

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#10,>res0=reg256#10
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm9,>res0=%ymm9
vcmpeqpd %ymm0,%ymm9,%ymm9

# qhasm: i aligned= mem256[_idx7]
# asm 1: vmovapd _idx7,>i=reg256#11
# asm 2: vmovapd _idx7,>i=%ymm10
vmovapd _idx7,%ymm10

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#11,>res1=reg256#11
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm10,>res1=%ymm10
vcmpeqpd %ymm0,%ymm10,%ymm10

# qhasm: mask7 = res0 | res1
# asm 1: vorpd  <res0=reg256#10,<res1=reg256#11,>mask7=reg256#10
# asm 2: vorpd  <res0=%ymm9,<res1=%ymm10,>mask7=%ymm9
vorpd  %ymm9,%ymm10,%ymm9

# qhasm: i aligned= mem256[_idx_8]
# asm 1: vmovapd _idx_8,>i=reg256#11
# asm 2: vmovapd _idx_8,>i=%ymm10
vmovapd _idx_8,%ymm10

# qhasm: mask8 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#11,>mask8=reg256#11
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm10,>mask8=%ymm10
vcmpeqpd %ymm0,%ymm10,%ymm10

# qhasm: F0 aligned= mem256[_F0]
# asm 1: vmovapd _F0,>F0=reg256#12
# asm 2: vmovapd _F0,>F0=%ymm11
vmovapd _F0,%ymm11

# qhasm: flip = v^F0
# asm 1: vxorpd <v=reg256#1,<F0=reg256#12,>flip=reg256#1
# asm 2: vxorpd <v=%ymm0,<F0=%ymm11,>flip=%ymm0
vxorpd %ymm0,%ymm11,%ymm0

# qhasm: 4x flip approx-= F0
# asm 1: vsubpd <F0=reg256#12,<flip=reg256#1,>flip=reg256#1
# asm 2: vsubpd <F0=%ymm11,<flip=%ymm0,>flip=%ymm0
vsubpd %ymm11,%ymm0,%ymm0

# qhasm: mzero aligned= mem256[_mzero]
# asm 1: vmovapd _mzero,>mzero=reg256#12
# asm 2: vmovapd _mzero,>mzero=%ymm11
vmovapd _mzero,%ymm11

# qhasm: flip &= mzero
# asm 1: vandpd <mzero=reg256#12,<flip=reg256#1,<flip=reg256#1
# asm 2: vandpd <mzero=%ymm11,<flip=%ymm0,<flip=%ymm0
vandpd %ymm11,%ymm0,%ymm0

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 = mem256[_one]
# asm 1: vmovupd _one,>t1=reg256#13
# asm 2: vmovupd _one,>t1=%ymm12
vmovupd _one,%ymm12

# qhasm: t1 &= mask0
# asm 1: vandpd <mask0=reg256#3,<t1=reg256#13,<t1=reg256#13
# asm 2: vandpd <mask0=%ymm2,<t1=%ymm12,<t1=%ymm12
vandpd %ymm2,%ymm12,%ymm12

# qhasm: t2 = t1
# asm 1: vmovapd <t1=reg256#13,>t2=reg256#3
# asm 2: vmovapd <t1=%ymm12,>t2=%ymm2
vmovapd %ymm12,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 0]
# asm 1: vandpd 0(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 0(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 0(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 384]
# asm 1: vandpd 384(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 384(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 384(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 768]
# asm 1: vandpd 768(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 768(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 768(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1152]
# asm 1: vandpd 1152(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1152(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1152(%rsi),%ymm3,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1536]
# asm 1: vandpd 1536(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1536(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1536(%rsi),%ymm4,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 1920]
# asm 1: vandpd 1920(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1920(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1920(%rsi),%ymm4,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2304]
# asm 1: vandpd 2304(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2304(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2304(%rsi),%ymm4,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 2688]
# asm 1: vandpd 2688(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2688(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2688(%rsi),%ymm4,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3072]
# asm 1: vandpd 3072(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3072(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3072(%rsi),%ymm5,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3456]
# asm 1: vandpd 3456(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3456(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3456(%rsi),%ymm5,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 3840]
# asm 1: vandpd 3840(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3840(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3840(%rsi),%ymm5,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4224]
# asm 1: vandpd 4224(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4224(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4224(%rsi),%ymm5,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4608]
# asm 1: vandpd 4608(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4608(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4608(%rsi),%ymm6,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 4992]
# asm 1: vandpd 4992(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4992(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4992(%rsi),%ymm6,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5376]
# asm 1: vandpd 5376(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5376(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5376(%rsi),%ymm6,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 5760]
# asm 1: vandpd 5760(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5760(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5760(%rsi),%ymm6,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6144]
# asm 1: vandpd 6144(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6144(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6144(%rsi),%ymm7,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6528]
# asm 1: vandpd 6528(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6528(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6528(%rsi),%ymm7,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 6912]
# asm 1: vandpd 6912(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6912(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6912(%rsi),%ymm7,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7296]
# asm 1: vandpd 7296(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7296(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7296(%rsi),%ymm7,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 7680]
# asm 1: vandpd 7680(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 7680(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 7680(%rsi),%ymm8,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8064]
# asm 1: vandpd 8064(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8064(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8064(%rsi),%ymm8,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8448]
# asm 1: vandpd 8448(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8448(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8448(%rsi),%ymm8,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 8832]
# asm 1: vandpd 8832(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8832(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8832(%rsi),%ymm8,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9216]
# asm 1: vandpd 9216(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9216(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9216(%rsi),%ymm9,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9600]
# asm 1: vandpd 9600(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9600(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9600(%rsi),%ymm9,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 9984]
# asm 1: vandpd 9984(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9984(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9984(%rsi),%ymm9,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10368]
# asm 1: vandpd 10368(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10368(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10368(%rsi),%ymm9,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 10752]
# asm 1: vandpd 10752(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 10752(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 10752(%rsi),%ymm10,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11136]
# asm 1: vandpd 11136(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11136(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11136(%rsi),%ymm10,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11520]
# asm 1: vandpd 11520(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11520(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11520(%rsi),%ymm10,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 11904]
# asm 1: vandpd 11904(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11904(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11904(%rsi),%ymm10,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 0] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,0(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,0(<input_0=%rdi)
vmovapd   %ymm11,0(%rdi)

# qhasm: mem256[input_0 + 384] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,384(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,384(<input_0=%rdi)
vmovapd   %ymm12,384(%rdi)

# qhasm: mem256[input_0 + 768] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,768(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,768(<input_0=%rdi)
vmovapd   %ymm2,768(%rdi)

# qhasm: mem256[input_0 + 1152] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1152(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1152(<input_0=%rdi)
vmovapd   %ymm13,1152(%rdi)

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 ^= t1
# asm 1: vxorpd <t1=reg256#13,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <t1=%ymm12,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: t2 ^= t2
# asm 1: vxorpd <t2=reg256#3,<t2=reg256#3,<t2=reg256#3
# asm 2: vxorpd <t2=%ymm2,<t2=%ymm2,<t2=%ymm2
vxorpd %ymm2,%ymm2,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 32]
# asm 1: vandpd 32(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 32(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 32(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 416]
# asm 1: vandpd 416(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 416(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 416(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 800]
# asm 1: vandpd 800(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 800(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 800(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1184]
# asm 1: vandpd 1184(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1184(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1184(%rsi),%ymm3,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1568]
# asm 1: vandpd 1568(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1568(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1568(%rsi),%ymm4,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 1952]
# asm 1: vandpd 1952(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1952(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1952(%rsi),%ymm4,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2336]
# asm 1: vandpd 2336(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2336(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2336(%rsi),%ymm4,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 2720]
# asm 1: vandpd 2720(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2720(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2720(%rsi),%ymm4,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3104]
# asm 1: vandpd 3104(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3104(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3104(%rsi),%ymm5,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3488]
# asm 1: vandpd 3488(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3488(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3488(%rsi),%ymm5,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 3872]
# asm 1: vandpd 3872(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3872(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3872(%rsi),%ymm5,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4256]
# asm 1: vandpd 4256(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4256(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4256(%rsi),%ymm5,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4640]
# asm 1: vandpd 4640(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4640(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4640(%rsi),%ymm6,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 5024]
# asm 1: vandpd 5024(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5024(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5024(%rsi),%ymm6,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5408]
# asm 1: vandpd 5408(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5408(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5408(%rsi),%ymm6,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 5792]
# asm 1: vandpd 5792(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5792(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5792(%rsi),%ymm6,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6176]
# asm 1: vandpd 6176(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6176(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6176(%rsi),%ymm7,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6560]
# asm 1: vandpd 6560(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6560(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6560(%rsi),%ymm7,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 6944]
# asm 1: vandpd 6944(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6944(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6944(%rsi),%ymm7,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7328]
# asm 1: vandpd 7328(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7328(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7328(%rsi),%ymm7,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 7712]
# asm 1: vandpd 7712(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 7712(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 7712(%rsi),%ymm8,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8096]
# asm 1: vandpd 8096(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8096(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8096(%rsi),%ymm8,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8480]
# asm 1: vandpd 8480(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8480(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8480(%rsi),%ymm8,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 8864]
# asm 1: vandpd 8864(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8864(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8864(%rsi),%ymm8,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9248]
# asm 1: vandpd 9248(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9248(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9248(%rsi),%ymm9,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9632]
# asm 1: vandpd 9632(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9632(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9632(%rsi),%ymm9,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 10016]
# asm 1: vandpd 10016(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10016(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10016(%rsi),%ymm9,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10400]
# asm 1: vandpd 10400(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10400(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10400(%rsi),%ymm9,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 10784]
# asm 1: vandpd 10784(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 10784(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 10784(%rsi),%ymm10,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11168]
# asm 1: vandpd 11168(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11168(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11168(%rsi),%ymm10,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11552]
# asm 1: vandpd 11552(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11552(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11552(%rsi),%ymm10,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 11936]
# asm 1: vandpd 11936(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11936(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11936(%rsi),%ymm10,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 32] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,32(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,32(<input_0=%rdi)
vmovapd   %ymm11,32(%rdi)

# qhasm: mem256[input_0 + 416] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,416(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,416(<input_0=%rdi)
vmovapd   %ymm12,416(%rdi)

# qhasm: mem256[input_0 + 800] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,800(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,800(<input_0=%rdi)
vmovapd   %ymm2,800(%rdi)

# qhasm: mem256[input_0 + 1184] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1184(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1184(<input_0=%rdi)
vmovapd   %ymm13,1184(%rdi)

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 ^= t1
# asm 1: vxorpd <t1=reg256#13,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <t1=%ymm12,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: t2 ^= t2
# asm 1: vxorpd <t2=reg256#3,<t2=reg256#3,<t2=reg256#3
# asm 2: vxorpd <t2=%ymm2,<t2=%ymm2,<t2=%ymm2
vxorpd %ymm2,%ymm2,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 64]
# asm 1: vandpd 64(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 64(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 64(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 448]
# asm 1: vandpd 448(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 448(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 448(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 832]
# asm 1: vandpd 832(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 832(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 832(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1216]
# asm 1: vandpd 1216(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1216(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1216(%rsi),%ymm3,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1600]
# asm 1: vandpd 1600(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1600(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1600(%rsi),%ymm4,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 1984]
# asm 1: vandpd 1984(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1984(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1984(%rsi),%ymm4,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2368]
# asm 1: vandpd 2368(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2368(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2368(%rsi),%ymm4,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 2752]
# asm 1: vandpd 2752(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2752(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2752(%rsi),%ymm4,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3136]
# asm 1: vandpd 3136(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3136(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3136(%rsi),%ymm5,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3520]
# asm 1: vandpd 3520(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3520(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3520(%rsi),%ymm5,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 3904]
# asm 1: vandpd 3904(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3904(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3904(%rsi),%ymm5,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4288]
# asm 1: vandpd 4288(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4288(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4288(%rsi),%ymm5,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4672]
# asm 1: vandpd 4672(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4672(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4672(%rsi),%ymm6,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 5056]
# asm 1: vandpd 5056(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5056(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5056(%rsi),%ymm6,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5440]
# asm 1: vandpd 5440(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5440(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5440(%rsi),%ymm6,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 5824]
# asm 1: vandpd 5824(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5824(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5824(%rsi),%ymm6,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6208]
# asm 1: vandpd 6208(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6208(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6208(%rsi),%ymm7,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6592]
# asm 1: vandpd 6592(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6592(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6592(%rsi),%ymm7,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 6976]
# asm 1: vandpd 6976(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6976(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6976(%rsi),%ymm7,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7360]
# asm 1: vandpd 7360(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7360(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7360(%rsi),%ymm7,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 7744]
# asm 1: vandpd 7744(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 7744(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 7744(%rsi),%ymm8,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8128]
# asm 1: vandpd 8128(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8128(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8128(%rsi),%ymm8,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8512]
# asm 1: vandpd 8512(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8512(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8512(%rsi),%ymm8,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 8896]
# asm 1: vandpd 8896(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8896(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8896(%rsi),%ymm8,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9280]
# asm 1: vandpd 9280(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9280(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9280(%rsi),%ymm9,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9664]
# asm 1: vandpd 9664(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9664(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9664(%rsi),%ymm9,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 10048]
# asm 1: vandpd 10048(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10048(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10048(%rsi),%ymm9,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10432]
# asm 1: vandpd 10432(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10432(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10432(%rsi),%ymm9,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 10816]
# asm 1: vandpd 10816(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 10816(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 10816(%rsi),%ymm10,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11200]
# asm 1: vandpd 11200(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11200(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11200(%rsi),%ymm10,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11584]
# asm 1: vandpd 11584(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11584(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11584(%rsi),%ymm10,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 11968]
# asm 1: vandpd 11968(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11968(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11968(%rsi),%ymm10,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 64] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,64(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,64(<input_0=%rdi)
vmovapd   %ymm11,64(%rdi)

# qhasm: mem256[input_0 + 448] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,448(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,448(<input_0=%rdi)
vmovapd   %ymm12,448(%rdi)

# qhasm: mem256[input_0 + 832] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,832(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,832(<input_0=%rdi)
vmovapd   %ymm2,832(%rdi)

# qhasm: mem256[input_0 + 1216] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1216(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1216(<input_0=%rdi)
vmovapd   %ymm13,1216(%rdi)

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 ^= t1
# asm 1: vxorpd <t1=reg256#13,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <t1=%ymm12,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: t2 ^= t2
# asm 1: vxorpd <t2=reg256#3,<t2=reg256#3,<t2=reg256#3
# asm 2: vxorpd <t2=%ymm2,<t2=%ymm2,<t2=%ymm2
vxorpd %ymm2,%ymm2,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 96]
# asm 1: vandpd 96(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 96(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 96(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 480]
# asm 1: vandpd 480(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 480(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 480(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 864]
# asm 1: vandpd 864(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 864(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 864(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1248]
# asm 1: vandpd 1248(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1248(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1248(%rsi),%ymm3,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1632]
# asm 1: vandpd 1632(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1632(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1632(%rsi),%ymm4,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 2016]
# asm 1: vandpd 2016(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2016(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2016(%rsi),%ymm4,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2400]
# asm 1: vandpd 2400(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2400(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2400(%rsi),%ymm4,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 2784]
# asm 1: vandpd 2784(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2784(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2784(%rsi),%ymm4,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3168]
# asm 1: vandpd 3168(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3168(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3168(%rsi),%ymm5,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3552]
# asm 1: vandpd 3552(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3552(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3552(%rsi),%ymm5,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 3936]
# asm 1: vandpd 3936(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3936(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3936(%rsi),%ymm5,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4320]
# asm 1: vandpd 4320(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4320(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4320(%rsi),%ymm5,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4704]
# asm 1: vandpd 4704(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4704(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4704(%rsi),%ymm6,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 5088]
# asm 1: vandpd 5088(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5088(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5088(%rsi),%ymm6,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5472]
# asm 1: vandpd 5472(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5472(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5472(%rsi),%ymm6,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 5856]
# asm 1: vandpd 5856(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5856(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5856(%rsi),%ymm6,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6240]
# asm 1: vandpd 6240(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6240(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6240(%rsi),%ymm7,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6624]
# asm 1: vandpd 6624(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6624(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6624(%rsi),%ymm7,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 7008]
# asm 1: vandpd 7008(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7008(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7008(%rsi),%ymm7,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7392]
# asm 1: vandpd 7392(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7392(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7392(%rsi),%ymm7,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 7776]
# asm 1: vandpd 7776(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 7776(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 7776(%rsi),%ymm8,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8160]
# asm 1: vandpd 8160(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8160(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8160(%rsi),%ymm8,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8544]
# asm 1: vandpd 8544(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8544(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8544(%rsi),%ymm8,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 8928]
# asm 1: vandpd 8928(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8928(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8928(%rsi),%ymm8,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9312]
# asm 1: vandpd 9312(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9312(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9312(%rsi),%ymm9,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9696]
# asm 1: vandpd 9696(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9696(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9696(%rsi),%ymm9,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 10080]
# asm 1: vandpd 10080(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10080(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10080(%rsi),%ymm9,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10464]
# asm 1: vandpd 10464(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10464(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10464(%rsi),%ymm9,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 10848]
# asm 1: vandpd 10848(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 10848(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 10848(%rsi),%ymm10,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11232]
# asm 1: vandpd 11232(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11232(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11232(%rsi),%ymm10,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11616]
# asm 1: vandpd 11616(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11616(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11616(%rsi),%ymm10,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 12000]
# asm 1: vandpd 12000(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 12000(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 12000(%rsi),%ymm10,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 96] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,96(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,96(<input_0=%rdi)
vmovapd   %ymm11,96(%rdi)

# qhasm: mem256[input_0 + 480] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,480(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,480(<input_0=%rdi)
vmovapd   %ymm12,480(%rdi)

# qhasm: mem256[input_0 + 864] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,864(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,864(<input_0=%rdi)
vmovapd   %ymm2,864(%rdi)

# qhasm: mem256[input_0 + 1248] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1248(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1248(<input_0=%rdi)
vmovapd   %ymm13,1248(%rdi)

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 ^= t1
# asm 1: vxorpd <t1=reg256#13,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <t1=%ymm12,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: t2 ^= t2
# asm 1: vxorpd <t2=reg256#3,<t2=reg256#3,<t2=reg256#3
# asm 2: vxorpd <t2=%ymm2,<t2=%ymm2,<t2=%ymm2
vxorpd %ymm2,%ymm2,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 128]
# asm 1: vandpd 128(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 128(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 128(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 512]
# asm 1: vandpd 512(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 512(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 512(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 896]
# asm 1: vandpd 896(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 896(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 896(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1280]
# asm 1: vandpd 1280(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1280(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1280(%rsi),%ymm3,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1664]
# asm 1: vandpd 1664(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1664(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1664(%rsi),%ymm4,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 2048]
# asm 1: vandpd 2048(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2048(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2048(%rsi),%ymm4,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2432]
# asm 1: vandpd 2432(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2432(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2432(%rsi),%ymm4,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 2816]
# asm 1: vandpd 2816(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2816(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2816(%rsi),%ymm4,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3200]
# asm 1: vandpd 3200(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3200(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3200(%rsi),%ymm5,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3584]
# asm 1: vandpd 3584(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3584(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3584(%rsi),%ymm5,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 3968]
# asm 1: vandpd 3968(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3968(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3968(%rsi),%ymm5,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4352]
# asm 1: vandpd 4352(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4352(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4352(%rsi),%ymm5,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4736]
# asm 1: vandpd 4736(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4736(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4736(%rsi),%ymm6,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 5120]
# asm 1: vandpd 5120(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5120(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5120(%rsi),%ymm6,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5504]
# asm 1: vandpd 5504(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5504(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5504(%rsi),%ymm6,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 5888]
# asm 1: vandpd 5888(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5888(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5888(%rsi),%ymm6,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6272]
# asm 1: vandpd 6272(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6272(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6272(%rsi),%ymm7,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6656]
# asm 1: vandpd 6656(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6656(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6656(%rsi),%ymm7,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 7040]
# asm 1: vandpd 7040(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7040(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7040(%rsi),%ymm7,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7424]
# asm 1: vandpd 7424(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7424(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7424(%rsi),%ymm7,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 7808]
# asm 1: vandpd 7808(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 7808(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 7808(%rsi),%ymm8,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8192]
# asm 1: vandpd 8192(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8192(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8192(%rsi),%ymm8,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8576]
# asm 1: vandpd 8576(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8576(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8576(%rsi),%ymm8,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 8960]
# asm 1: vandpd 8960(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8960(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8960(%rsi),%ymm8,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9344]
# asm 1: vandpd 9344(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9344(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9344(%rsi),%ymm9,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9728]
# asm 1: vandpd 9728(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9728(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9728(%rsi),%ymm9,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 10112]
# asm 1: vandpd 10112(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10112(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10112(%rsi),%ymm9,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10496]
# asm 1: vandpd 10496(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10496(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10496(%rsi),%ymm9,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 10880]
# asm 1: vandpd 10880(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 10880(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 10880(%rsi),%ymm10,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11264]
# asm 1: vandpd 11264(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11264(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11264(%rsi),%ymm10,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11648]
# asm 1: vandpd 11648(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11648(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11648(%rsi),%ymm10,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 12032]
# asm 1: vandpd 12032(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 12032(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 12032(%rsi),%ymm10,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 128] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,128(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,128(<input_0=%rdi)
vmovapd   %ymm11,128(%rdi)

# qhasm: mem256[input_0 + 512] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,512(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,512(<input_0=%rdi)
vmovapd   %ymm12,512(%rdi)

# qhasm: mem256[input_0 + 896] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,896(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,896(<input_0=%rdi)
vmovapd   %ymm2,896(%rdi)

# qhasm: mem256[input_0 + 1280] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1280(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1280(<input_0=%rdi)
vmovapd   %ymm13,1280(%rdi)

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 ^= t1
# asm 1: vxorpd <t1=reg256#13,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <t1=%ymm12,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: t2 ^= t2
# asm 1: vxorpd <t2=reg256#3,<t2=reg256#3,<t2=reg256#3
# asm 2: vxorpd <t2=%ymm2,<t2=%ymm2,<t2=%ymm2
vxorpd %ymm2,%ymm2,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 160]
# asm 1: vandpd 160(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 160(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 160(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 544]
# asm 1: vandpd 544(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 544(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 544(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 928]
# asm 1: vandpd 928(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 928(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 928(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1312]
# asm 1: vandpd 1312(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1312(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1312(%rsi),%ymm3,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1696]
# asm 1: vandpd 1696(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1696(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1696(%rsi),%ymm4,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 2080]
# asm 1: vandpd 2080(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2080(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2080(%rsi),%ymm4,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2464]
# asm 1: vandpd 2464(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2464(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2464(%rsi),%ymm4,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 2848]
# asm 1: vandpd 2848(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2848(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2848(%rsi),%ymm4,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3232]
# asm 1: vandpd 3232(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3232(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3232(%rsi),%ymm5,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3616]
# asm 1: vandpd 3616(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3616(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3616(%rsi),%ymm5,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 4000]
# asm 1: vandpd 4000(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4000(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4000(%rsi),%ymm5,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4384]
# asm 1: vandpd 4384(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4384(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4384(%rsi),%ymm5,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4768]
# asm 1: vandpd 4768(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4768(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4768(%rsi),%ymm6,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 5152]
# asm 1: vandpd 5152(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5152(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5152(%rsi),%ymm6,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5536]
# asm 1: vandpd 5536(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5536(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5536(%rsi),%ymm6,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 5920]
# asm 1: vandpd 5920(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5920(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5920(%rsi),%ymm6,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6304]
# asm 1: vandpd 6304(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6304(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6304(%rsi),%ymm7,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6688]
# asm 1: vandpd 6688(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6688(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6688(%rsi),%ymm7,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 7072]
# asm 1: vandpd 7072(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7072(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7072(%rsi),%ymm7,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7456]
# asm 1: vandpd 7456(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7456(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7456(%rsi),%ymm7,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 7840]
# asm 1: vandpd 7840(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 7840(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 7840(%rsi),%ymm8,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8224]
# asm 1: vandpd 8224(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8224(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8224(%rsi),%ymm8,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8608]
# asm 1: vandpd 8608(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8608(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8608(%rsi),%ymm8,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 8992]
# asm 1: vandpd 8992(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8992(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8992(%rsi),%ymm8,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9376]
# asm 1: vandpd 9376(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9376(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9376(%rsi),%ymm9,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9760]
# asm 1: vandpd 9760(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9760(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9760(%rsi),%ymm9,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 10144]
# asm 1: vandpd 10144(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10144(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10144(%rsi),%ymm9,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10528]
# asm 1: vandpd 10528(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10528(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10528(%rsi),%ymm9,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 10912]
# asm 1: vandpd 10912(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 10912(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 10912(%rsi),%ymm10,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11296]
# asm 1: vandpd 11296(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11296(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11296(%rsi),%ymm10,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11680]
# asm 1: vandpd 11680(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11680(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11680(%rsi),%ymm10,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 12064]
# asm 1: vandpd 12064(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 12064(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 12064(%rsi),%ymm10,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 160] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,160(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,160(<input_0=%rdi)
vmovapd   %ymm11,160(%rdi)

# qhasm: mem256[input_0 + 544] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,544(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,544(<input_0=%rdi)
vmovapd   %ymm12,544(%rdi)

# qhasm: mem256[input_0 + 928] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,928(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,928(<input_0=%rdi)
vmovapd   %ymm2,928(%rdi)

# qhasm: mem256[input_0 + 1312] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1312(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1312(<input_0=%rdi)
vmovapd   %ymm13,1312(%rdi)

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 ^= t1
# asm 1: vxorpd <t1=reg256#13,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <t1=%ymm12,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: t2 ^= t2
# asm 1: vxorpd <t2=reg256#3,<t2=reg256#3,<t2=reg256#3
# asm 2: vxorpd <t2=%ymm2,<t2=%ymm2,<t2=%ymm2
vxorpd %ymm2,%ymm2,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 192]
# asm 1: vandpd 192(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 192(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 192(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 576]
# asm 1: vandpd 576(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 576(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 576(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 960]
# asm 1: vandpd 960(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 960(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 960(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1344]
# asm 1: vandpd 1344(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1344(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1344(%rsi),%ymm3,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1728]
# asm 1: vandpd 1728(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1728(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1728(%rsi),%ymm4,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 2112]
# asm 1: vandpd 2112(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2112(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2112(%rsi),%ymm4,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2496]
# asm 1: vandpd 2496(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2496(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2496(%rsi),%ymm4,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 2880]
# asm 1: vandpd 2880(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2880(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2880(%rsi),%ymm4,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3264]
# asm 1: vandpd 3264(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3264(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3264(%rsi),%ymm5,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3648]
# asm 1: vandpd 3648(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3648(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3648(%rsi),%ymm5,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 4032]
# asm 1: vandpd 4032(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4032(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4032(%rsi),%ymm5,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4416]
# asm 1: vandpd 4416(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4416(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4416(%rsi),%ymm5,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4800]
# asm 1: vandpd 4800(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4800(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4800(%rsi),%ymm6,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 5184]
# asm 1: vandpd 5184(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5184(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5184(%rsi),%ymm6,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5568]
# asm 1: vandpd 5568(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5568(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5568(%rsi),%ymm6,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 5952]
# asm 1: vandpd 5952(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5952(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5952(%rsi),%ymm6,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6336]
# asm 1: vandpd 6336(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6336(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6336(%rsi),%ymm7,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6720]
# asm 1: vandpd 6720(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6720(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6720(%rsi),%ymm7,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 7104]
# asm 1: vandpd 7104(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7104(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7104(%rsi),%ymm7,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7488]
# asm 1: vandpd 7488(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7488(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7488(%rsi),%ymm7,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 7872]
# asm 1: vandpd 7872(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 7872(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 7872(%rsi),%ymm8,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8256]
# asm 1: vandpd 8256(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8256(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8256(%rsi),%ymm8,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8640]
# asm 1: vandpd 8640(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8640(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8640(%rsi),%ymm8,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 9024]
# asm 1: vandpd 9024(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 9024(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 9024(%rsi),%ymm8,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9408]
# asm 1: vandpd 9408(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9408(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9408(%rsi),%ymm9,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9792]
# asm 1: vandpd 9792(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9792(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9792(%rsi),%ymm9,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 10176]
# asm 1: vandpd 10176(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10176(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10176(%rsi),%ymm9,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10560]
# asm 1: vandpd 10560(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10560(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10560(%rsi),%ymm9,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 10944]
# asm 1: vandpd 10944(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 10944(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 10944(%rsi),%ymm10,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11328]
# asm 1: vandpd 11328(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11328(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11328(%rsi),%ymm10,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11712]
# asm 1: vandpd 11712(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11712(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11712(%rsi),%ymm10,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 12096]
# asm 1: vandpd 12096(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 12096(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 12096(%rsi),%ymm10,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 192] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,192(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,192(<input_0=%rdi)
vmovapd   %ymm11,192(%rdi)

# qhasm: mem256[input_0 + 576] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,576(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,576(<input_0=%rdi)
vmovapd   %ymm12,576(%rdi)

# qhasm: mem256[input_0 + 960] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,960(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,960(<input_0=%rdi)
vmovapd   %ymm2,960(%rdi)

# qhasm: mem256[input_0 + 1344] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1344(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1344(<input_0=%rdi)
vmovapd   %ymm13,1344(%rdi)

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 ^= t1
# asm 1: vxorpd <t1=reg256#13,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <t1=%ymm12,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: t2 ^= t2
# asm 1: vxorpd <t2=reg256#3,<t2=reg256#3,<t2=reg256#3
# asm 2: vxorpd <t2=%ymm2,<t2=%ymm2,<t2=%ymm2
vxorpd %ymm2,%ymm2,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 224]
# asm 1: vandpd 224(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 224(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 224(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 608]
# asm 1: vandpd 608(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 608(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 608(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 992]
# asm 1: vandpd 992(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 992(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 992(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1376]
# asm 1: vandpd 1376(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1376(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1376(%rsi),%ymm3,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1760]
# asm 1: vandpd 1760(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1760(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1760(%rsi),%ymm4,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 2144]
# asm 1: vandpd 2144(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2144(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2144(%rsi),%ymm4,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2528]
# asm 1: vandpd 2528(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2528(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2528(%rsi),%ymm4,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 2912]
# asm 1: vandpd 2912(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2912(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2912(%rsi),%ymm4,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3296]
# asm 1: vandpd 3296(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3296(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3296(%rsi),%ymm5,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3680]
# asm 1: vandpd 3680(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3680(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3680(%rsi),%ymm5,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 4064]
# asm 1: vandpd 4064(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4064(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4064(%rsi),%ymm5,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4448]
# asm 1: vandpd 4448(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4448(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4448(%rsi),%ymm5,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4832]
# asm 1: vandpd 4832(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4832(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4832(%rsi),%ymm6,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 5216]
# asm 1: vandpd 5216(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5216(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5216(%rsi),%ymm6,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5600]
# asm 1: vandpd 5600(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5600(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5600(%rsi),%ymm6,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 5984]
# asm 1: vandpd 5984(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5984(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5984(%rsi),%ymm6,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6368]
# asm 1: vandpd 6368(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6368(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6368(%rsi),%ymm7,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6752]
# asm 1: vandpd 6752(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6752(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6752(%rsi),%ymm7,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 7136]
# asm 1: vandpd 7136(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7136(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7136(%rsi),%ymm7,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7520]
# asm 1: vandpd 7520(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7520(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7520(%rsi),%ymm7,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 7904]
# asm 1: vandpd 7904(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 7904(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 7904(%rsi),%ymm8,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8288]
# asm 1: vandpd 8288(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8288(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8288(%rsi),%ymm8,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8672]
# asm 1: vandpd 8672(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8672(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8672(%rsi),%ymm8,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 9056]
# asm 1: vandpd 9056(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 9056(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 9056(%rsi),%ymm8,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9440]
# asm 1: vandpd 9440(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9440(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9440(%rsi),%ymm9,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9824]
# asm 1: vandpd 9824(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9824(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9824(%rsi),%ymm9,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 10208]
# asm 1: vandpd 10208(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10208(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10208(%rsi),%ymm9,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10592]
# asm 1: vandpd 10592(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10592(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10592(%rsi),%ymm9,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 10976]
# asm 1: vandpd 10976(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 10976(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 10976(%rsi),%ymm10,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11360]
# asm 1: vandpd 11360(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11360(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11360(%rsi),%ymm10,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11744]
# asm 1: vandpd 11744(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11744(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11744(%rsi),%ymm10,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 12128]
# asm 1: vandpd 12128(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 12128(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 12128(%rsi),%ymm10,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 224] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,224(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,224(<input_0=%rdi)
vmovapd   %ymm11,224(%rdi)

# qhasm: mem256[input_0 + 608] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,608(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,608(<input_0=%rdi)
vmovapd   %ymm12,608(%rdi)

# qhasm: mem256[input_0 + 992] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,992(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,992(<input_0=%rdi)
vmovapd   %ymm2,992(%rdi)

# qhasm: mem256[input_0 + 1376] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1376(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1376(<input_0=%rdi)
vmovapd   %ymm13,1376(%rdi)

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 ^= t1
# asm 1: vxorpd <t1=reg256#13,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <t1=%ymm12,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: t2 ^= t2
# asm 1: vxorpd <t2=reg256#3,<t2=reg256#3,<t2=reg256#3
# asm 2: vxorpd <t2=%ymm2,<t2=%ymm2,<t2=%ymm2
vxorpd %ymm2,%ymm2,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 256]
# asm 1: vandpd 256(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 256(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 256(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 640]
# asm 1: vandpd 640(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 640(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 640(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 1024]
# asm 1: vandpd 1024(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1024(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1024(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1408]
# asm 1: vandpd 1408(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1408(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1408(%rsi),%ymm3,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1792]
# asm 1: vandpd 1792(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1792(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1792(%rsi),%ymm4,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 2176]
# asm 1: vandpd 2176(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2176(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2176(%rsi),%ymm4,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2560]
# asm 1: vandpd 2560(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2560(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2560(%rsi),%ymm4,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 2944]
# asm 1: vandpd 2944(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2944(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2944(%rsi),%ymm4,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3328]
# asm 1: vandpd 3328(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3328(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3328(%rsi),%ymm5,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3712]
# asm 1: vandpd 3712(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3712(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3712(%rsi),%ymm5,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 4096]
# asm 1: vandpd 4096(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4096(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4096(%rsi),%ymm5,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4480]
# asm 1: vandpd 4480(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4480(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4480(%rsi),%ymm5,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4864]
# asm 1: vandpd 4864(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4864(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4864(%rsi),%ymm6,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 5248]
# asm 1: vandpd 5248(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5248(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5248(%rsi),%ymm6,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5632]
# asm 1: vandpd 5632(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5632(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5632(%rsi),%ymm6,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 6016]
# asm 1: vandpd 6016(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 6016(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 6016(%rsi),%ymm6,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6400]
# asm 1: vandpd 6400(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6400(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6400(%rsi),%ymm7,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6784]
# asm 1: vandpd 6784(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6784(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6784(%rsi),%ymm7,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 7168]
# asm 1: vandpd 7168(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7168(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7168(%rsi),%ymm7,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7552]
# asm 1: vandpd 7552(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7552(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7552(%rsi),%ymm7,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 7936]
# asm 1: vandpd 7936(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 7936(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 7936(%rsi),%ymm8,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8320]
# asm 1: vandpd 8320(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8320(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8320(%rsi),%ymm8,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8704]
# asm 1: vandpd 8704(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8704(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8704(%rsi),%ymm8,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 9088]
# asm 1: vandpd 9088(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 9088(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 9088(%rsi),%ymm8,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9472]
# asm 1: vandpd 9472(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9472(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9472(%rsi),%ymm9,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9856]
# asm 1: vandpd 9856(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9856(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9856(%rsi),%ymm9,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 10240]
# asm 1: vandpd 10240(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10240(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10240(%rsi),%ymm9,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10624]
# asm 1: vandpd 10624(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10624(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10624(%rsi),%ymm9,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 11008]
# asm 1: vandpd 11008(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11008(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11008(%rsi),%ymm10,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11392]
# asm 1: vandpd 11392(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11392(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11392(%rsi),%ymm10,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11776]
# asm 1: vandpd 11776(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11776(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11776(%rsi),%ymm10,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 12160]
# asm 1: vandpd 12160(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 12160(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 12160(%rsi),%ymm10,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 256] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,256(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,256(<input_0=%rdi)
vmovapd   %ymm11,256(%rdi)

# qhasm: mem256[input_0 + 640] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,640(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,640(<input_0=%rdi)
vmovapd   %ymm12,640(%rdi)

# qhasm: mem256[input_0 + 1024] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,1024(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,1024(<input_0=%rdi)
vmovapd   %ymm2,1024(%rdi)

# qhasm: mem256[input_0 + 1408] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1408(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1408(<input_0=%rdi)
vmovapd   %ymm13,1408(%rdi)

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 ^= t1
# asm 1: vxorpd <t1=reg256#13,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <t1=%ymm12,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: t2 ^= t2
# asm 1: vxorpd <t2=reg256#3,<t2=reg256#3,<t2=reg256#3
# asm 2: vxorpd <t2=%ymm2,<t2=%ymm2,<t2=%ymm2
vxorpd %ymm2,%ymm2,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 288]
# asm 1: vandpd 288(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 288(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 288(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 672]
# asm 1: vandpd 672(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 672(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 672(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 1056]
# asm 1: vandpd 1056(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1056(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1056(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1440]
# asm 1: vandpd 1440(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1440(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1440(%rsi),%ymm3,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1824]
# asm 1: vandpd 1824(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1824(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1824(%rsi),%ymm4,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 2208]
# asm 1: vandpd 2208(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2208(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2208(%rsi),%ymm4,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2592]
# asm 1: vandpd 2592(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2592(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2592(%rsi),%ymm4,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 2976]
# asm 1: vandpd 2976(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2976(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2976(%rsi),%ymm4,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3360]
# asm 1: vandpd 3360(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3360(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3360(%rsi),%ymm5,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3744]
# asm 1: vandpd 3744(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3744(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3744(%rsi),%ymm5,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 4128]
# asm 1: vandpd 4128(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4128(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4128(%rsi),%ymm5,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4512]
# asm 1: vandpd 4512(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4512(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4512(%rsi),%ymm5,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4896]
# asm 1: vandpd 4896(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4896(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4896(%rsi),%ymm6,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 5280]
# asm 1: vandpd 5280(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5280(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5280(%rsi),%ymm6,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5664]
# asm 1: vandpd 5664(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5664(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5664(%rsi),%ymm6,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 6048]
# asm 1: vandpd 6048(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 6048(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 6048(%rsi),%ymm6,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6432]
# asm 1: vandpd 6432(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6432(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6432(%rsi),%ymm7,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6816]
# asm 1: vandpd 6816(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6816(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6816(%rsi),%ymm7,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 7200]
# asm 1: vandpd 7200(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7200(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7200(%rsi),%ymm7,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7584]
# asm 1: vandpd 7584(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7584(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7584(%rsi),%ymm7,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 7968]
# asm 1: vandpd 7968(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 7968(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 7968(%rsi),%ymm8,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8352]
# asm 1: vandpd 8352(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8352(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8352(%rsi),%ymm8,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8736]
# asm 1: vandpd 8736(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8736(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8736(%rsi),%ymm8,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 9120]
# asm 1: vandpd 9120(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 9120(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 9120(%rsi),%ymm8,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9504]
# asm 1: vandpd 9504(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9504(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9504(%rsi),%ymm9,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9888]
# asm 1: vandpd 9888(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9888(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9888(%rsi),%ymm9,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 10272]
# asm 1: vandpd 10272(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10272(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10272(%rsi),%ymm9,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10656]
# asm 1: vandpd 10656(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10656(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10656(%rsi),%ymm9,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 11040]
# asm 1: vandpd 11040(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11040(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11040(%rsi),%ymm10,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11424]
# asm 1: vandpd 11424(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11424(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11424(%rsi),%ymm10,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11808]
# asm 1: vandpd 11808(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11808(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11808(%rsi),%ymm10,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 12192]
# asm 1: vandpd 12192(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 12192(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 12192(%rsi),%ymm10,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 288] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,288(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,288(<input_0=%rdi)
vmovapd   %ymm11,288(%rdi)

# qhasm: mem256[input_0 + 672] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,672(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,672(<input_0=%rdi)
vmovapd   %ymm12,672(%rdi)

# qhasm: mem256[input_0 + 1056] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,1056(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,1056(<input_0=%rdi)
vmovapd   %ymm2,1056(%rdi)

# qhasm: mem256[input_0 + 1440] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1440(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1440(<input_0=%rdi)
vmovapd   %ymm13,1440(%rdi)

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 ^= t1
# asm 1: vxorpd <t1=reg256#13,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <t1=%ymm12,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: t2 ^= t2
# asm 1: vxorpd <t2=reg256#3,<t2=reg256#3,<t2=reg256#3
# asm 2: vxorpd <t2=%ymm2,<t2=%ymm2,<t2=%ymm2
vxorpd %ymm2,%ymm2,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 320]
# asm 1: vandpd 320(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 320(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 320(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 704]
# asm 1: vandpd 704(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 704(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 704(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 1088]
# asm 1: vandpd 1088(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1088(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1088(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1472]
# asm 1: vandpd 1472(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1472(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1472(%rsi),%ymm3,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1856]
# asm 1: vandpd 1856(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 1856(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 1856(%rsi),%ymm4,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 2240]
# asm 1: vandpd 2240(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2240(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2240(%rsi),%ymm4,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2624]
# asm 1: vandpd 2624(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 2624(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 2624(%rsi),%ymm4,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 3008]
# asm 1: vandpd 3008(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#15
# asm 2: vandpd 3008(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm14
vandpd 3008(%rsi),%ymm4,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3392]
# asm 1: vandpd 3392(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3392(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3392(%rsi),%ymm5,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3776]
# asm 1: vandpd 3776(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 3776(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 3776(%rsi),%ymm5,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 4160]
# asm 1: vandpd 4160(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4160(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4160(%rsi),%ymm5,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4544]
# asm 1: vandpd 4544(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#15
# asm 2: vandpd 4544(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm14
vandpd 4544(%rsi),%ymm5,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4928]
# asm 1: vandpd 4928(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 4928(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 4928(%rsi),%ymm6,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 5312]
# asm 1: vandpd 5312(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5312(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5312(%rsi),%ymm6,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5696]
# asm 1: vandpd 5696(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 5696(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 5696(%rsi),%ymm6,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 6080]
# asm 1: vandpd 6080(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#15
# asm 2: vandpd 6080(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm14
vandpd 6080(%rsi),%ymm6,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6464]
# asm 1: vandpd 6464(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6464(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6464(%rsi),%ymm7,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6848]
# asm 1: vandpd 6848(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 6848(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 6848(%rsi),%ymm7,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 7232]
# asm 1: vandpd 7232(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7232(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7232(%rsi),%ymm7,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7616]
# asm 1: vandpd 7616(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#15
# asm 2: vandpd 7616(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm14
vandpd 7616(%rsi),%ymm7,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 8000]
# asm 1: vandpd 8000(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8000(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8000(%rsi),%ymm8,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8384]
# asm 1: vandpd 8384(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8384(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8384(%rsi),%ymm8,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8768]
# asm 1: vandpd 8768(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 8768(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 8768(%rsi),%ymm8,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 9152]
# asm 1: vandpd 9152(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#15
# asm 2: vandpd 9152(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm14
vandpd 9152(%rsi),%ymm8,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9536]
# asm 1: vandpd 9536(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9536(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9536(%rsi),%ymm9,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9920]
# asm 1: vandpd 9920(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 9920(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 9920(%rsi),%ymm9,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 10304]
# asm 1: vandpd 10304(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10304(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10304(%rsi),%ymm9,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10688]
# asm 1: vandpd 10688(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#15
# asm 2: vandpd 10688(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm14
vandpd 10688(%rsi),%ymm9,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 11072]
# asm 1: vandpd 11072(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11072(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11072(%rsi),%ymm10,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11456]
# asm 1: vandpd 11456(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11456(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11456(%rsi),%ymm10,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11840]
# asm 1: vandpd 11840(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 11840(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 11840(%rsi),%ymm10,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 12224]
# asm 1: vandpd 12224(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#15
# asm 2: vandpd 12224(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm14
vandpd 12224(%rsi),%ymm10,%ymm14

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#15,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm14,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 320] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,320(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,320(<input_0=%rdi)
vmovapd   %ymm11,320(%rdi)

# qhasm: mem256[input_0 + 704] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,704(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,704(<input_0=%rdi)
vmovapd   %ymm12,704(%rdi)

# qhasm: mem256[input_0 + 1088] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,1088(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,1088(<input_0=%rdi)
vmovapd   %ymm2,1088(%rdi)

# qhasm: mem256[input_0 + 1472] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1472(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1472(<input_0=%rdi)
vmovapd   %ymm13,1472(%rdi)

# qhasm: t0 ^= t0
# asm 1: vxorpd <t0=reg256#12,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <t0=%ymm11,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm11,%ymm11,%ymm11

# qhasm: t1 ^= t1
# asm 1: vxorpd <t1=reg256#13,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <t1=%ymm12,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: t2 ^= t2
# asm 1: vxorpd <t2=reg256#3,<t2=reg256#3,<t2=reg256#3
# asm 2: vxorpd <t2=%ymm2,<t2=%ymm2,<t2=%ymm2
vxorpd %ymm2,%ymm2,%ymm2

# qhasm: t3 ^= t3
# asm 1: vxorpd <t3=reg256#14,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <t3=%ymm13,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: res1 =  mask1 & mem256[input_1 + 352]
# asm 1: vandpd 352(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 352(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 352(%rsi),%ymm3,%ymm14

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#15,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm14,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm14,%ymm11,%ymm11

# qhasm: res1 =  mask1 & mem256[input_1 + 736]
# asm 1: vandpd 736(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 736(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 736(%rsi),%ymm3,%ymm14

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: res1 =  mask1 & mem256[input_1 + 1120]
# asm 1: vandpd 1120(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#15
# asm 2: vandpd 1120(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm14
vandpd 1120(%rsi),%ymm3,%ymm14

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#15,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm14,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm14,%ymm2,%ymm2

# qhasm: res1 =  mask1 & mem256[input_1 + 1504]
# asm 1: vandpd 1504(<input_1=int64#2),<mask1=reg256#4,>res1=reg256#4
# asm 2: vandpd 1504(<input_1=%rsi),<mask1=%ymm3,>res1=%ymm3
vandpd 1504(%rsi),%ymm3,%ymm3

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#4,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm3,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm3,%ymm13,%ymm13

# qhasm: res1 =  mask2 & mem256[input_1 + 1888]
# asm 1: vandpd 1888(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#4
# asm 2: vandpd 1888(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm3
vandpd 1888(%rsi),%ymm4,%ymm3

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#4,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm3,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm3,%ymm11,%ymm11

# qhasm: res1 =  mask2 & mem256[input_1 + 2272]
# asm 1: vandpd 2272(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#4
# asm 2: vandpd 2272(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm3
vandpd 2272(%rsi),%ymm4,%ymm3

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#4,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm3,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm3,%ymm12,%ymm12

# qhasm: res1 =  mask2 & mem256[input_1 + 2656]
# asm 1: vandpd 2656(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#4
# asm 2: vandpd 2656(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm3
vandpd 2656(%rsi),%ymm4,%ymm3

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#4,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm3,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm3,%ymm2,%ymm2

# qhasm: res1 =  mask2 & mem256[input_1 + 3040]
# asm 1: vandpd 3040(<input_1=int64#2),<mask2=reg256#5,>res1=reg256#4
# asm 2: vandpd 3040(<input_1=%rsi),<mask2=%ymm4,>res1=%ymm3
vandpd 3040(%rsi),%ymm4,%ymm3

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#4,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm3,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm3,%ymm13,%ymm13

# qhasm: res1 =  mask3 & mem256[input_1 + 3424]
# asm 1: vandpd 3424(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#4
# asm 2: vandpd 3424(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm3
vandpd 3424(%rsi),%ymm5,%ymm3

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#4,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm3,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm3,%ymm11,%ymm11

# qhasm: res1 =  mask3 & mem256[input_1 + 3808]
# asm 1: vandpd 3808(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#4
# asm 2: vandpd 3808(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm3
vandpd 3808(%rsi),%ymm5,%ymm3

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#4,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm3,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm3,%ymm12,%ymm12

# qhasm: res1 =  mask3 & mem256[input_1 + 4192]
# asm 1: vandpd 4192(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#4
# asm 2: vandpd 4192(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm3
vandpd 4192(%rsi),%ymm5,%ymm3

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#4,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm3,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm3,%ymm2,%ymm2

# qhasm: res1 =  mask3 & mem256[input_1 + 4576]
# asm 1: vandpd 4576(<input_1=int64#2),<mask3=reg256#6,>res1=reg256#4
# asm 2: vandpd 4576(<input_1=%rsi),<mask3=%ymm5,>res1=%ymm3
vandpd 4576(%rsi),%ymm5,%ymm3

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#4,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm3,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm3,%ymm13,%ymm13

# qhasm: res1 =  mask4 & mem256[input_1 + 4960]
# asm 1: vandpd 4960(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#4
# asm 2: vandpd 4960(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm3
vandpd 4960(%rsi),%ymm6,%ymm3

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#4,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm3,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm3,%ymm11,%ymm11

# qhasm: res1 =  mask4 & mem256[input_1 + 5344]
# asm 1: vandpd 5344(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#4
# asm 2: vandpd 5344(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm3
vandpd 5344(%rsi),%ymm6,%ymm3

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#4,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm3,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm3,%ymm12,%ymm12

# qhasm: res1 =  mask4 & mem256[input_1 + 5728]
# asm 1: vandpd 5728(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#4
# asm 2: vandpd 5728(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm3
vandpd 5728(%rsi),%ymm6,%ymm3

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#4,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm3,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm3,%ymm2,%ymm2

# qhasm: res1 =  mask4 & mem256[input_1 + 6112]
# asm 1: vandpd 6112(<input_1=int64#2),<mask4=reg256#7,>res1=reg256#4
# asm 2: vandpd 6112(<input_1=%rsi),<mask4=%ymm6,>res1=%ymm3
vandpd 6112(%rsi),%ymm6,%ymm3

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#4,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm3,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm3,%ymm13,%ymm13

# qhasm: res1 =  mask5 & mem256[input_1 + 6496]
# asm 1: vandpd 6496(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#4
# asm 2: vandpd 6496(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm3
vandpd 6496(%rsi),%ymm7,%ymm3

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#4,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm3,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm3,%ymm11,%ymm11

# qhasm: res1 =  mask5 & mem256[input_1 + 6880]
# asm 1: vandpd 6880(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#4
# asm 2: vandpd 6880(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm3
vandpd 6880(%rsi),%ymm7,%ymm3

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#4,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm3,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm3,%ymm12,%ymm12

# qhasm: res1 =  mask5 & mem256[input_1 + 7264]
# asm 1: vandpd 7264(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#4
# asm 2: vandpd 7264(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm3
vandpd 7264(%rsi),%ymm7,%ymm3

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#4,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm3,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm3,%ymm2,%ymm2

# qhasm: res1 =  mask5 & mem256[input_1 + 7648]
# asm 1: vandpd 7648(<input_1=int64#2),<mask5=reg256#8,>res1=reg256#4
# asm 2: vandpd 7648(<input_1=%rsi),<mask5=%ymm7,>res1=%ymm3
vandpd 7648(%rsi),%ymm7,%ymm3

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#4,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm3,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm3,%ymm13,%ymm13

# qhasm: res1 =  mask6 & mem256[input_1 + 8032]
# asm 1: vandpd 8032(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#4
# asm 2: vandpd 8032(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm3
vandpd 8032(%rsi),%ymm8,%ymm3

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#4,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm3,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm3,%ymm11,%ymm11

# qhasm: res1 =  mask6 & mem256[input_1 + 8416]
# asm 1: vandpd 8416(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#4
# asm 2: vandpd 8416(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm3
vandpd 8416(%rsi),%ymm8,%ymm3

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#4,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm3,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm3,%ymm12,%ymm12

# qhasm: res1 =  mask6 & mem256[input_1 + 8800]
# asm 1: vandpd 8800(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#4
# asm 2: vandpd 8800(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm3
vandpd 8800(%rsi),%ymm8,%ymm3

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#4,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm3,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm3,%ymm2,%ymm2

# qhasm: res1 =  mask6 & mem256[input_1 + 9184]
# asm 1: vandpd 9184(<input_1=int64#2),<mask6=reg256#9,>res1=reg256#4
# asm 2: vandpd 9184(<input_1=%rsi),<mask6=%ymm8,>res1=%ymm3
vandpd 9184(%rsi),%ymm8,%ymm3

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#4,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm3,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm3,%ymm13,%ymm13

# qhasm: res1 =  mask7 & mem256[input_1 + 9568]
# asm 1: vandpd 9568(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#4
# asm 2: vandpd 9568(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm3
vandpd 9568(%rsi),%ymm9,%ymm3

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#4,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm3,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm3,%ymm11,%ymm11

# qhasm: res1 =  mask7 & mem256[input_1 + 9952]
# asm 1: vandpd 9952(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#4
# asm 2: vandpd 9952(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm3
vandpd 9952(%rsi),%ymm9,%ymm3

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#4,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm3,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm3,%ymm12,%ymm12

# qhasm: res1 =  mask7 & mem256[input_1 + 10336]
# asm 1: vandpd 10336(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#4
# asm 2: vandpd 10336(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm3
vandpd 10336(%rsi),%ymm9,%ymm3

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#4,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm3,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm3,%ymm2,%ymm2

# qhasm: res1 =  mask7 & mem256[input_1 + 10720]
# asm 1: vandpd 10720(<input_1=int64#2),<mask7=reg256#10,>res1=reg256#4
# asm 2: vandpd 10720(<input_1=%rsi),<mask7=%ymm9,>res1=%ymm3
vandpd 10720(%rsi),%ymm9,%ymm3

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#4,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm3,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm3,%ymm13,%ymm13

# qhasm: res1 =  mask8 & mem256[input_1 + 11104]
# asm 1: vandpd 11104(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#4
# asm 2: vandpd 11104(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm3
vandpd 11104(%rsi),%ymm10,%ymm3

# qhasm: t0 |= res1
# asm 1: vorpd  <res1=reg256#4,<t0=reg256#12,<t0=reg256#12
# asm 2: vorpd  <res1=%ymm3,<t0=%ymm11,<t0=%ymm11
vorpd  %ymm3,%ymm11,%ymm11

# qhasm: res1 =  mask8 & mem256[input_1 + 11488]
# asm 1: vandpd 11488(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#4
# asm 2: vandpd 11488(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm3
vandpd 11488(%rsi),%ymm10,%ymm3

# qhasm: t1 |= res1
# asm 1: vorpd  <res1=reg256#4,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <res1=%ymm3,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm3,%ymm12,%ymm12

# qhasm: res1 =  mask8 & mem256[input_1 + 11872]
# asm 1: vandpd 11872(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#4
# asm 2: vandpd 11872(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm3
vandpd 11872(%rsi),%ymm10,%ymm3

# qhasm: t2 |= res1
# asm 1: vorpd  <res1=reg256#4,<t2=reg256#3,<t2=reg256#3
# asm 2: vorpd  <res1=%ymm3,<t2=%ymm2,<t2=%ymm2
vorpd  %ymm3,%ymm2,%ymm2

# qhasm: res1 =  mask8 & mem256[input_1 + 12256]
# asm 1: vandpd 12256(<input_1=int64#2),<mask8=reg256#11,>res1=reg256#4
# asm 2: vandpd 12256(<input_1=%rsi),<mask8=%ymm10,>res1=%ymm3
vandpd 12256(%rsi),%ymm10,%ymm3

# qhasm: t3 |= res1
# asm 1: vorpd  <res1=reg256#4,<t3=reg256#14,<t3=reg256#14
# asm 2: vorpd  <res1=%ymm3,<t3=%ymm13,<t3=%ymm13
vorpd  %ymm3,%ymm13,%ymm13

# qhasm: t0 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t0=reg256#12,<t0=reg256#12
# asm 2: vxorpd <flip=%ymm0,<t0=%ymm11,<t0=%ymm11
vxorpd %ymm0,%ymm11,%ymm11

# qhasm: t3 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t3=reg256#14,<t3=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t3=%ymm13,<t3=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 352] aligned= t0
# asm 1: vmovapd   <t0=reg256#12,352(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm11,352(<input_0=%rdi)
vmovapd   %ymm11,352(%rdi)

# qhasm: mem256[input_0 + 736] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,736(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,736(<input_0=%rdi)
vmovapd   %ymm12,736(%rdi)

# qhasm: mem256[input_0 + 1120] aligned= t2
# asm 1: vmovapd   <t2=reg256#3,1120(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm2,1120(<input_0=%rdi)
vmovapd   %ymm2,1120(%rdi)

# qhasm: mem256[input_0 + 1504] aligned= t3
# asm 1: vmovapd   <t3=reg256#14,1504(<input_0=int64#1)
# asm 2: vmovapd   <t3=%ymm13,1504(<input_0=%rdi)
vmovapd   %ymm13,1504(%rdi)

# qhasm: return
add %r11,%rsp
ret
