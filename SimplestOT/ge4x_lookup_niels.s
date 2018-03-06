
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

# qhasm: reg256 v0

# qhasm: reg256 v1

# qhasm: reg256 v2

# qhasm: reg256 s

# qhasm: reg256 t

# qhasm: reg256 z

# qhasm: reg256 t0

# qhasm: reg256 t1

# qhasm: reg256 t2

# qhasm: reg256 t3

# qhasm: reg256 i

# qhasm: reg256 flip

# qhasm: reg256 diff

# qhasm: reg256 neg_mask

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

# qhasm: enter ge4x_lookup_niels_asm
.p2align 5
.global _ge4x_lookup_niels_asm
.global ge4x_lookup_niels_asm
_ge4x_lookup_niels_asm:
ge4x_lookup_niels_asm:
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

# qhasm: (int64) r0 >>= 7
# asm 1: sar  $7,<r0=int64#5
# asm 2: sar  $7,<r0=%r8
sar  $7,%r8

# qhasm: r0 = -r0
# asm 1: neg  <r0=int64#5
# asm 2: neg  <r0=%r8
neg  %r8

# qhasm: (int64) r1 >>= 7
# asm 1: sar  $7,<r1=int64#6
# asm 2: sar  $7,<r1=%r9
sar  $7,%r9

# qhasm: r1 = -r1
# asm 1: neg  <r1=int64#6
# asm 2: neg  <r1=%r9
neg  %r9

# qhasm: (int64) r2 >>= 7
# asm 1: sar  $7,<r2=int64#7
# asm 2: sar  $7,<r2=%rax
sar  $7,%rax

# qhasm: r2 = -r2
# asm 1: neg  <r2=int64#7
# asm 2: neg  <r2=%rax
neg  %rax

# qhasm: (int64) r3 >>= 7
# asm 1: sar  $7,<r3=int64#3
# asm 2: sar  $7,<r3=%rdx
sar  $7,%rdx

# qhasm: r3 = -r3
# asm 1: neg  <r3=int64#3
# asm 2: neg  <r3=%rdx
neg  %rdx

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

# qhasm: neg_mask = buf
# asm 1: vmovapd <buf=stack256#1,>neg_mask=reg256#2
# asm 2: vmovapd <buf=0(%rsp),>neg_mask=%ymm1
vmovapd 0(%rsp),%ymm1

# qhasm: allone aligned= mem256[_allone]
# asm 1: vmovapd _allone,>allone=reg256#3
# asm 2: vmovapd _allone,>allone=%ymm2
vmovapd _allone,%ymm2

# qhasm: i aligned= mem256[_idx0]
# asm 1: vmovapd _idx0,>i=reg256#4
# asm 2: vmovapd _idx0,>i=%ymm3
vmovapd _idx0,%ymm3

# qhasm: mask0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#4,>mask0=reg256#4
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm3,>mask0=%ymm3
vcmpeqpd %ymm0,%ymm3,%ymm3

# qhasm: i aligned= mem256[_idx_1]
# asm 1: vmovapd _idx_1,>i=reg256#5
# asm 2: vmovapd _idx_1,>i=%ymm4
vmovapd _idx_1,%ymm4

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#5,>res0=reg256#5
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm4,>res0=%ymm4
vcmpeqpd %ymm0,%ymm4,%ymm4

# qhasm: i aligned= mem256[_idx1]
# asm 1: vmovapd _idx1,>i=reg256#6
# asm 2: vmovapd _idx1,>i=%ymm5
vmovapd _idx1,%ymm5

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#6,>res1=reg256#6
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm5,>res1=%ymm5
vcmpeqpd %ymm0,%ymm5,%ymm5

# qhasm: mask1 = res0 | res1
# asm 1: vorpd  <res0=reg256#5,<res1=reg256#6,>mask1=reg256#5
# asm 2: vorpd  <res0=%ymm4,<res1=%ymm5,>mask1=%ymm4
vorpd  %ymm4,%ymm5,%ymm4

# qhasm: i aligned= mem256[_idx_2]
# asm 1: vmovapd _idx_2,>i=reg256#6
# asm 2: vmovapd _idx_2,>i=%ymm5
vmovapd _idx_2,%ymm5

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#6,>res0=reg256#6
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm5,>res0=%ymm5
vcmpeqpd %ymm0,%ymm5,%ymm5

# qhasm: i aligned= mem256[_idx2]
# asm 1: vmovapd _idx2,>i=reg256#7
# asm 2: vmovapd _idx2,>i=%ymm6
vmovapd _idx2,%ymm6

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#7,>res1=reg256#7
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm6,>res1=%ymm6
vcmpeqpd %ymm0,%ymm6,%ymm6

# qhasm: mask2 = res0 | res1
# asm 1: vorpd  <res0=reg256#6,<res1=reg256#7,>mask2=reg256#6
# asm 2: vorpd  <res0=%ymm5,<res1=%ymm6,>mask2=%ymm5
vorpd  %ymm5,%ymm6,%ymm5

# qhasm: i aligned= mem256[_idx_3]
# asm 1: vmovapd _idx_3,>i=reg256#7
# asm 2: vmovapd _idx_3,>i=%ymm6
vmovapd _idx_3,%ymm6

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#7,>res0=reg256#7
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm6,>res0=%ymm6
vcmpeqpd %ymm0,%ymm6,%ymm6

# qhasm: i aligned= mem256[_idx3]
# asm 1: vmovapd _idx3,>i=reg256#8
# asm 2: vmovapd _idx3,>i=%ymm7
vmovapd _idx3,%ymm7

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#8,>res1=reg256#8
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm7,>res1=%ymm7
vcmpeqpd %ymm0,%ymm7,%ymm7

# qhasm: mask3 = res0 | res1
# asm 1: vorpd  <res0=reg256#7,<res1=reg256#8,>mask3=reg256#7
# asm 2: vorpd  <res0=%ymm6,<res1=%ymm7,>mask3=%ymm6
vorpd  %ymm6,%ymm7,%ymm6

# qhasm: i aligned= mem256[_idx_4]
# asm 1: vmovapd _idx_4,>i=reg256#8
# asm 2: vmovapd _idx_4,>i=%ymm7
vmovapd _idx_4,%ymm7

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#8,>res0=reg256#8
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm7,>res0=%ymm7
vcmpeqpd %ymm0,%ymm7,%ymm7

# qhasm: i aligned= mem256[_idx4]
# asm 1: vmovapd _idx4,>i=reg256#9
# asm 2: vmovapd _idx4,>i=%ymm8
vmovapd _idx4,%ymm8

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#9,>res1=reg256#9
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm8,>res1=%ymm8
vcmpeqpd %ymm0,%ymm8,%ymm8

# qhasm: mask4 = res0 | res1
# asm 1: vorpd  <res0=reg256#8,<res1=reg256#9,>mask4=reg256#8
# asm 2: vorpd  <res0=%ymm7,<res1=%ymm8,>mask4=%ymm7
vorpd  %ymm7,%ymm8,%ymm7

# qhasm: i aligned= mem256[_idx_5]
# asm 1: vmovapd _idx_5,>i=reg256#9
# asm 2: vmovapd _idx_5,>i=%ymm8
vmovapd _idx_5,%ymm8

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#9,>res0=reg256#9
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm8,>res0=%ymm8
vcmpeqpd %ymm0,%ymm8,%ymm8

# qhasm: i aligned= mem256[_idx5]
# asm 1: vmovapd _idx5,>i=reg256#10
# asm 2: vmovapd _idx5,>i=%ymm9
vmovapd _idx5,%ymm9

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#10,>res1=reg256#10
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm9,>res1=%ymm9
vcmpeqpd %ymm0,%ymm9,%ymm9

# qhasm: mask5 = res0 | res1
# asm 1: vorpd  <res0=reg256#9,<res1=reg256#10,>mask5=reg256#9
# asm 2: vorpd  <res0=%ymm8,<res1=%ymm9,>mask5=%ymm8
vorpd  %ymm8,%ymm9,%ymm8

# qhasm: i aligned= mem256[_idx_6]
# asm 1: vmovapd _idx_6,>i=reg256#10
# asm 2: vmovapd _idx_6,>i=%ymm9
vmovapd _idx_6,%ymm9

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#10,>res0=reg256#10
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm9,>res0=%ymm9
vcmpeqpd %ymm0,%ymm9,%ymm9

# qhasm: i aligned= mem256[_idx6]
# asm 1: vmovapd _idx6,>i=reg256#11
# asm 2: vmovapd _idx6,>i=%ymm10
vmovapd _idx6,%ymm10

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#11,>res1=reg256#11
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm10,>res1=%ymm10
vcmpeqpd %ymm0,%ymm10,%ymm10

# qhasm: mask6 = res0 | res1
# asm 1: vorpd  <res0=reg256#10,<res1=reg256#11,>mask6=reg256#10
# asm 2: vorpd  <res0=%ymm9,<res1=%ymm10,>mask6=%ymm9
vorpd  %ymm9,%ymm10,%ymm9

# qhasm: i aligned= mem256[_idx_7]
# asm 1: vmovapd _idx_7,>i=reg256#11
# asm 2: vmovapd _idx_7,>i=%ymm10
vmovapd _idx_7,%ymm10

# qhasm: res0 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#11,>res0=reg256#11
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm10,>res0=%ymm10
vcmpeqpd %ymm0,%ymm10,%ymm10

# qhasm: i aligned= mem256[_idx7]
# asm 1: vmovapd _idx7,>i=reg256#12
# asm 2: vmovapd _idx7,>i=%ymm11
vmovapd _idx7,%ymm11

# qhasm: res1 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#12,>res1=reg256#12
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm11,>res1=%ymm11
vcmpeqpd %ymm0,%ymm11,%ymm11

# qhasm: mask7 = res0 | res1
# asm 1: vorpd  <res0=reg256#11,<res1=reg256#12,>mask7=reg256#11
# asm 2: vorpd  <res0=%ymm10,<res1=%ymm11,>mask7=%ymm10
vorpd  %ymm10,%ymm11,%ymm10

# qhasm: i aligned= mem256[_idx_8]
# asm 1: vmovapd _idx_8,>i=reg256#12
# asm 2: vmovapd _idx_8,>i=%ymm11
vmovapd _idx_8,%ymm11

# qhasm: mask8 = (v == i)
# asm 1: vcmpeqpd <v=reg256#1,<i=reg256#12,>mask8=reg256#12
# asm 2: vcmpeqpd <v=%ymm0,<i=%ymm11,>mask8=%ymm11
vcmpeqpd %ymm0,%ymm11,%ymm11

# qhasm: F0 aligned= mem256[_F0]
# asm 1: vmovapd _F0,>F0=reg256#13
# asm 2: vmovapd _F0,>F0=%ymm12
vmovapd _F0,%ymm12

# qhasm: flip = v^F0
# asm 1: vxorpd <v=reg256#1,<F0=reg256#13,>flip=reg256#1
# asm 2: vxorpd <v=%ymm0,<F0=%ymm12,>flip=%ymm0
vxorpd %ymm0,%ymm12,%ymm0

# qhasm: 4x flip approx-= F0
# asm 1: vsubpd <F0=reg256#13,<flip=reg256#1,>flip=reg256#1
# asm 2: vsubpd <F0=%ymm12,<flip=%ymm0,>flip=%ymm0
vsubpd %ymm12,%ymm0,%ymm0

# qhasm: mzero aligned= mem256[_mzero]
# asm 1: vmovapd _mzero,>mzero=reg256#13
# asm 2: vmovapd _mzero,>mzero=%ymm12
vmovapd _mzero,%ymm12

# qhasm: flip &= mzero
# asm 1: vandpd <mzero=reg256#13,<flip=reg256#1,<flip=reg256#1
# asm 2: vandpd <mzero=%ymm12,<flip=%ymm0,<flip=%ymm0
vandpd %ymm12,%ymm0,%ymm0

# qhasm: t0 = mem256[_one]
# asm 1: vmovupd _one,>t0=reg256#13
# asm 2: vmovupd _one,>t0=%ymm12
vmovupd _one,%ymm12

# qhasm: t0 &= mask0
# asm 1: vandpd <mask0=reg256#4,<t0=reg256#13,<t0=reg256#13
# asm 2: vandpd <mask0=%ymm3,<t0=%ymm12,<t0=%ymm12
vandpd %ymm3,%ymm12,%ymm12

# qhasm: t1 = t0
# asm 1: vmovapd <t0=reg256#13,>t1=reg256#4
# asm 2: vmovapd <t0=%ymm12,>t1=%ymm3
vmovapd %ymm12,%ymm3

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 0] x4
# asm 1: vbroadcastsd 0(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 0(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 0(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#13,<t0=reg256#13
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm12,<t0=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v1 =  mem64[input_1 + 96] x4
# asm 1: vbroadcastsd 96(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 96(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 96(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#4,<t1=reg256#4
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm3,<t1=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v2 =  mem64[input_1 + 192] x4
# asm 1: vbroadcastsd 192(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 192(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 192(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 288] x4
# asm 1: vbroadcastsd 288(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 288(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 288(%rsi),%ymm14

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm14,<v0=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#13,<t0=reg256#13
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm12,<t0=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v1 =  mem64[input_1 + 384] x4
# asm 1: vbroadcastsd 384(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 384(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 384(%rsi),%ymm14

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm14,<v1=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#4,<t1=reg256#4
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm3,<t1=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v2 =  mem64[input_1 + 480] x4
# asm 1: vbroadcastsd 480(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 480(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 480(%rsi),%ymm14

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm14,<v2=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 576] x4
# asm 1: vbroadcastsd 576(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 576(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 576(%rsi),%ymm14

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm14,<v0=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#13,<t0=reg256#13
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm12,<t0=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v1 =  mem64[input_1 + 672] x4
# asm 1: vbroadcastsd 672(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 672(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 672(%rsi),%ymm14

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm14,<v1=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#4,<t1=reg256#4
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm3,<t1=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v2 =  mem64[input_1 + 768] x4
# asm 1: vbroadcastsd 768(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 768(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 768(%rsi),%ymm14

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm14,<v2=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 864] x4
# asm 1: vbroadcastsd 864(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 864(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 864(%rsi),%ymm14

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm14,<v0=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#13,<t0=reg256#13
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm12,<t0=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v1 =  mem64[input_1 + 960] x4
# asm 1: vbroadcastsd 960(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 960(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 960(%rsi),%ymm14

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm14,<v1=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#4,<t1=reg256#4
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm3,<t1=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v2 =  mem64[input_1 + 1056] x4
# asm 1: vbroadcastsd 1056(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1056(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1056(%rsi),%ymm14

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm14,<v2=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1152] x4
# asm 1: vbroadcastsd 1152(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1152(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1152(%rsi),%ymm14

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm14,<v0=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#13,<t0=reg256#13
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm12,<t0=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v1 =  mem64[input_1 + 1248] x4
# asm 1: vbroadcastsd 1248(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1248(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1248(%rsi),%ymm14

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm14,<v1=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#4,<t1=reg256#4
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm3,<t1=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v2 =  mem64[input_1 + 1344] x4
# asm 1: vbroadcastsd 1344(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1344(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1344(%rsi),%ymm14

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm14,<v2=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1440] x4
# asm 1: vbroadcastsd 1440(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1440(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1440(%rsi),%ymm14

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm14,<v0=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#13,<t0=reg256#13
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm12,<t0=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v1 =  mem64[input_1 + 1536] x4
# asm 1: vbroadcastsd 1536(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1536(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1536(%rsi),%ymm14

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm14,<v1=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#4,<t1=reg256#4
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm3,<t1=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v2 =  mem64[input_1 + 1632] x4
# asm 1: vbroadcastsd 1632(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1632(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1632(%rsi),%ymm14

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm14,<v2=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1728] x4
# asm 1: vbroadcastsd 1728(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1728(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1728(%rsi),%ymm14

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm14,<v0=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#13,<t0=reg256#13
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm12,<t0=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v1 =  mem64[input_1 + 1824] x4
# asm 1: vbroadcastsd 1824(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1824(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1824(%rsi),%ymm14

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm14,<v1=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#4,<t1=reg256#4
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm3,<t1=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v2 =  mem64[input_1 + 1920] x4
# asm 1: vbroadcastsd 1920(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1920(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1920(%rsi),%ymm14

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm14,<v2=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2016] x4
# asm 1: vbroadcastsd 2016(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 2016(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 2016(%rsi),%ymm14

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm14,<v0=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#13,<t0=reg256#13
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm12,<t0=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v1 =  mem64[input_1 + 2112] x4
# asm 1: vbroadcastsd 2112(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 2112(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 2112(%rsi),%ymm14

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm14,<v1=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#4,<t1=reg256#4
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm3,<t1=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v2 =  mem64[input_1 + 2208] x4
# asm 1: vbroadcastsd 2208(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2208(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2208(%rsi),%ymm14

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm14,<v2=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 768] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,768(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,768(<input_0=%rdi)
vmovapd   %ymm13,768(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#13,<t1=reg256#4,>diff=reg256#14
# asm 2: vxorpd <t0=%ymm12,<t1=%ymm3,>diff=%ymm13
vxorpd %ymm12,%ymm3,%ymm13

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#14,<diff=reg256#14
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm13,<diff=%ymm13
vandpd %ymm1,%ymm13,%ymm13

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t0=reg256#13,<t0=reg256#13
# asm 2: vxorpd <diff=%ymm13,<t0=%ymm12,<t0=%ymm12
vxorpd %ymm13,%ymm12,%ymm12

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t1=reg256#4,<t1=reg256#4
# asm 2: vxorpd <diff=%ymm13,<t1=%ymm3,<t1=%ymm3
vxorpd %ymm13,%ymm3,%ymm3

# qhasm: mem256[input_0 + 0] aligned= t0
# asm 1: vmovapd   <t0=reg256#13,0(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm12,0(<input_0=%rdi)
vmovapd   %ymm12,0(%rdi)

# qhasm: mem256[input_0 + 384] aligned= t1
# asm 1: vmovapd   <t1=reg256#4,384(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm3,384(<input_0=%rdi)
vmovapd   %ymm3,384(%rdi)

# qhasm: clear t0
# asm 1: vxorpd >t0=reg256#4,>t0=reg256#4,>t0=reg256#4
# asm 2: vxorpd >t0=%ymm3,>t0=%ymm3,>t0=%ymm3
vxorpd %ymm3,%ymm3,%ymm3

# qhasm: clear t1
# asm 1: vxorpd >t1=reg256#13,>t1=reg256#13,>t1=reg256#13
# asm 2: vxorpd >t1=%ymm12,>t1=%ymm12,>t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 8] x4
# asm 1: vbroadcastsd 8(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 8(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 8(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 104] x4
# asm 1: vbroadcastsd 104(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 104(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 104(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 200] x4
# asm 1: vbroadcastsd 200(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 200(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 200(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 296] x4
# asm 1: vbroadcastsd 296(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 296(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 296(%rsi),%ymm14

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm14,<v0=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 392] x4
# asm 1: vbroadcastsd 392(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 392(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 392(%rsi),%ymm14

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm14,<v1=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 488] x4
# asm 1: vbroadcastsd 488(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 488(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 488(%rsi),%ymm14

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm14,<v2=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 584] x4
# asm 1: vbroadcastsd 584(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 584(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 584(%rsi),%ymm14

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm14,<v0=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 680] x4
# asm 1: vbroadcastsd 680(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 680(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 680(%rsi),%ymm14

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm14,<v1=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 776] x4
# asm 1: vbroadcastsd 776(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 776(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 776(%rsi),%ymm14

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm14,<v2=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 872] x4
# asm 1: vbroadcastsd 872(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 872(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 872(%rsi),%ymm14

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm14,<v0=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 968] x4
# asm 1: vbroadcastsd 968(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 968(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 968(%rsi),%ymm14

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm14,<v1=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1064] x4
# asm 1: vbroadcastsd 1064(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1064(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1064(%rsi),%ymm14

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm14,<v2=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1160] x4
# asm 1: vbroadcastsd 1160(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1160(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1160(%rsi),%ymm14

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm14,<v0=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1256] x4
# asm 1: vbroadcastsd 1256(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1256(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1256(%rsi),%ymm14

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm14,<v1=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1352] x4
# asm 1: vbroadcastsd 1352(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1352(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1352(%rsi),%ymm14

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm14,<v2=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1448] x4
# asm 1: vbroadcastsd 1448(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1448(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1448(%rsi),%ymm14

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm14,<v0=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1544] x4
# asm 1: vbroadcastsd 1544(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1544(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1544(%rsi),%ymm14

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm14,<v1=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1640] x4
# asm 1: vbroadcastsd 1640(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1640(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1640(%rsi),%ymm14

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm14,<v2=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1736] x4
# asm 1: vbroadcastsd 1736(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1736(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1736(%rsi),%ymm14

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm14,<v0=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1832] x4
# asm 1: vbroadcastsd 1832(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1832(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1832(%rsi),%ymm14

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm14,<v1=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1928] x4
# asm 1: vbroadcastsd 1928(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1928(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1928(%rsi),%ymm14

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm14,<v2=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2024] x4
# asm 1: vbroadcastsd 2024(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 2024(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 2024(%rsi),%ymm14

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm14,<v0=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 2120] x4
# asm 1: vbroadcastsd 2120(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 2120(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 2120(%rsi),%ymm14

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm14,<v1=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2216] x4
# asm 1: vbroadcastsd 2216(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2216(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2216(%rsi),%ymm14

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm14,<v2=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 800] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,800(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,800(<input_0=%rdi)
vmovapd   %ymm13,800(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#4,<t1=reg256#13,>diff=reg256#14
# asm 2: vxorpd <t0=%ymm3,<t1=%ymm12,>diff=%ymm13
vxorpd %ymm3,%ymm12,%ymm13

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#14,<diff=reg256#14
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm13,<diff=%ymm13
vandpd %ymm1,%ymm13,%ymm13

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t0=reg256#4,<t0=reg256#4
# asm 2: vxorpd <diff=%ymm13,<t0=%ymm3,<t0=%ymm3
vxorpd %ymm13,%ymm3,%ymm3

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <diff=%ymm13,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm13,%ymm12,%ymm12

# qhasm: mem256[input_0 + 32] aligned= t0
# asm 1: vmovapd   <t0=reg256#4,32(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm3,32(<input_0=%rdi)
vmovapd   %ymm3,32(%rdi)

# qhasm: mem256[input_0 + 416] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,416(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,416(<input_0=%rdi)
vmovapd   %ymm12,416(%rdi)

# qhasm: clear t0
# asm 1: vxorpd >t0=reg256#4,>t0=reg256#4,>t0=reg256#4
# asm 2: vxorpd >t0=%ymm3,>t0=%ymm3,>t0=%ymm3
vxorpd %ymm3,%ymm3,%ymm3

# qhasm: clear t1
# asm 1: vxorpd >t1=reg256#13,>t1=reg256#13,>t1=reg256#13
# asm 2: vxorpd >t1=%ymm12,>t1=%ymm12,>t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 16] x4
# asm 1: vbroadcastsd 16(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 16(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 16(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 112] x4
# asm 1: vbroadcastsd 112(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 112(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 112(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 208] x4
# asm 1: vbroadcastsd 208(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 208(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 208(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 304] x4
# asm 1: vbroadcastsd 304(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 304(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 304(%rsi),%ymm14

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm14,<v0=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 400] x4
# asm 1: vbroadcastsd 400(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 400(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 400(%rsi),%ymm14

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm14,<v1=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 496] x4
# asm 1: vbroadcastsd 496(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 496(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 496(%rsi),%ymm14

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm14,<v2=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 592] x4
# asm 1: vbroadcastsd 592(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 592(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 592(%rsi),%ymm14

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm14,<v0=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 688] x4
# asm 1: vbroadcastsd 688(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 688(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 688(%rsi),%ymm14

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm14,<v1=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 784] x4
# asm 1: vbroadcastsd 784(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 784(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 784(%rsi),%ymm14

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm14,<v2=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 880] x4
# asm 1: vbroadcastsd 880(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 880(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 880(%rsi),%ymm14

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm14,<v0=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 976] x4
# asm 1: vbroadcastsd 976(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 976(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 976(%rsi),%ymm14

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm14,<v1=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1072] x4
# asm 1: vbroadcastsd 1072(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1072(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1072(%rsi),%ymm14

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm14,<v2=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1168] x4
# asm 1: vbroadcastsd 1168(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1168(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1168(%rsi),%ymm14

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm14,<v0=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1264] x4
# asm 1: vbroadcastsd 1264(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1264(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1264(%rsi),%ymm14

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm14,<v1=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1360] x4
# asm 1: vbroadcastsd 1360(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1360(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1360(%rsi),%ymm14

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm14,<v2=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1456] x4
# asm 1: vbroadcastsd 1456(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1456(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1456(%rsi),%ymm14

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm14,<v0=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1552] x4
# asm 1: vbroadcastsd 1552(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1552(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1552(%rsi),%ymm14

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm14,<v1=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1648] x4
# asm 1: vbroadcastsd 1648(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1648(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1648(%rsi),%ymm14

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm14,<v2=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1744] x4
# asm 1: vbroadcastsd 1744(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1744(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1744(%rsi),%ymm14

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm14,<v0=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1840] x4
# asm 1: vbroadcastsd 1840(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1840(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1840(%rsi),%ymm14

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm14,<v1=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1936] x4
# asm 1: vbroadcastsd 1936(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1936(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1936(%rsi),%ymm14

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm14,<v2=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2032] x4
# asm 1: vbroadcastsd 2032(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 2032(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 2032(%rsi),%ymm14

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm14,<v0=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 2128] x4
# asm 1: vbroadcastsd 2128(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 2128(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 2128(%rsi),%ymm14

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm14,<v1=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2224] x4
# asm 1: vbroadcastsd 2224(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2224(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2224(%rsi),%ymm14

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm14,<v2=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 832] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,832(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,832(<input_0=%rdi)
vmovapd   %ymm13,832(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#4,<t1=reg256#13,>diff=reg256#14
# asm 2: vxorpd <t0=%ymm3,<t1=%ymm12,>diff=%ymm13
vxorpd %ymm3,%ymm12,%ymm13

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#14,<diff=reg256#14
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm13,<diff=%ymm13
vandpd %ymm1,%ymm13,%ymm13

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t0=reg256#4,<t0=reg256#4
# asm 2: vxorpd <diff=%ymm13,<t0=%ymm3,<t0=%ymm3
vxorpd %ymm13,%ymm3,%ymm3

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <diff=%ymm13,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm13,%ymm12,%ymm12

# qhasm: mem256[input_0 + 64] aligned= t0
# asm 1: vmovapd   <t0=reg256#4,64(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm3,64(<input_0=%rdi)
vmovapd   %ymm3,64(%rdi)

# qhasm: mem256[input_0 + 448] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,448(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,448(<input_0=%rdi)
vmovapd   %ymm12,448(%rdi)

# qhasm: clear t0
# asm 1: vxorpd >t0=reg256#4,>t0=reg256#4,>t0=reg256#4
# asm 2: vxorpd >t0=%ymm3,>t0=%ymm3,>t0=%ymm3
vxorpd %ymm3,%ymm3,%ymm3

# qhasm: clear t1
# asm 1: vxorpd >t1=reg256#13,>t1=reg256#13,>t1=reg256#13
# asm 2: vxorpd >t1=%ymm12,>t1=%ymm12,>t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 24] x4
# asm 1: vbroadcastsd 24(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 24(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 24(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 120] x4
# asm 1: vbroadcastsd 120(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 120(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 120(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 216] x4
# asm 1: vbroadcastsd 216(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 216(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 216(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 312] x4
# asm 1: vbroadcastsd 312(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 312(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 312(%rsi),%ymm14

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm14,<v0=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 408] x4
# asm 1: vbroadcastsd 408(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 408(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 408(%rsi),%ymm14

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm14,<v1=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 504] x4
# asm 1: vbroadcastsd 504(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 504(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 504(%rsi),%ymm14

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm14,<v2=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 600] x4
# asm 1: vbroadcastsd 600(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 600(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 600(%rsi),%ymm14

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm14,<v0=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 696] x4
# asm 1: vbroadcastsd 696(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 696(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 696(%rsi),%ymm14

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm14,<v1=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 792] x4
# asm 1: vbroadcastsd 792(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 792(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 792(%rsi),%ymm14

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm14,<v2=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 888] x4
# asm 1: vbroadcastsd 888(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 888(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 888(%rsi),%ymm14

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm14,<v0=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 984] x4
# asm 1: vbroadcastsd 984(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 984(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 984(%rsi),%ymm14

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm14,<v1=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1080] x4
# asm 1: vbroadcastsd 1080(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1080(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1080(%rsi),%ymm14

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm14,<v2=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1176] x4
# asm 1: vbroadcastsd 1176(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1176(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1176(%rsi),%ymm14

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm14,<v0=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1272] x4
# asm 1: vbroadcastsd 1272(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1272(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1272(%rsi),%ymm14

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm14,<v1=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1368] x4
# asm 1: vbroadcastsd 1368(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1368(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1368(%rsi),%ymm14

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm14,<v2=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1464] x4
# asm 1: vbroadcastsd 1464(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1464(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1464(%rsi),%ymm14

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm14,<v0=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1560] x4
# asm 1: vbroadcastsd 1560(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1560(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1560(%rsi),%ymm14

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm14,<v1=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1656] x4
# asm 1: vbroadcastsd 1656(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1656(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1656(%rsi),%ymm14

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm14,<v2=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1752] x4
# asm 1: vbroadcastsd 1752(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1752(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1752(%rsi),%ymm14

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm14,<v0=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1848] x4
# asm 1: vbroadcastsd 1848(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1848(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1848(%rsi),%ymm14

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm14,<v1=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1944] x4
# asm 1: vbroadcastsd 1944(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1944(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1944(%rsi),%ymm14

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm14,<v2=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2040] x4
# asm 1: vbroadcastsd 2040(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 2040(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 2040(%rsi),%ymm14

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm14,<v0=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 2136] x4
# asm 1: vbroadcastsd 2136(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 2136(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 2136(%rsi),%ymm14

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm14,<v1=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2232] x4
# asm 1: vbroadcastsd 2232(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2232(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2232(%rsi),%ymm14

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm14,<v2=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 864] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,864(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,864(<input_0=%rdi)
vmovapd   %ymm13,864(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#4,<t1=reg256#13,>diff=reg256#14
# asm 2: vxorpd <t0=%ymm3,<t1=%ymm12,>diff=%ymm13
vxorpd %ymm3,%ymm12,%ymm13

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#14,<diff=reg256#14
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm13,<diff=%ymm13
vandpd %ymm1,%ymm13,%ymm13

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t0=reg256#4,<t0=reg256#4
# asm 2: vxorpd <diff=%ymm13,<t0=%ymm3,<t0=%ymm3
vxorpd %ymm13,%ymm3,%ymm3

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <diff=%ymm13,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm13,%ymm12,%ymm12

# qhasm: mem256[input_0 + 96] aligned= t0
# asm 1: vmovapd   <t0=reg256#4,96(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm3,96(<input_0=%rdi)
vmovapd   %ymm3,96(%rdi)

# qhasm: mem256[input_0 + 480] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,480(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,480(<input_0=%rdi)
vmovapd   %ymm12,480(%rdi)

# qhasm: clear t0
# asm 1: vxorpd >t0=reg256#4,>t0=reg256#4,>t0=reg256#4
# asm 2: vxorpd >t0=%ymm3,>t0=%ymm3,>t0=%ymm3
vxorpd %ymm3,%ymm3,%ymm3

# qhasm: clear t1
# asm 1: vxorpd >t1=reg256#13,>t1=reg256#13,>t1=reg256#13
# asm 2: vxorpd >t1=%ymm12,>t1=%ymm12,>t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 32] x4
# asm 1: vbroadcastsd 32(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 32(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 32(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 128] x4
# asm 1: vbroadcastsd 128(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 128(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 128(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 224] x4
# asm 1: vbroadcastsd 224(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 224(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 224(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 320] x4
# asm 1: vbroadcastsd 320(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 320(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 320(%rsi),%ymm14

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm14,<v0=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 416] x4
# asm 1: vbroadcastsd 416(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 416(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 416(%rsi),%ymm14

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm14,<v1=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 512] x4
# asm 1: vbroadcastsd 512(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 512(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 512(%rsi),%ymm14

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm14,<v2=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 608] x4
# asm 1: vbroadcastsd 608(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 608(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 608(%rsi),%ymm14

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm14,<v0=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 704] x4
# asm 1: vbroadcastsd 704(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 704(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 704(%rsi),%ymm14

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm14,<v1=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 800] x4
# asm 1: vbroadcastsd 800(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 800(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 800(%rsi),%ymm14

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm14,<v2=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 896] x4
# asm 1: vbroadcastsd 896(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 896(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 896(%rsi),%ymm14

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm14,<v0=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 992] x4
# asm 1: vbroadcastsd 992(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 992(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 992(%rsi),%ymm14

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm14,<v1=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1088] x4
# asm 1: vbroadcastsd 1088(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1088(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1088(%rsi),%ymm14

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm14,<v2=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1184] x4
# asm 1: vbroadcastsd 1184(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1184(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1184(%rsi),%ymm14

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm14,<v0=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1280] x4
# asm 1: vbroadcastsd 1280(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1280(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1280(%rsi),%ymm14

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm14,<v1=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1376] x4
# asm 1: vbroadcastsd 1376(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1376(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1376(%rsi),%ymm14

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm14,<v2=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1472] x4
# asm 1: vbroadcastsd 1472(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1472(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1472(%rsi),%ymm14

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm14,<v0=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1568] x4
# asm 1: vbroadcastsd 1568(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1568(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1568(%rsi),%ymm14

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm14,<v1=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1664] x4
# asm 1: vbroadcastsd 1664(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1664(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1664(%rsi),%ymm14

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm14,<v2=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1760] x4
# asm 1: vbroadcastsd 1760(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1760(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1760(%rsi),%ymm14

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm14,<v0=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1856] x4
# asm 1: vbroadcastsd 1856(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1856(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1856(%rsi),%ymm14

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm14,<v1=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1952] x4
# asm 1: vbroadcastsd 1952(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1952(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1952(%rsi),%ymm14

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm14,<v2=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2048] x4
# asm 1: vbroadcastsd 2048(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 2048(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 2048(%rsi),%ymm14

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm14,<v0=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 2144] x4
# asm 1: vbroadcastsd 2144(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 2144(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 2144(%rsi),%ymm14

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm14,<v1=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2240] x4
# asm 1: vbroadcastsd 2240(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2240(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2240(%rsi),%ymm14

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm14,<v2=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 896] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,896(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,896(<input_0=%rdi)
vmovapd   %ymm13,896(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#4,<t1=reg256#13,>diff=reg256#14
# asm 2: vxorpd <t0=%ymm3,<t1=%ymm12,>diff=%ymm13
vxorpd %ymm3,%ymm12,%ymm13

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#14,<diff=reg256#14
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm13,<diff=%ymm13
vandpd %ymm1,%ymm13,%ymm13

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t0=reg256#4,<t0=reg256#4
# asm 2: vxorpd <diff=%ymm13,<t0=%ymm3,<t0=%ymm3
vxorpd %ymm13,%ymm3,%ymm3

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <diff=%ymm13,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm13,%ymm12,%ymm12

# qhasm: mem256[input_0 + 128] aligned= t0
# asm 1: vmovapd   <t0=reg256#4,128(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm3,128(<input_0=%rdi)
vmovapd   %ymm3,128(%rdi)

# qhasm: mem256[input_0 + 512] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,512(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,512(<input_0=%rdi)
vmovapd   %ymm12,512(%rdi)

# qhasm: clear t0
# asm 1: vxorpd >t0=reg256#4,>t0=reg256#4,>t0=reg256#4
# asm 2: vxorpd >t0=%ymm3,>t0=%ymm3,>t0=%ymm3
vxorpd %ymm3,%ymm3,%ymm3

# qhasm: clear t1
# asm 1: vxorpd >t1=reg256#13,>t1=reg256#13,>t1=reg256#13
# asm 2: vxorpd >t1=%ymm12,>t1=%ymm12,>t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 40] x4
# asm 1: vbroadcastsd 40(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 40(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 40(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 136] x4
# asm 1: vbroadcastsd 136(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 136(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 136(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 232] x4
# asm 1: vbroadcastsd 232(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 232(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 232(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 328] x4
# asm 1: vbroadcastsd 328(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 328(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 328(%rsi),%ymm14

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm14,<v0=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 424] x4
# asm 1: vbroadcastsd 424(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 424(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 424(%rsi),%ymm14

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm14,<v1=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 520] x4
# asm 1: vbroadcastsd 520(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 520(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 520(%rsi),%ymm14

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm14,<v2=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 616] x4
# asm 1: vbroadcastsd 616(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 616(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 616(%rsi),%ymm14

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm14,<v0=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 712] x4
# asm 1: vbroadcastsd 712(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 712(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 712(%rsi),%ymm14

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm14,<v1=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 808] x4
# asm 1: vbroadcastsd 808(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 808(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 808(%rsi),%ymm14

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm14,<v2=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 904] x4
# asm 1: vbroadcastsd 904(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 904(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 904(%rsi),%ymm14

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm14,<v0=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1000] x4
# asm 1: vbroadcastsd 1000(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1000(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1000(%rsi),%ymm14

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm14,<v1=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1096] x4
# asm 1: vbroadcastsd 1096(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1096(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1096(%rsi),%ymm14

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm14,<v2=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1192] x4
# asm 1: vbroadcastsd 1192(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1192(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1192(%rsi),%ymm14

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm14,<v0=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1288] x4
# asm 1: vbroadcastsd 1288(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1288(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1288(%rsi),%ymm14

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm14,<v1=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1384] x4
# asm 1: vbroadcastsd 1384(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1384(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1384(%rsi),%ymm14

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm14,<v2=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1480] x4
# asm 1: vbroadcastsd 1480(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1480(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1480(%rsi),%ymm14

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm14,<v0=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1576] x4
# asm 1: vbroadcastsd 1576(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1576(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1576(%rsi),%ymm14

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm14,<v1=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1672] x4
# asm 1: vbroadcastsd 1672(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1672(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1672(%rsi),%ymm14

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm14,<v2=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1768] x4
# asm 1: vbroadcastsd 1768(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1768(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1768(%rsi),%ymm14

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm14,<v0=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1864] x4
# asm 1: vbroadcastsd 1864(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1864(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1864(%rsi),%ymm14

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm14,<v1=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1960] x4
# asm 1: vbroadcastsd 1960(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1960(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1960(%rsi),%ymm14

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm14,<v2=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2056] x4
# asm 1: vbroadcastsd 2056(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 2056(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 2056(%rsi),%ymm14

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm14,<v0=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 2152] x4
# asm 1: vbroadcastsd 2152(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 2152(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 2152(%rsi),%ymm14

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm14,<v1=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2248] x4
# asm 1: vbroadcastsd 2248(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2248(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2248(%rsi),%ymm14

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm14,<v2=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 928] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,928(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,928(<input_0=%rdi)
vmovapd   %ymm13,928(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#4,<t1=reg256#13,>diff=reg256#14
# asm 2: vxorpd <t0=%ymm3,<t1=%ymm12,>diff=%ymm13
vxorpd %ymm3,%ymm12,%ymm13

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#14,<diff=reg256#14
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm13,<diff=%ymm13
vandpd %ymm1,%ymm13,%ymm13

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t0=reg256#4,<t0=reg256#4
# asm 2: vxorpd <diff=%ymm13,<t0=%ymm3,<t0=%ymm3
vxorpd %ymm13,%ymm3,%ymm3

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <diff=%ymm13,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm13,%ymm12,%ymm12

# qhasm: mem256[input_0 + 160] aligned= t0
# asm 1: vmovapd   <t0=reg256#4,160(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm3,160(<input_0=%rdi)
vmovapd   %ymm3,160(%rdi)

# qhasm: mem256[input_0 + 544] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,544(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,544(<input_0=%rdi)
vmovapd   %ymm12,544(%rdi)

# qhasm: clear t0
# asm 1: vxorpd >t0=reg256#4,>t0=reg256#4,>t0=reg256#4
# asm 2: vxorpd >t0=%ymm3,>t0=%ymm3,>t0=%ymm3
vxorpd %ymm3,%ymm3,%ymm3

# qhasm: clear t1
# asm 1: vxorpd >t1=reg256#13,>t1=reg256#13,>t1=reg256#13
# asm 2: vxorpd >t1=%ymm12,>t1=%ymm12,>t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 48] x4
# asm 1: vbroadcastsd 48(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 48(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 48(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 144] x4
# asm 1: vbroadcastsd 144(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 144(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 144(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 240] x4
# asm 1: vbroadcastsd 240(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 240(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 240(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 336] x4
# asm 1: vbroadcastsd 336(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 336(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 336(%rsi),%ymm14

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm14,<v0=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 432] x4
# asm 1: vbroadcastsd 432(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 432(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 432(%rsi),%ymm14

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm14,<v1=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 528] x4
# asm 1: vbroadcastsd 528(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 528(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 528(%rsi),%ymm14

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm14,<v2=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 624] x4
# asm 1: vbroadcastsd 624(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 624(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 624(%rsi),%ymm14

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm14,<v0=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 720] x4
# asm 1: vbroadcastsd 720(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 720(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 720(%rsi),%ymm14

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm14,<v1=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 816] x4
# asm 1: vbroadcastsd 816(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 816(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 816(%rsi),%ymm14

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm14,<v2=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 912] x4
# asm 1: vbroadcastsd 912(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 912(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 912(%rsi),%ymm14

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm14,<v0=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1008] x4
# asm 1: vbroadcastsd 1008(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1008(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1008(%rsi),%ymm14

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm14,<v1=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1104] x4
# asm 1: vbroadcastsd 1104(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1104(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1104(%rsi),%ymm14

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm14,<v2=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1200] x4
# asm 1: vbroadcastsd 1200(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1200(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1200(%rsi),%ymm14

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm14,<v0=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1296] x4
# asm 1: vbroadcastsd 1296(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1296(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1296(%rsi),%ymm14

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm14,<v1=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1392] x4
# asm 1: vbroadcastsd 1392(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1392(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1392(%rsi),%ymm14

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm14,<v2=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1488] x4
# asm 1: vbroadcastsd 1488(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1488(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1488(%rsi),%ymm14

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm14,<v0=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1584] x4
# asm 1: vbroadcastsd 1584(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1584(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1584(%rsi),%ymm14

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm14,<v1=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1680] x4
# asm 1: vbroadcastsd 1680(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1680(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1680(%rsi),%ymm14

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm14,<v2=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1776] x4
# asm 1: vbroadcastsd 1776(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1776(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1776(%rsi),%ymm14

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm14,<v0=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1872] x4
# asm 1: vbroadcastsd 1872(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1872(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1872(%rsi),%ymm14

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm14,<v1=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1968] x4
# asm 1: vbroadcastsd 1968(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1968(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1968(%rsi),%ymm14

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm14,<v2=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2064] x4
# asm 1: vbroadcastsd 2064(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 2064(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 2064(%rsi),%ymm14

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm14,<v0=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 2160] x4
# asm 1: vbroadcastsd 2160(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 2160(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 2160(%rsi),%ymm14

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm14,<v1=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2256] x4
# asm 1: vbroadcastsd 2256(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2256(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2256(%rsi),%ymm14

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm14,<v2=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 960] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,960(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,960(<input_0=%rdi)
vmovapd   %ymm13,960(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#4,<t1=reg256#13,>diff=reg256#14
# asm 2: vxorpd <t0=%ymm3,<t1=%ymm12,>diff=%ymm13
vxorpd %ymm3,%ymm12,%ymm13

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#14,<diff=reg256#14
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm13,<diff=%ymm13
vandpd %ymm1,%ymm13,%ymm13

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t0=reg256#4,<t0=reg256#4
# asm 2: vxorpd <diff=%ymm13,<t0=%ymm3,<t0=%ymm3
vxorpd %ymm13,%ymm3,%ymm3

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <diff=%ymm13,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm13,%ymm12,%ymm12

# qhasm: mem256[input_0 + 192] aligned= t0
# asm 1: vmovapd   <t0=reg256#4,192(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm3,192(<input_0=%rdi)
vmovapd   %ymm3,192(%rdi)

# qhasm: mem256[input_0 + 576] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,576(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,576(<input_0=%rdi)
vmovapd   %ymm12,576(%rdi)

# qhasm: clear t0
# asm 1: vxorpd >t0=reg256#4,>t0=reg256#4,>t0=reg256#4
# asm 2: vxorpd >t0=%ymm3,>t0=%ymm3,>t0=%ymm3
vxorpd %ymm3,%ymm3,%ymm3

# qhasm: clear t1
# asm 1: vxorpd >t1=reg256#13,>t1=reg256#13,>t1=reg256#13
# asm 2: vxorpd >t1=%ymm12,>t1=%ymm12,>t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 56] x4
# asm 1: vbroadcastsd 56(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 56(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 56(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 152] x4
# asm 1: vbroadcastsd 152(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 152(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 152(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 248] x4
# asm 1: vbroadcastsd 248(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 248(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 248(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 344] x4
# asm 1: vbroadcastsd 344(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 344(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 344(%rsi),%ymm14

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm14,<v0=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 440] x4
# asm 1: vbroadcastsd 440(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 440(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 440(%rsi),%ymm14

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm14,<v1=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 536] x4
# asm 1: vbroadcastsd 536(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 536(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 536(%rsi),%ymm14

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm14,<v2=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 632] x4
# asm 1: vbroadcastsd 632(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 632(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 632(%rsi),%ymm14

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm14,<v0=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 728] x4
# asm 1: vbroadcastsd 728(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 728(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 728(%rsi),%ymm14

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm14,<v1=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 824] x4
# asm 1: vbroadcastsd 824(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 824(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 824(%rsi),%ymm14

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm14,<v2=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 920] x4
# asm 1: vbroadcastsd 920(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 920(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 920(%rsi),%ymm14

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm14,<v0=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1016] x4
# asm 1: vbroadcastsd 1016(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1016(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1016(%rsi),%ymm14

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm14,<v1=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1112] x4
# asm 1: vbroadcastsd 1112(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1112(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1112(%rsi),%ymm14

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm14,<v2=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1208] x4
# asm 1: vbroadcastsd 1208(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1208(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1208(%rsi),%ymm14

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm14,<v0=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1304] x4
# asm 1: vbroadcastsd 1304(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1304(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1304(%rsi),%ymm14

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm14,<v1=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1400] x4
# asm 1: vbroadcastsd 1400(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1400(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1400(%rsi),%ymm14

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm14,<v2=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1496] x4
# asm 1: vbroadcastsd 1496(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1496(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1496(%rsi),%ymm14

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm14,<v0=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1592] x4
# asm 1: vbroadcastsd 1592(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1592(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1592(%rsi),%ymm14

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm14,<v1=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1688] x4
# asm 1: vbroadcastsd 1688(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1688(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1688(%rsi),%ymm14

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm14,<v2=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1784] x4
# asm 1: vbroadcastsd 1784(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1784(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1784(%rsi),%ymm14

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm14,<v0=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1880] x4
# asm 1: vbroadcastsd 1880(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1880(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1880(%rsi),%ymm14

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm14,<v1=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1976] x4
# asm 1: vbroadcastsd 1976(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1976(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1976(%rsi),%ymm14

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm14,<v2=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2072] x4
# asm 1: vbroadcastsd 2072(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 2072(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 2072(%rsi),%ymm14

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm14,<v0=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 2168] x4
# asm 1: vbroadcastsd 2168(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 2168(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 2168(%rsi),%ymm14

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm14,<v1=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2264] x4
# asm 1: vbroadcastsd 2264(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2264(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2264(%rsi),%ymm14

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm14,<v2=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 992] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,992(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,992(<input_0=%rdi)
vmovapd   %ymm13,992(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#4,<t1=reg256#13,>diff=reg256#14
# asm 2: vxorpd <t0=%ymm3,<t1=%ymm12,>diff=%ymm13
vxorpd %ymm3,%ymm12,%ymm13

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#14,<diff=reg256#14
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm13,<diff=%ymm13
vandpd %ymm1,%ymm13,%ymm13

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t0=reg256#4,<t0=reg256#4
# asm 2: vxorpd <diff=%ymm13,<t0=%ymm3,<t0=%ymm3
vxorpd %ymm13,%ymm3,%ymm3

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <diff=%ymm13,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm13,%ymm12,%ymm12

# qhasm: mem256[input_0 + 224] aligned= t0
# asm 1: vmovapd   <t0=reg256#4,224(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm3,224(<input_0=%rdi)
vmovapd   %ymm3,224(%rdi)

# qhasm: mem256[input_0 + 608] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,608(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,608(<input_0=%rdi)
vmovapd   %ymm12,608(%rdi)

# qhasm: clear t0
# asm 1: vxorpd >t0=reg256#4,>t0=reg256#4,>t0=reg256#4
# asm 2: vxorpd >t0=%ymm3,>t0=%ymm3,>t0=%ymm3
vxorpd %ymm3,%ymm3,%ymm3

# qhasm: clear t1
# asm 1: vxorpd >t1=reg256#13,>t1=reg256#13,>t1=reg256#13
# asm 2: vxorpd >t1=%ymm12,>t1=%ymm12,>t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 64] x4
# asm 1: vbroadcastsd 64(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 64(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 64(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 160] x4
# asm 1: vbroadcastsd 160(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 160(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 160(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 256] x4
# asm 1: vbroadcastsd 256(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 256(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 256(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 352] x4
# asm 1: vbroadcastsd 352(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 352(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 352(%rsi),%ymm14

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm14,<v0=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 448] x4
# asm 1: vbroadcastsd 448(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 448(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 448(%rsi),%ymm14

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm14,<v1=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 544] x4
# asm 1: vbroadcastsd 544(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 544(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 544(%rsi),%ymm14

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm14,<v2=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 640] x4
# asm 1: vbroadcastsd 640(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 640(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 640(%rsi),%ymm14

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm14,<v0=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 736] x4
# asm 1: vbroadcastsd 736(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 736(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 736(%rsi),%ymm14

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm14,<v1=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 832] x4
# asm 1: vbroadcastsd 832(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 832(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 832(%rsi),%ymm14

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm14,<v2=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 928] x4
# asm 1: vbroadcastsd 928(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 928(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 928(%rsi),%ymm14

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm14,<v0=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1024] x4
# asm 1: vbroadcastsd 1024(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1024(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1024(%rsi),%ymm14

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm14,<v1=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1120] x4
# asm 1: vbroadcastsd 1120(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1120(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1120(%rsi),%ymm14

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm14,<v2=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1216] x4
# asm 1: vbroadcastsd 1216(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1216(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1216(%rsi),%ymm14

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm14,<v0=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1312] x4
# asm 1: vbroadcastsd 1312(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1312(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1312(%rsi),%ymm14

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm14,<v1=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1408] x4
# asm 1: vbroadcastsd 1408(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1408(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1408(%rsi),%ymm14

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm14,<v2=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1504] x4
# asm 1: vbroadcastsd 1504(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1504(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1504(%rsi),%ymm14

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm14,<v0=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1600] x4
# asm 1: vbroadcastsd 1600(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1600(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1600(%rsi),%ymm14

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm14,<v1=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1696] x4
# asm 1: vbroadcastsd 1696(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1696(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1696(%rsi),%ymm14

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm14,<v2=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1792] x4
# asm 1: vbroadcastsd 1792(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1792(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1792(%rsi),%ymm14

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm14,<v0=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1888] x4
# asm 1: vbroadcastsd 1888(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1888(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1888(%rsi),%ymm14

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm14,<v1=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1984] x4
# asm 1: vbroadcastsd 1984(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1984(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1984(%rsi),%ymm14

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm14,<v2=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2080] x4
# asm 1: vbroadcastsd 2080(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 2080(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 2080(%rsi),%ymm14

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm14,<v0=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 2176] x4
# asm 1: vbroadcastsd 2176(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 2176(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 2176(%rsi),%ymm14

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm14,<v1=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2272] x4
# asm 1: vbroadcastsd 2272(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2272(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2272(%rsi),%ymm14

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm14,<v2=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 1024] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,1024(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,1024(<input_0=%rdi)
vmovapd   %ymm13,1024(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#4,<t1=reg256#13,>diff=reg256#14
# asm 2: vxorpd <t0=%ymm3,<t1=%ymm12,>diff=%ymm13
vxorpd %ymm3,%ymm12,%ymm13

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#14,<diff=reg256#14
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm13,<diff=%ymm13
vandpd %ymm1,%ymm13,%ymm13

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t0=reg256#4,<t0=reg256#4
# asm 2: vxorpd <diff=%ymm13,<t0=%ymm3,<t0=%ymm3
vxorpd %ymm13,%ymm3,%ymm3

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <diff=%ymm13,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm13,%ymm12,%ymm12

# qhasm: mem256[input_0 + 256] aligned= t0
# asm 1: vmovapd   <t0=reg256#4,256(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm3,256(<input_0=%rdi)
vmovapd   %ymm3,256(%rdi)

# qhasm: mem256[input_0 + 640] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,640(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,640(<input_0=%rdi)
vmovapd   %ymm12,640(%rdi)

# qhasm: clear t0
# asm 1: vxorpd >t0=reg256#4,>t0=reg256#4,>t0=reg256#4
# asm 2: vxorpd >t0=%ymm3,>t0=%ymm3,>t0=%ymm3
vxorpd %ymm3,%ymm3,%ymm3

# qhasm: clear t1
# asm 1: vxorpd >t1=reg256#13,>t1=reg256#13,>t1=reg256#13
# asm 2: vxorpd >t1=%ymm12,>t1=%ymm12,>t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 72] x4
# asm 1: vbroadcastsd 72(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 72(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 72(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 168] x4
# asm 1: vbroadcastsd 168(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 168(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 168(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 264] x4
# asm 1: vbroadcastsd 264(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 264(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 264(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 360] x4
# asm 1: vbroadcastsd 360(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 360(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 360(%rsi),%ymm14

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm14,<v0=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 456] x4
# asm 1: vbroadcastsd 456(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 456(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 456(%rsi),%ymm14

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm14,<v1=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 552] x4
# asm 1: vbroadcastsd 552(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 552(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 552(%rsi),%ymm14

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm14,<v2=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 648] x4
# asm 1: vbroadcastsd 648(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 648(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 648(%rsi),%ymm14

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm14,<v0=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 744] x4
# asm 1: vbroadcastsd 744(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 744(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 744(%rsi),%ymm14

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm14,<v1=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 840] x4
# asm 1: vbroadcastsd 840(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 840(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 840(%rsi),%ymm14

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm14,<v2=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 936] x4
# asm 1: vbroadcastsd 936(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 936(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 936(%rsi),%ymm14

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm14,<v0=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1032] x4
# asm 1: vbroadcastsd 1032(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1032(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1032(%rsi),%ymm14

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm14,<v1=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1128] x4
# asm 1: vbroadcastsd 1128(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1128(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1128(%rsi),%ymm14

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm14,<v2=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1224] x4
# asm 1: vbroadcastsd 1224(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1224(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1224(%rsi),%ymm14

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm14,<v0=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1320] x4
# asm 1: vbroadcastsd 1320(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1320(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1320(%rsi),%ymm14

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm14,<v1=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1416] x4
# asm 1: vbroadcastsd 1416(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1416(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1416(%rsi),%ymm14

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm14,<v2=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1512] x4
# asm 1: vbroadcastsd 1512(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1512(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1512(%rsi),%ymm14

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm14,<v0=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1608] x4
# asm 1: vbroadcastsd 1608(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1608(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1608(%rsi),%ymm14

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm14,<v1=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1704] x4
# asm 1: vbroadcastsd 1704(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1704(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1704(%rsi),%ymm14

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm14,<v2=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1800] x4
# asm 1: vbroadcastsd 1800(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1800(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1800(%rsi),%ymm14

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm14,<v0=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1896] x4
# asm 1: vbroadcastsd 1896(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1896(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1896(%rsi),%ymm14

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm14,<v1=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1992] x4
# asm 1: vbroadcastsd 1992(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1992(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1992(%rsi),%ymm14

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm14,<v2=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2088] x4
# asm 1: vbroadcastsd 2088(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 2088(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 2088(%rsi),%ymm14

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm14,<v0=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 2184] x4
# asm 1: vbroadcastsd 2184(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 2184(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 2184(%rsi),%ymm14

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm14,<v1=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2280] x4
# asm 1: vbroadcastsd 2280(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2280(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2280(%rsi),%ymm14

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm14,<v2=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 1056] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,1056(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,1056(<input_0=%rdi)
vmovapd   %ymm13,1056(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#4,<t1=reg256#13,>diff=reg256#14
# asm 2: vxorpd <t0=%ymm3,<t1=%ymm12,>diff=%ymm13
vxorpd %ymm3,%ymm12,%ymm13

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#14,<diff=reg256#14
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm13,<diff=%ymm13
vandpd %ymm1,%ymm13,%ymm13

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t0=reg256#4,<t0=reg256#4
# asm 2: vxorpd <diff=%ymm13,<t0=%ymm3,<t0=%ymm3
vxorpd %ymm13,%ymm3,%ymm3

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <diff=%ymm13,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm13,%ymm12,%ymm12

# qhasm: mem256[input_0 + 288] aligned= t0
# asm 1: vmovapd   <t0=reg256#4,288(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm3,288(<input_0=%rdi)
vmovapd   %ymm3,288(%rdi)

# qhasm: mem256[input_0 + 672] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,672(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,672(<input_0=%rdi)
vmovapd   %ymm12,672(%rdi)

# qhasm: clear t0
# asm 1: vxorpd >t0=reg256#4,>t0=reg256#4,>t0=reg256#4
# asm 2: vxorpd >t0=%ymm3,>t0=%ymm3,>t0=%ymm3
vxorpd %ymm3,%ymm3,%ymm3

# qhasm: clear t1
# asm 1: vxorpd >t1=reg256#13,>t1=reg256#13,>t1=reg256#13
# asm 2: vxorpd >t1=%ymm12,>t1=%ymm12,>t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 80] x4
# asm 1: vbroadcastsd 80(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 80(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 80(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 176] x4
# asm 1: vbroadcastsd 176(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 176(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 176(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 272] x4
# asm 1: vbroadcastsd 272(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 272(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 272(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 368] x4
# asm 1: vbroadcastsd 368(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 368(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 368(%rsi),%ymm14

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm14,<v0=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 464] x4
# asm 1: vbroadcastsd 464(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 464(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 464(%rsi),%ymm14

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm14,<v1=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 560] x4
# asm 1: vbroadcastsd 560(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 560(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 560(%rsi),%ymm14

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm14,<v2=%ymm14
vandpd %ymm5,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 656] x4
# asm 1: vbroadcastsd 656(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 656(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 656(%rsi),%ymm14

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm14,<v0=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 752] x4
# asm 1: vbroadcastsd 752(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 752(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 752(%rsi),%ymm14

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm14,<v1=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 848] x4
# asm 1: vbroadcastsd 848(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 848(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 848(%rsi),%ymm14

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm14,<v2=%ymm14
vandpd %ymm6,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 944] x4
# asm 1: vbroadcastsd 944(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 944(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 944(%rsi),%ymm14

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm14,<v0=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1040] x4
# asm 1: vbroadcastsd 1040(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1040(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1040(%rsi),%ymm14

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm14,<v1=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1136] x4
# asm 1: vbroadcastsd 1136(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1136(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1136(%rsi),%ymm14

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm14,<v2=%ymm14
vandpd %ymm7,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1232] x4
# asm 1: vbroadcastsd 1232(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1232(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1232(%rsi),%ymm14

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm14,<v0=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1328] x4
# asm 1: vbroadcastsd 1328(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1328(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1328(%rsi),%ymm14

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm14,<v1=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1424] x4
# asm 1: vbroadcastsd 1424(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1424(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1424(%rsi),%ymm14

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm14,<v2=%ymm14
vandpd %ymm8,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1520] x4
# asm 1: vbroadcastsd 1520(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1520(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1520(%rsi),%ymm14

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm14,<v0=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1616] x4
# asm 1: vbroadcastsd 1616(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1616(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1616(%rsi),%ymm14

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm14,<v1=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1712] x4
# asm 1: vbroadcastsd 1712(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 1712(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 1712(%rsi),%ymm14

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm14,<v2=%ymm14
vandpd %ymm9,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1808] x4
# asm 1: vbroadcastsd 1808(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 1808(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 1808(%rsi),%ymm14

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm14,<v0=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1904] x4
# asm 1: vbroadcastsd 1904(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 1904(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 1904(%rsi),%ymm14

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm14,<v1=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2000] x4
# asm 1: vbroadcastsd 2000(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2000(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2000(%rsi),%ymm14

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm14,<v2=%ymm14
vandpd %ymm10,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2096] x4
# asm 1: vbroadcastsd 2096(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 2096(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 2096(%rsi),%ymm14

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm14,<v0=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 2192] x4
# asm 1: vbroadcastsd 2192(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 2192(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 2192(%rsi),%ymm14

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm14,<v1=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2288] x4
# asm 1: vbroadcastsd 2288(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 2288(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 2288(%rsi),%ymm14

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm14,<v2=%ymm14
vandpd %ymm11,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 1088] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,1088(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,1088(<input_0=%rdi)
vmovapd   %ymm13,1088(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#4,<t1=reg256#13,>diff=reg256#14
# asm 2: vxorpd <t0=%ymm3,<t1=%ymm12,>diff=%ymm13
vxorpd %ymm3,%ymm12,%ymm13

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#14,<diff=reg256#14
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm13,<diff=%ymm13
vandpd %ymm1,%ymm13,%ymm13

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t0=reg256#4,<t0=reg256#4
# asm 2: vxorpd <diff=%ymm13,<t0=%ymm3,<t0=%ymm3
vxorpd %ymm13,%ymm3,%ymm3

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#14,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <diff=%ymm13,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm13,%ymm12,%ymm12

# qhasm: mem256[input_0 + 320] aligned= t0
# asm 1: vmovapd   <t0=reg256#4,320(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm3,320(<input_0=%rdi)
vmovapd   %ymm3,320(%rdi)

# qhasm: mem256[input_0 + 704] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,704(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,704(<input_0=%rdi)
vmovapd   %ymm12,704(%rdi)

# qhasm: clear t0
# asm 1: vxorpd >t0=reg256#4,>t0=reg256#4,>t0=reg256#4
# asm 2: vxorpd >t0=%ymm3,>t0=%ymm3,>t0=%ymm3
vxorpd %ymm3,%ymm3,%ymm3

# qhasm: clear t1
# asm 1: vxorpd >t1=reg256#13,>t1=reg256#13,>t1=reg256#13
# asm 2: vxorpd >t1=%ymm12,>t1=%ymm12,>t1=%ymm12
vxorpd %ymm12,%ymm12,%ymm12

# qhasm: clear t2
# asm 1: vxorpd >t2=reg256#14,>t2=reg256#14,>t2=reg256#14
# asm 2: vxorpd >t2=%ymm13,>t2=%ymm13,>t2=%ymm13
vxorpd %ymm13,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 88] x4
# asm 1: vbroadcastsd 88(<input_1=int64#2),>v0=reg256#15
# asm 2: vbroadcastsd 88(<input_1=%rsi),>v0=%ymm14
vbroadcastsd 88(%rsi),%ymm14

# qhasm: v0 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v0=reg256#15,<v0=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v0=%ymm14,<v0=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#15,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm14,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm14,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 184] x4
# asm 1: vbroadcastsd 184(<input_1=int64#2),>v1=reg256#15
# asm 2: vbroadcastsd 184(<input_1=%rsi),>v1=%ymm14
vbroadcastsd 184(%rsi),%ymm14

# qhasm: v1 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v1=reg256#15,<v1=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v1=%ymm14,<v1=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#15,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm14,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm14,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 280] x4
# asm 1: vbroadcastsd 280(<input_1=int64#2),>v2=reg256#15
# asm 2: vbroadcastsd 280(<input_1=%rsi),>v2=%ymm14
vbroadcastsd 280(%rsi),%ymm14

# qhasm: v2 &= mask1
# asm 1: vandpd <mask1=reg256#5,<v2=reg256#15,<v2=reg256#15
# asm 2: vandpd <mask1=%ymm4,<v2=%ymm14,<v2=%ymm14
vandpd %ymm4,%ymm14,%ymm14

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#15,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm14,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm14,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 376] x4
# asm 1: vbroadcastsd 376(<input_1=int64#2),>v0=reg256#5
# asm 2: vbroadcastsd 376(<input_1=%rsi),>v0=%ymm4
vbroadcastsd 376(%rsi),%ymm4

# qhasm: v0 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v0=reg256#5,<v0=reg256#5
# asm 2: vandpd <mask2=%ymm5,<v0=%ymm4,<v0=%ymm4
vandpd %ymm5,%ymm4,%ymm4

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#5,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm4,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm4,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 472] x4
# asm 1: vbroadcastsd 472(<input_1=int64#2),>v1=reg256#5
# asm 2: vbroadcastsd 472(<input_1=%rsi),>v1=%ymm4
vbroadcastsd 472(%rsi),%ymm4

# qhasm: v1 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v1=reg256#5,<v1=reg256#5
# asm 2: vandpd <mask2=%ymm5,<v1=%ymm4,<v1=%ymm4
vandpd %ymm5,%ymm4,%ymm4

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#5,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm4,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm4,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 568] x4
# asm 1: vbroadcastsd 568(<input_1=int64#2),>v2=reg256#5
# asm 2: vbroadcastsd 568(<input_1=%rsi),>v2=%ymm4
vbroadcastsd 568(%rsi),%ymm4

# qhasm: v2 &= mask2
# asm 1: vandpd <mask2=reg256#6,<v2=reg256#5,<v2=reg256#5
# asm 2: vandpd <mask2=%ymm5,<v2=%ymm4,<v2=%ymm4
vandpd %ymm5,%ymm4,%ymm4

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#5,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm4,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm4,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 664] x4
# asm 1: vbroadcastsd 664(<input_1=int64#2),>v0=reg256#5
# asm 2: vbroadcastsd 664(<input_1=%rsi),>v0=%ymm4
vbroadcastsd 664(%rsi),%ymm4

# qhasm: v0 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v0=reg256#5,<v0=reg256#5
# asm 2: vandpd <mask3=%ymm6,<v0=%ymm4,<v0=%ymm4
vandpd %ymm6,%ymm4,%ymm4

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#5,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm4,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm4,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 760] x4
# asm 1: vbroadcastsd 760(<input_1=int64#2),>v1=reg256#5
# asm 2: vbroadcastsd 760(<input_1=%rsi),>v1=%ymm4
vbroadcastsd 760(%rsi),%ymm4

# qhasm: v1 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v1=reg256#5,<v1=reg256#5
# asm 2: vandpd <mask3=%ymm6,<v1=%ymm4,<v1=%ymm4
vandpd %ymm6,%ymm4,%ymm4

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#5,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm4,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm4,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 856] x4
# asm 1: vbroadcastsd 856(<input_1=int64#2),>v2=reg256#5
# asm 2: vbroadcastsd 856(<input_1=%rsi),>v2=%ymm4
vbroadcastsd 856(%rsi),%ymm4

# qhasm: v2 &= mask3
# asm 1: vandpd <mask3=reg256#7,<v2=reg256#5,<v2=reg256#5
# asm 2: vandpd <mask3=%ymm6,<v2=%ymm4,<v2=%ymm4
vandpd %ymm6,%ymm4,%ymm4

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#5,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm4,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm4,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 952] x4
# asm 1: vbroadcastsd 952(<input_1=int64#2),>v0=reg256#5
# asm 2: vbroadcastsd 952(<input_1=%rsi),>v0=%ymm4
vbroadcastsd 952(%rsi),%ymm4

# qhasm: v0 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v0=reg256#5,<v0=reg256#5
# asm 2: vandpd <mask4=%ymm7,<v0=%ymm4,<v0=%ymm4
vandpd %ymm7,%ymm4,%ymm4

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#5,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm4,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm4,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1048] x4
# asm 1: vbroadcastsd 1048(<input_1=int64#2),>v1=reg256#5
# asm 2: vbroadcastsd 1048(<input_1=%rsi),>v1=%ymm4
vbroadcastsd 1048(%rsi),%ymm4

# qhasm: v1 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v1=reg256#5,<v1=reg256#5
# asm 2: vandpd <mask4=%ymm7,<v1=%ymm4,<v1=%ymm4
vandpd %ymm7,%ymm4,%ymm4

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#5,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm4,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm4,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1144] x4
# asm 1: vbroadcastsd 1144(<input_1=int64#2),>v2=reg256#5
# asm 2: vbroadcastsd 1144(<input_1=%rsi),>v2=%ymm4
vbroadcastsd 1144(%rsi),%ymm4

# qhasm: v2 &= mask4
# asm 1: vandpd <mask4=reg256#8,<v2=reg256#5,<v2=reg256#5
# asm 2: vandpd <mask4=%ymm7,<v2=%ymm4,<v2=%ymm4
vandpd %ymm7,%ymm4,%ymm4

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#5,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm4,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm4,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1240] x4
# asm 1: vbroadcastsd 1240(<input_1=int64#2),>v0=reg256#5
# asm 2: vbroadcastsd 1240(<input_1=%rsi),>v0=%ymm4
vbroadcastsd 1240(%rsi),%ymm4

# qhasm: v0 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v0=reg256#5,<v0=reg256#5
# asm 2: vandpd <mask5=%ymm8,<v0=%ymm4,<v0=%ymm4
vandpd %ymm8,%ymm4,%ymm4

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#5,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm4,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm4,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1336] x4
# asm 1: vbroadcastsd 1336(<input_1=int64#2),>v1=reg256#5
# asm 2: vbroadcastsd 1336(<input_1=%rsi),>v1=%ymm4
vbroadcastsd 1336(%rsi),%ymm4

# qhasm: v1 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v1=reg256#5,<v1=reg256#5
# asm 2: vandpd <mask5=%ymm8,<v1=%ymm4,<v1=%ymm4
vandpd %ymm8,%ymm4,%ymm4

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#5,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm4,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm4,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1432] x4
# asm 1: vbroadcastsd 1432(<input_1=int64#2),>v2=reg256#5
# asm 2: vbroadcastsd 1432(<input_1=%rsi),>v2=%ymm4
vbroadcastsd 1432(%rsi),%ymm4

# qhasm: v2 &= mask5
# asm 1: vandpd <mask5=reg256#9,<v2=reg256#5,<v2=reg256#5
# asm 2: vandpd <mask5=%ymm8,<v2=%ymm4,<v2=%ymm4
vandpd %ymm8,%ymm4,%ymm4

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#5,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm4,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm4,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1528] x4
# asm 1: vbroadcastsd 1528(<input_1=int64#2),>v0=reg256#5
# asm 2: vbroadcastsd 1528(<input_1=%rsi),>v0=%ymm4
vbroadcastsd 1528(%rsi),%ymm4

# qhasm: v0 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v0=reg256#5,<v0=reg256#5
# asm 2: vandpd <mask6=%ymm9,<v0=%ymm4,<v0=%ymm4
vandpd %ymm9,%ymm4,%ymm4

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#5,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm4,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm4,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1624] x4
# asm 1: vbroadcastsd 1624(<input_1=int64#2),>v1=reg256#5
# asm 2: vbroadcastsd 1624(<input_1=%rsi),>v1=%ymm4
vbroadcastsd 1624(%rsi),%ymm4

# qhasm: v1 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v1=reg256#5,<v1=reg256#5
# asm 2: vandpd <mask6=%ymm9,<v1=%ymm4,<v1=%ymm4
vandpd %ymm9,%ymm4,%ymm4

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#5,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm4,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm4,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 1720] x4
# asm 1: vbroadcastsd 1720(<input_1=int64#2),>v2=reg256#5
# asm 2: vbroadcastsd 1720(<input_1=%rsi),>v2=%ymm4
vbroadcastsd 1720(%rsi),%ymm4

# qhasm: v2 &= mask6
# asm 1: vandpd <mask6=reg256#10,<v2=reg256#5,<v2=reg256#5
# asm 2: vandpd <mask6=%ymm9,<v2=%ymm4,<v2=%ymm4
vandpd %ymm9,%ymm4,%ymm4

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#5,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm4,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm4,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 1816] x4
# asm 1: vbroadcastsd 1816(<input_1=int64#2),>v0=reg256#5
# asm 2: vbroadcastsd 1816(<input_1=%rsi),>v0=%ymm4
vbroadcastsd 1816(%rsi),%ymm4

# qhasm: v0 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v0=reg256#5,<v0=reg256#5
# asm 2: vandpd <mask7=%ymm10,<v0=%ymm4,<v0=%ymm4
vandpd %ymm10,%ymm4,%ymm4

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#5,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm4,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm4,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 1912] x4
# asm 1: vbroadcastsd 1912(<input_1=int64#2),>v1=reg256#5
# asm 2: vbroadcastsd 1912(<input_1=%rsi),>v1=%ymm4
vbroadcastsd 1912(%rsi),%ymm4

# qhasm: v1 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v1=reg256#5,<v1=reg256#5
# asm 2: vandpd <mask7=%ymm10,<v1=%ymm4,<v1=%ymm4
vandpd %ymm10,%ymm4,%ymm4

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#5,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm4,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm4,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2008] x4
# asm 1: vbroadcastsd 2008(<input_1=int64#2),>v2=reg256#5
# asm 2: vbroadcastsd 2008(<input_1=%rsi),>v2=%ymm4
vbroadcastsd 2008(%rsi),%ymm4

# qhasm: v2 &= mask7
# asm 1: vandpd <mask7=reg256#11,<v2=reg256#5,<v2=reg256#5
# asm 2: vandpd <mask7=%ymm10,<v2=%ymm4,<v2=%ymm4
vandpd %ymm10,%ymm4,%ymm4

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#5,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm4,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm4,%ymm13,%ymm13

# qhasm: v0 =  mem64[input_1 + 2104] x4
# asm 1: vbroadcastsd 2104(<input_1=int64#2),>v0=reg256#5
# asm 2: vbroadcastsd 2104(<input_1=%rsi),>v0=%ymm4
vbroadcastsd 2104(%rsi),%ymm4

# qhasm: v0 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v0=reg256#5,<v0=reg256#5
# asm 2: vandpd <mask8=%ymm11,<v0=%ymm4,<v0=%ymm4
vandpd %ymm11,%ymm4,%ymm4

# qhasm: t0 |= v0
# asm 1: vorpd  <v0=reg256#5,<t0=reg256#4,<t0=reg256#4
# asm 2: vorpd  <v0=%ymm4,<t0=%ymm3,<t0=%ymm3
vorpd  %ymm4,%ymm3,%ymm3

# qhasm: v1 =  mem64[input_1 + 2200] x4
# asm 1: vbroadcastsd 2200(<input_1=int64#2),>v1=reg256#5
# asm 2: vbroadcastsd 2200(<input_1=%rsi),>v1=%ymm4
vbroadcastsd 2200(%rsi),%ymm4

# qhasm: v1 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v1=reg256#5,<v1=reg256#5
# asm 2: vandpd <mask8=%ymm11,<v1=%ymm4,<v1=%ymm4
vandpd %ymm11,%ymm4,%ymm4

# qhasm: t1 |= v1
# asm 1: vorpd  <v1=reg256#5,<t1=reg256#13,<t1=reg256#13
# asm 2: vorpd  <v1=%ymm4,<t1=%ymm12,<t1=%ymm12
vorpd  %ymm4,%ymm12,%ymm12

# qhasm: v2 =  mem64[input_1 + 2296] x4
# asm 1: vbroadcastsd 2296(<input_1=int64#2),>v2=reg256#5
# asm 2: vbroadcastsd 2296(<input_1=%rsi),>v2=%ymm4
vbroadcastsd 2296(%rsi),%ymm4

# qhasm: v2 &= mask8
# asm 1: vandpd <mask8=reg256#12,<v2=reg256#5,<v2=reg256#5
# asm 2: vandpd <mask8=%ymm11,<v2=%ymm4,<v2=%ymm4
vandpd %ymm11,%ymm4,%ymm4

# qhasm: t2 |= v2
# asm 1: vorpd  <v2=reg256#5,<t2=reg256#14,<t2=reg256#14
# asm 2: vorpd  <v2=%ymm4,<t2=%ymm13,<t2=%ymm13
vorpd  %ymm4,%ymm13,%ymm13

# qhasm: t2 ^= flip
# asm 1: vxorpd <flip=reg256#1,<t2=reg256#14,<t2=reg256#14
# asm 2: vxorpd <flip=%ymm0,<t2=%ymm13,<t2=%ymm13
vxorpd %ymm0,%ymm13,%ymm13

# qhasm: mem256[input_0 + 1120] aligned= t2
# asm 1: vmovapd   <t2=reg256#14,1120(<input_0=int64#1)
# asm 2: vmovapd   <t2=%ymm13,1120(<input_0=%rdi)
vmovapd   %ymm13,1120(%rdi)

# qhasm: diff = t0 ^ t1
# asm 1: vxorpd <t0=reg256#4,<t1=reg256#13,>diff=reg256#1
# asm 2: vxorpd <t0=%ymm3,<t1=%ymm12,>diff=%ymm0
vxorpd %ymm3,%ymm12,%ymm0

# qhasm: diff &= neg_mask
# asm 1: vandpd <neg_mask=reg256#2,<diff=reg256#1,<diff=reg256#1
# asm 2: vandpd <neg_mask=%ymm1,<diff=%ymm0,<diff=%ymm0
vandpd %ymm1,%ymm0,%ymm0

# qhasm: t0 ^= diff
# asm 1: vxorpd <diff=reg256#1,<t0=reg256#4,<t0=reg256#4
# asm 2: vxorpd <diff=%ymm0,<t0=%ymm3,<t0=%ymm3
vxorpd %ymm0,%ymm3,%ymm3

# qhasm: t1 ^= diff
# asm 1: vxorpd <diff=reg256#1,<t1=reg256#13,<t1=reg256#13
# asm 2: vxorpd <diff=%ymm0,<t1=%ymm12,<t1=%ymm12
vxorpd %ymm0,%ymm12,%ymm12

# qhasm: mem256[input_0 + 352] aligned= t0
# asm 1: vmovapd   <t0=reg256#4,352(<input_0=int64#1)
# asm 2: vmovapd   <t0=%ymm3,352(<input_0=%rdi)
vmovapd   %ymm3,352(%rdi)

# qhasm: mem256[input_0 + 736] aligned= t1
# asm 1: vmovapd   <t1=reg256#13,736(<input_0=int64#1)
# asm 2: vmovapd   <t1=%ymm12,736(<input_0=%rdi)
vmovapd   %ymm12,736(%rdi)

# qhasm: return
add %r11,%rsp
ret
