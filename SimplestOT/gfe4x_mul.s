
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

# qhasm: reg256 mul_y0

# qhasm: reg256 mul_x0

# qhasm: reg256 mul_x1

# qhasm: reg256 mul_x2

# qhasm: reg256 mul_x3

# qhasm: reg256 mul_x4

# qhasm: reg256 mul_x5

# qhasm: reg256 mul_x6

# qhasm: reg256 mul_x7

# qhasm: reg256 mul_x8

# qhasm: reg256 mul_x9

# qhasm: reg256 mul_x10

# qhasm: reg256 mul_x11

# qhasm: reg256 mul_nineteen

# qhasm: reg256 mul_t

# qhasm: reg256 mul_c

# qhasm: reg256 r0

# qhasm: reg256 r1

# qhasm: reg256 r2

# qhasm: reg256 r3

# qhasm: reg256 r4

# qhasm: reg256 r5

# qhasm: reg256 r6

# qhasm: reg256 r7

# qhasm: reg256 r8

# qhasm: reg256 r9

# qhasm: reg256 r10

# qhasm: reg256 r11

# qhasm: enter gfe4x_mul
.p2align 5
.global _gfe4x_mul
.global gfe4x_mul
_gfe4x_mul:
gfe4x_mul:
mov %rsp,%r11
and $31,%r11
add $0,%r11
sub %r11,%rsp

# qhasm:   mul_nineteen aligned= mem256[scale19]
# asm 1: vmovapd scale19,>mul_nineteen=reg256#1
# asm 2: vmovapd scale19,>mul_nineteen=%ymm0
vmovapd scale19,%ymm0

# qhasm:   mul_x0 aligned= mem256[input_1 + 0]
# asm 1: vmovapd   0(<input_1=int64#2),>mul_x0=reg256#2
# asm 2: vmovapd   0(<input_1=%rsi),>mul_x0=%ymm1
vmovapd   0(%rsi),%ymm1

# qhasm:   mul_y0 aligned= mem256[input_2 + 0]
# asm 1: vmovapd   0(<input_2=int64#3),>mul_y0=reg256#3
# asm 2: vmovapd   0(<input_2=%rdx),>mul_y0=%ymm2
vmovapd   0(%rdx),%ymm2

# qhasm:   4x r0 = approx mul_x0 * mul_y0
# asm 1: vmulpd <mul_x0=reg256#2,<mul_y0=reg256#3,>r0=reg256#4
# asm 2: vmulpd <mul_x0=%ymm1,<mul_y0=%ymm2,>r0=%ymm3
vmulpd %ymm1,%ymm2,%ymm3

# qhasm:   4x r1 = approx mul_x0 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x0=reg256#2,>r1=reg256#5
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x0=%ymm1,>r1=%ymm4
vmulpd 32(%rdx),%ymm1,%ymm4

# qhasm:   4x r2 = approx mul_x0 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x0=reg256#2,>r2=reg256#6
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x0=%ymm1,>r2=%ymm5
vmulpd 64(%rdx),%ymm1,%ymm5

# qhasm:   4x r3 = approx mul_x0 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x0=reg256#2,>r3=reg256#7
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x0=%ymm1,>r3=%ymm6
vmulpd 96(%rdx),%ymm1,%ymm6

# qhasm:   4x r4 = approx mul_x0 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x0=reg256#2,>r4=reg256#8
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x0=%ymm1,>r4=%ymm7
vmulpd 128(%rdx),%ymm1,%ymm7

# qhasm:   4x r5 = approx mul_x0 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x0=reg256#2,>r5=reg256#9
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x0=%ymm1,>r5=%ymm8
vmulpd 160(%rdx),%ymm1,%ymm8

# qhasm:   4x r6 = approx mul_x0 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x0=reg256#2,>r6=reg256#10
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x0=%ymm1,>r6=%ymm9
vmulpd 192(%rdx),%ymm1,%ymm9

# qhasm:   4x r7 = approx mul_x0 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x0=reg256#2,>r7=reg256#11
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x0=%ymm1,>r7=%ymm10
vmulpd 224(%rdx),%ymm1,%ymm10

# qhasm:   4x r8 = approx mul_x0 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x0=reg256#2,>r8=reg256#12
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x0=%ymm1,>r8=%ymm11
vmulpd 256(%rdx),%ymm1,%ymm11

# qhasm:   4x r9 = approx mul_x0 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x0=reg256#2,>r9=reg256#13
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x0=%ymm1,>r9=%ymm12
vmulpd 288(%rdx),%ymm1,%ymm12

# qhasm:   4x r10 = approx mul_x0 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x0=reg256#2,>r10=reg256#14
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x0=%ymm1,>r10=%ymm13
vmulpd 320(%rdx),%ymm1,%ymm13

# qhasm:   4x r11 = approx mul_x0 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x0=reg256#2,>r11=reg256#2
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x0=%ymm1,>r11=%ymm1
vmulpd 352(%rdx),%ymm1,%ymm1

# qhasm:   mul_x1 aligned= mem256[input_1 + 32]
# asm 1: vmovapd   32(<input_1=int64#2),>mul_x1=reg256#15
# asm 2: vmovapd   32(<input_1=%rsi),>mul_x1=%ymm14
vmovapd   32(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mul_y0
# asm 1: vmulpd <mul_x1=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x1=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x1 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x1=reg256#15,>mul_x1=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x1=%ymm14,>mul_x1=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdx),%ymm14,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   mul_x2 aligned= mem256[input_1 + 64]
# asm 1: vmovapd   64(<input_1=int64#2),>mul_x2=reg256#15
# asm 2: vmovapd   64(<input_1=%rsi),>mul_x2=%ymm14
vmovapd   64(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mul_y0
# asm 1: vmulpd <mul_x2=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x2=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x2 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x2=reg256#15,>mul_x2=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x2=%ymm14,>mul_x2=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdx),%ymm14,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   mul_x3 aligned= mem256[input_1 + 96]
# asm 1: vmovapd   96(<input_1=int64#2),>mul_x3=reg256#15
# asm 2: vmovapd   96(<input_1=%rsi),>mul_x3=%ymm14
vmovapd   96(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mul_y0
# asm 1: vmulpd <mul_x3=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x3=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x3 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x3=reg256#15,>mul_x3=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x3=%ymm14,>mul_x3=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdx),%ymm14,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   mul_x4 aligned= mem256[input_1 + 128]
# asm 1: vmovapd   128(<input_1=int64#2),>mul_x4=reg256#15
# asm 2: vmovapd   128(<input_1=%rsi),>mul_x4=%ymm14
vmovapd   128(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mul_y0
# asm 1: vmulpd <mul_x4=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x4=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x4 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x4=reg256#15,>mul_x4=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x4=%ymm14,>mul_x4=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdx),%ymm14,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   mul_x5 aligned= mem256[input_1 + 160]
# asm 1: vmovapd   160(<input_1=int64#2),>mul_x5=reg256#15
# asm 2: vmovapd   160(<input_1=%rsi),>mul_x5=%ymm14
vmovapd   160(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mul_y0
# asm 1: vmulpd <mul_x5=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x5=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x5 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x5=reg256#15,>mul_x5=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x5=%ymm14,>mul_x5=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdx),%ymm14,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   mul_x6 aligned= mem256[input_1 + 192]
# asm 1: vmovapd   192(<input_1=int64#2),>mul_x6=reg256#15
# asm 2: vmovapd   192(<input_1=%rsi),>mul_x6=%ymm14
vmovapd   192(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mul_y0
# asm 1: vmulpd <mul_x6=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x6=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x6 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x6=reg256#15,>mul_x6=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x6=%ymm14,>mul_x6=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdx),%ymm14,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   mul_x7 aligned= mem256[input_1 + 224]
# asm 1: vmovapd   224(<input_1=int64#2),>mul_x7=reg256#15
# asm 2: vmovapd   224(<input_1=%rsi),>mul_x7=%ymm14
vmovapd   224(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mul_y0
# asm 1: vmulpd <mul_x7=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x7=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x7 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x7=reg256#15,>mul_x7=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x7=%ymm14,>mul_x7=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdx),%ymm14,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   mul_x8 aligned= mem256[input_1 + 256]
# asm 1: vmovapd   256(<input_1=int64#2),>mul_x8=reg256#15
# asm 2: vmovapd   256(<input_1=%rsi),>mul_x8=%ymm14
vmovapd   256(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mul_y0
# asm 1: vmulpd <mul_x8=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x8=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x8 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x8=reg256#15,>mul_x8=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x8=%ymm14,>mul_x8=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdx),%ymm14,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   mul_x9 aligned= mem256[input_1 + 288]
# asm 1: vmovapd   288(<input_1=int64#2),>mul_x9=reg256#15
# asm 2: vmovapd   288(<input_1=%rsi),>mul_x9=%ymm14
vmovapd   288(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mul_y0
# asm 1: vmulpd <mul_x9=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x9=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x9 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x9=reg256#15,>mul_x9=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x9=%ymm14,>mul_x9=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdx),%ymm14,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   mul_x10 aligned= mem256[input_1 + 320]
# asm 1: vmovapd   320(<input_1=int64#2),>mul_x10=reg256#15
# asm 2: vmovapd   320(<input_1=%rsi),>mul_x10=%ymm14
vmovapd   320(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mul_y0
# asm 1: vmulpd <mul_x10=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x10=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x10 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x10=reg256#15,>mul_x10=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x10=%ymm14,>mul_x10=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdx),%ymm14,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   mul_x11 aligned= mem256[input_1 + 352]
# asm 1: vmovapd   352(<input_1=int64#2),>mul_x11=reg256#15
# asm 2: vmovapd   352(<input_1=%rsi),>mul_x11=%ymm14
vmovapd   352(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x11 * mul_y0
# asm 1: vmulpd <mul_x11=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#3
# asm 2: vmulpd <mul_x11=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm2
vmulpd %ymm14,%ymm2,%ymm2

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#3,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm2,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm2,%ymm1,%ymm1

# qhasm:   4x mul_x11 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x11=reg256#15,>mul_x11=reg256#3
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x11=%ymm14,>mul_x11=%ymm2
vmulpd %ymm0,%ymm14,%ymm2

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 32]
# asm 1: vmulpd 32(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 32(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 32(%rdx),%ymm2,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 64]
# asm 1: vmulpd 64(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 64(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 64(%rdx),%ymm2,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 96]
# asm 1: vmulpd 96(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 96(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 96(%rdx),%ymm2,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 128]
# asm 1: vmulpd 128(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 128(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 128(%rdx),%ymm2,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 160]
# asm 1: vmulpd 160(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 160(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 160(%rdx),%ymm2,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 192]
# asm 1: vmulpd 192(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 192(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 192(%rdx),%ymm2,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 224]
# asm 1: vmulpd 224(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 224(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 224(%rdx),%ymm2,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 256]
# asm 1: vmulpd 256(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 256(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 256(%rdx),%ymm2,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 288]
# asm 1: vmulpd 288(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 288(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 288(%rdx),%ymm2,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 320]
# asm 1: vmulpd 320(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 320(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 320(%rdx),%ymm2,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 352]
# asm 1: vmulpd 352(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#3
# asm 2: vmulpd 352(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm2
vmulpd 352(%rdx),%ymm2,%ymm2

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#3,<r10=reg256#14,>r10=reg256#3
# asm 2: vaddpd <mul_t=%ymm2,<r10=%ymm13,>r10=%ymm2
vaddpd %ymm2,%ymm13,%ymm2

# qhasm:   mul_c aligned= mem256[alpha22]
# asm 1: vmovapd alpha22,>mul_c=reg256#14
# asm 2: vmovapd alpha22,>mul_c=%ymm13
vmovapd alpha22,%ymm13

# qhasm:   4x mul_t = approx r0 +mul_c
# asm 1: vaddpd <r0=reg256#4,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r0=%ymm3,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm3,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r0 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r0=reg256#4,>r0=reg256#4
# asm 2: vsubpd <mul_t=%ymm13,<r0=%ymm3,>r0=%ymm3
vsubpd %ymm13,%ymm3,%ymm3

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#14,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm13,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm13,%ymm4,%ymm4

# qhasm:   mul_c aligned= mem256[alpha107]
# asm 1: vmovapd alpha107,>mul_c=reg256#14
# asm 2: vmovapd alpha107,>mul_c=%ymm13
vmovapd alpha107,%ymm13

# qhasm:   4x mul_t = approx r4 +mul_c
# asm 1: vaddpd <r4=reg256#8,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r4=%ymm7,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm7,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r4 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r4=reg256#8,>r4=reg256#8
# asm 2: vsubpd <mul_t=%ymm13,<r4=%ymm7,>r4=%ymm7
vsubpd %ymm13,%ymm7,%ymm7

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#14,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm13,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm13,%ymm8,%ymm8

# qhasm:   mul_c aligned= mem256[alpha192]
# asm 1: vmovapd alpha192,>mul_c=reg256#14
# asm 2: vmovapd alpha192,>mul_c=%ymm13
vmovapd alpha192,%ymm13

# qhasm:   4x mul_t = approx r8 +mul_c
# asm 1: vaddpd <r8=reg256#12,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r8=%ymm11,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm11,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r8 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r8=reg256#12,>r8=reg256#12
# asm 2: vsubpd <mul_t=%ymm13,<r8=%ymm11,>r8=%ymm11
vsubpd %ymm13,%ymm11,%ymm11

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#14,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm13,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm13,%ymm12,%ymm12

# qhasm:   mul_c aligned= mem256[alpha43]
# asm 1: vmovapd alpha43,>mul_c=reg256#14
# asm 2: vmovapd alpha43,>mul_c=%ymm13
vmovapd alpha43,%ymm13

# qhasm:   4x mul_t = approx r1 +mul_c
# asm 1: vaddpd <r1=reg256#5,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r1=%ymm4,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm4,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r1 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r1=reg256#5,>r1=reg256#5
# asm 2: vsubpd <mul_t=%ymm13,<r1=%ymm4,>r1=%ymm4
vsubpd %ymm13,%ymm4,%ymm4

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#14,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm13,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm13,%ymm5,%ymm5

# qhasm:   mul_c aligned= mem256[alpha128]
# asm 1: vmovapd alpha128,>mul_c=reg256#14
# asm 2: vmovapd alpha128,>mul_c=%ymm13
vmovapd alpha128,%ymm13

# qhasm:   4x mul_t = approx r5 +mul_c
# asm 1: vaddpd <r5=reg256#9,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r5=%ymm8,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm8,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r5 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r5=reg256#9,>r5=reg256#9
# asm 2: vsubpd <mul_t=%ymm13,<r5=%ymm8,>r5=%ymm8
vsubpd %ymm13,%ymm8,%ymm8

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#14,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm13,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm13,%ymm9,%ymm9

# qhasm:   mul_c aligned= mem256[alpha213]
# asm 1: vmovapd alpha213,>mul_c=reg256#14
# asm 2: vmovapd alpha213,>mul_c=%ymm13
vmovapd alpha213,%ymm13

# qhasm:   4x mul_t = approx r9 +mul_c
# asm 1: vaddpd <r9=reg256#13,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r9=%ymm12,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm12,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r9 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r9=reg256#13,>r9=reg256#13
# asm 2: vsubpd <mul_t=%ymm13,<r9=%ymm12,>r9=%ymm12
vsubpd %ymm13,%ymm12,%ymm12

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#14,<r10=reg256#3,>r10=reg256#3
# asm 2: vaddpd <mul_t=%ymm13,<r10=%ymm2,>r10=%ymm2
vaddpd %ymm13,%ymm2,%ymm2

# qhasm:   mul_c aligned= mem256[alpha64]
# asm 1: vmovapd alpha64,>mul_c=reg256#14
# asm 2: vmovapd alpha64,>mul_c=%ymm13
vmovapd alpha64,%ymm13

# qhasm:   4x mul_t = approx r2 +mul_c
# asm 1: vaddpd <r2=reg256#6,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r2=%ymm5,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm5,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r2 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r2=reg256#6,>r2=reg256#6
# asm 2: vsubpd <mul_t=%ymm13,<r2=%ymm5,>r2=%ymm5
vsubpd %ymm13,%ymm5,%ymm5

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#14,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm13,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm13,%ymm6,%ymm6

# qhasm:   mul_c aligned= mem256[alpha149]
# asm 1: vmovapd alpha149,>mul_c=reg256#14
# asm 2: vmovapd alpha149,>mul_c=%ymm13
vmovapd alpha149,%ymm13

# qhasm:   4x mul_t = approx r6 +mul_c
# asm 1: vaddpd <r6=reg256#10,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r6=%ymm9,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm9,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r6 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r6=reg256#10,>r6=reg256#10
# asm 2: vsubpd <mul_t=%ymm13,<r6=%ymm9,>r6=%ymm9
vsubpd %ymm13,%ymm9,%ymm9

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#14,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm13,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm13,%ymm10,%ymm10

# qhasm:   mul_c aligned= mem256[alpha234]
# asm 1: vmovapd alpha234,>mul_c=reg256#14
# asm 2: vmovapd alpha234,>mul_c=%ymm13
vmovapd alpha234,%ymm13

# qhasm:   4x mul_t = approx r10 +mul_c
# asm 1: vaddpd <r10=reg256#3,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r10=%ymm2,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm2,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r10 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r10=reg256#3,>r10=reg256#3
# asm 2: vsubpd <mul_t=%ymm13,<r10=%ymm2,>r10=%ymm2
vsubpd %ymm13,%ymm2,%ymm2

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#14,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm13,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm13,%ymm1,%ymm1

# qhasm:   mul_c aligned= mem256[alpha85]
# asm 1: vmovapd alpha85,>mul_c=reg256#14
# asm 2: vmovapd alpha85,>mul_c=%ymm13
vmovapd alpha85,%ymm13

# qhasm:   4x mul_t = approx r3 +mul_c
# asm 1: vaddpd <r3=reg256#7,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r3=%ymm6,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm6,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r3 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r3=reg256#7,>r3=reg256#7
# asm 2: vsubpd <mul_t=%ymm13,<r3=%ymm6,>r3=%ymm6
vsubpd %ymm13,%ymm6,%ymm6

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#14,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm13,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm13,%ymm7,%ymm7

# qhasm:   mul_c aligned= mem256[alpha170]
# asm 1: vmovapd alpha170,>mul_c=reg256#14
# asm 2: vmovapd alpha170,>mul_c=%ymm13
vmovapd alpha170,%ymm13

# qhasm:   4x mul_t = approx r7 +mul_c
# asm 1: vaddpd <r7=reg256#11,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r7=%ymm10,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm10,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r7 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r7=reg256#11,>r7=reg256#11
# asm 2: vsubpd <mul_t=%ymm13,<r7=%ymm10,>r7=%ymm10
vsubpd %ymm13,%ymm10,%ymm10

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#14,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm13,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm13,%ymm11,%ymm11

# qhasm:   mul_c aligned= mem256[alpha255]
# asm 1: vmovapd alpha255,>mul_c=reg256#14
# asm 2: vmovapd alpha255,>mul_c=%ymm13
vmovapd alpha255,%ymm13

# qhasm:   4x mul_t = approx r11 +mul_c
# asm 1: vaddpd <r11=reg256#2,<mul_c=reg256#14,>mul_t=reg256#15
# asm 2: vaddpd <r11=%ymm1,<mul_c=%ymm13,>mul_t=%ymm14
vaddpd %ymm1,%ymm13,%ymm14

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#14,<mul_t=reg256#15,>mul_t=reg256#14
# asm 2: vsubpd <mul_c=%ymm13,<mul_t=%ymm14,>mul_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r11 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#14,<r11=reg256#2,>r11=reg256#2
# asm 2: vsubpd <mul_t=%ymm13,<r11=%ymm1,>r11=%ymm1
vsubpd %ymm13,%ymm1,%ymm1

# qhasm:   4x mul_t approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_t=reg256#14,>mul_t=reg256#1
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_t=%ymm13,>mul_t=%ymm0
vmulpd %ymm0,%ymm13,%ymm0

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#1,<r0=reg256#4,>r0=reg256#1
# asm 2: vaddpd <mul_t=%ymm0,<r0=%ymm3,>r0=%ymm0
vaddpd %ymm0,%ymm3,%ymm0

# qhasm:   mul_c aligned= mem256[alpha22]
# asm 1: vmovapd alpha22,>mul_c=reg256#4
# asm 2: vmovapd alpha22,>mul_c=%ymm3
vmovapd alpha22,%ymm3

# qhasm:   4x mul_t = approx r0 +mul_c
# asm 1: vaddpd <r0=reg256#1,<mul_c=reg256#4,>mul_t=reg256#14
# asm 2: vaddpd <r0=%ymm0,<mul_c=%ymm3,>mul_t=%ymm13
vaddpd %ymm0,%ymm3,%ymm13

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#4,<mul_t=reg256#14,>mul_t=reg256#4
# asm 2: vsubpd <mul_c=%ymm3,<mul_t=%ymm13,>mul_t=%ymm3
vsubpd %ymm3,%ymm13,%ymm3

# qhasm:   4x r0 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#4,<r0=reg256#1,>r0=reg256#1
# asm 2: vsubpd <mul_t=%ymm3,<r0=%ymm0,>r0=%ymm0
vsubpd %ymm3,%ymm0,%ymm0

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#4,<r1=reg256#5,>r1=reg256#4
# asm 2: vaddpd <mul_t=%ymm3,<r1=%ymm4,>r1=%ymm3
vaddpd %ymm3,%ymm4,%ymm3

# qhasm:   mul_c aligned= mem256[alpha107]
# asm 1: vmovapd alpha107,>mul_c=reg256#5
# asm 2: vmovapd alpha107,>mul_c=%ymm4
vmovapd alpha107,%ymm4

# qhasm:   4x mul_t = approx r4 +mul_c
# asm 1: vaddpd <r4=reg256#8,<mul_c=reg256#5,>mul_t=reg256#14
# asm 2: vaddpd <r4=%ymm7,<mul_c=%ymm4,>mul_t=%ymm13
vaddpd %ymm7,%ymm4,%ymm13

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#5,<mul_t=reg256#14,>mul_t=reg256#5
# asm 2: vsubpd <mul_c=%ymm4,<mul_t=%ymm13,>mul_t=%ymm4
vsubpd %ymm4,%ymm13,%ymm4

# qhasm:   4x r4 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#5,<r4=reg256#8,>r4=reg256#8
# asm 2: vsubpd <mul_t=%ymm4,<r4=%ymm7,>r4=%ymm7
vsubpd %ymm4,%ymm7,%ymm7

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#5,<r5=reg256#9,>r5=reg256#5
# asm 2: vaddpd <mul_t=%ymm4,<r5=%ymm8,>r5=%ymm4
vaddpd %ymm4,%ymm8,%ymm4

# qhasm:   mul_c aligned= mem256[alpha192]
# asm 1: vmovapd alpha192,>mul_c=reg256#9
# asm 2: vmovapd alpha192,>mul_c=%ymm8
vmovapd alpha192,%ymm8

# qhasm:   4x mul_t = approx r8 +mul_c
# asm 1: vaddpd <r8=reg256#12,<mul_c=reg256#9,>mul_t=reg256#14
# asm 2: vaddpd <r8=%ymm11,<mul_c=%ymm8,>mul_t=%ymm13
vaddpd %ymm11,%ymm8,%ymm13

# qhasm:   4x mul_t approx-=mul_c
# asm 1: vsubpd <mul_c=reg256#9,<mul_t=reg256#14,>mul_t=reg256#9
# asm 2: vsubpd <mul_c=%ymm8,<mul_t=%ymm13,>mul_t=%ymm8
vsubpd %ymm8,%ymm13,%ymm8

# qhasm:   4x r8 approx-= mul_t
# asm 1: vsubpd <mul_t=reg256#9,<r8=reg256#12,>r8=reg256#12
# asm 2: vsubpd <mul_t=%ymm8,<r8=%ymm11,>r8=%ymm11
vsubpd %ymm8,%ymm11,%ymm11

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#9,<r9=reg256#13,>r9=reg256#9
# asm 2: vaddpd <mul_t=%ymm8,<r9=%ymm12,>r9=%ymm8
vaddpd %ymm8,%ymm12,%ymm8

# qhasm: mem256[input_0 + 0] aligned= r0
# asm 1: vmovapd   <r0=reg256#1,0(<input_0=int64#1)
# asm 2: vmovapd   <r0=%ymm0,0(<input_0=%rdi)
vmovapd   %ymm0,0(%rdi)

# qhasm: mem256[input_0 + 32] aligned= r1
# asm 1: vmovapd   <r1=reg256#4,32(<input_0=int64#1)
# asm 2: vmovapd   <r1=%ymm3,32(<input_0=%rdi)
vmovapd   %ymm3,32(%rdi)

# qhasm: mem256[input_0 + 64] aligned= r2
# asm 1: vmovapd   <r2=reg256#6,64(<input_0=int64#1)
# asm 2: vmovapd   <r2=%ymm5,64(<input_0=%rdi)
vmovapd   %ymm5,64(%rdi)

# qhasm: mem256[input_0 + 96] aligned= r3
# asm 1: vmovapd   <r3=reg256#7,96(<input_0=int64#1)
# asm 2: vmovapd   <r3=%ymm6,96(<input_0=%rdi)
vmovapd   %ymm6,96(%rdi)

# qhasm: mem256[input_0 + 128] aligned= r4
# asm 1: vmovapd   <r4=reg256#8,128(<input_0=int64#1)
# asm 2: vmovapd   <r4=%ymm7,128(<input_0=%rdi)
vmovapd   %ymm7,128(%rdi)

# qhasm: mem256[input_0 + 160] aligned= r5
# asm 1: vmovapd   <r5=reg256#5,160(<input_0=int64#1)
# asm 2: vmovapd   <r5=%ymm4,160(<input_0=%rdi)
vmovapd   %ymm4,160(%rdi)

# qhasm: mem256[input_0 + 192] aligned= r6
# asm 1: vmovapd   <r6=reg256#10,192(<input_0=int64#1)
# asm 2: vmovapd   <r6=%ymm9,192(<input_0=%rdi)
vmovapd   %ymm9,192(%rdi)

# qhasm: mem256[input_0 + 224] aligned= r7
# asm 1: vmovapd   <r7=reg256#11,224(<input_0=int64#1)
# asm 2: vmovapd   <r7=%ymm10,224(<input_0=%rdi)
vmovapd   %ymm10,224(%rdi)

# qhasm: mem256[input_0 + 256] aligned= r8
# asm 1: vmovapd   <r8=reg256#12,256(<input_0=int64#1)
# asm 2: vmovapd   <r8=%ymm11,256(<input_0=%rdi)
vmovapd   %ymm11,256(%rdi)

# qhasm: mem256[input_0 + 288] aligned= r9
# asm 1: vmovapd   <r9=reg256#9,288(<input_0=int64#1)
# asm 2: vmovapd   <r9=%ymm8,288(<input_0=%rdi)
vmovapd   %ymm8,288(%rdi)

# qhasm: mem256[input_0 + 320] aligned= r10
# asm 1: vmovapd   <r10=reg256#3,320(<input_0=int64#1)
# asm 2: vmovapd   <r10=%ymm2,320(<input_0=%rdi)
vmovapd   %ymm2,320(%rdi)

# qhasm: mem256[input_0 + 352] aligned= r11
# asm 1: vmovapd   <r11=reg256#2,352(<input_0=int64#1)
# asm 2: vmovapd   <r11=%ymm1,352(<input_0=%rdi)
vmovapd   %ymm1,352(%rdi)

# qhasm: return
add %r11,%rsp
ret
