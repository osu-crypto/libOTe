
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

# qhasm: reg256 square_x0

# qhasm: reg256 square_x1

# qhasm: reg256 square_x2

# qhasm: reg256 square_x3

# qhasm: reg256 square_x4

# qhasm: reg256 square_x5

# qhasm: reg256 square_x6

# qhasm: reg256 square_x7

# qhasm: reg256 square_x8

# qhasm: reg256 square_x9

# qhasm: reg256 square_x10

# qhasm: reg256 square_x11

# qhasm: reg256 square_nineteen

# qhasm: reg256 square_two

# qhasm: reg256 square_t

# qhasm: reg256 square_c

# qhasm: reg256 s

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

# qhasm: enter ge4x_double_p1p1_asm
.p2align 5
.global _ge4x_double_p1p1_asm
.global ge4x_double_p1p1_asm
_ge4x_double_p1p1_asm:
ge4x_double_p1p1_asm:
mov %rsp,%r11
and $31,%r11
add $0,%r11
sub %r11,%rsp

# qhasm:   square_nineteen aligned= mem256[scale19]
# asm 1: vmovapd scale19,>square_nineteen=reg256#1
# asm 2: vmovapd scale19,>square_nineteen=%ymm0
vmovapd scale19,%ymm0

# qhasm:   square_two aligned= mem256[two4x]
# asm 1: vmovapd two4x,>square_two=reg256#2
# asm 2: vmovapd two4x,>square_two=%ymm1
vmovapd two4x,%ymm1

# qhasm:   square_x0 aligned= mem256[input_1 + 0]
# asm 1: vmovapd   0(<input_1=int64#2),>square_x0=reg256#3
# asm 2: vmovapd   0(<input_1=%rsi),>square_x0=%ymm2
vmovapd   0(%rsi),%ymm2

# qhasm:   4x r0 = approx square_x0 * square_x0
# asm 1: vmulpd <square_x0=reg256#3,<square_x0=reg256#3,>r0=reg256#4
# asm 2: vmulpd <square_x0=%ymm2,<square_x0=%ymm2,>r0=%ymm3
vmulpd %ymm2,%ymm2,%ymm3

# qhasm:   4x square_x0 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x0=reg256#3,>square_x0=reg256#3
# asm 2: vmulpd <square_two=%ymm1,<square_x0=%ymm2,>square_x0=%ymm2
vmulpd %ymm1,%ymm2,%ymm2

# qhasm:   4x r1 = approx square_x0 * mem256[input_1 + 32]
# asm 1: vmulpd 32(<input_1=int64#2),<square_x0=reg256#3,>r1=reg256#5
# asm 2: vmulpd 32(<input_1=%rsi),<square_x0=%ymm2,>r1=%ymm4
vmulpd 32(%rsi),%ymm2,%ymm4

# qhasm:   4x r2 = approx square_x0 * mem256[input_1 + 64]
# asm 1: vmulpd 64(<input_1=int64#2),<square_x0=reg256#3,>r2=reg256#6
# asm 2: vmulpd 64(<input_1=%rsi),<square_x0=%ymm2,>r2=%ymm5
vmulpd 64(%rsi),%ymm2,%ymm5

# qhasm:   4x r3 = approx square_x0 * mem256[input_1 + 96]
# asm 1: vmulpd 96(<input_1=int64#2),<square_x0=reg256#3,>r3=reg256#7
# asm 2: vmulpd 96(<input_1=%rsi),<square_x0=%ymm2,>r3=%ymm6
vmulpd 96(%rsi),%ymm2,%ymm6

# qhasm:   4x r4 = approx square_x0 * mem256[input_1 + 128]
# asm 1: vmulpd 128(<input_1=int64#2),<square_x0=reg256#3,>r4=reg256#8
# asm 2: vmulpd 128(<input_1=%rsi),<square_x0=%ymm2,>r4=%ymm7
vmulpd 128(%rsi),%ymm2,%ymm7

# qhasm:   4x r5 = approx square_x0 * mem256[input_1 + 160]
# asm 1: vmulpd 160(<input_1=int64#2),<square_x0=reg256#3,>r5=reg256#9
# asm 2: vmulpd 160(<input_1=%rsi),<square_x0=%ymm2,>r5=%ymm8
vmulpd 160(%rsi),%ymm2,%ymm8

# qhasm:   4x r6 = approx square_x0 * mem256[input_1 + 192]
# asm 1: vmulpd 192(<input_1=int64#2),<square_x0=reg256#3,>r6=reg256#10
# asm 2: vmulpd 192(<input_1=%rsi),<square_x0=%ymm2,>r6=%ymm9
vmulpd 192(%rsi),%ymm2,%ymm9

# qhasm:   4x r7 = approx square_x0 * mem256[input_1 + 224]
# asm 1: vmulpd 224(<input_1=int64#2),<square_x0=reg256#3,>r7=reg256#11
# asm 2: vmulpd 224(<input_1=%rsi),<square_x0=%ymm2,>r7=%ymm10
vmulpd 224(%rsi),%ymm2,%ymm10

# qhasm:   4x r8 = approx square_x0 * mem256[input_1 + 256]
# asm 1: vmulpd 256(<input_1=int64#2),<square_x0=reg256#3,>r8=reg256#12
# asm 2: vmulpd 256(<input_1=%rsi),<square_x0=%ymm2,>r8=%ymm11
vmulpd 256(%rsi),%ymm2,%ymm11

# qhasm:   4x r9 = approx square_x0 * mem256[input_1 + 288]
# asm 1: vmulpd 288(<input_1=int64#2),<square_x0=reg256#3,>r9=reg256#13
# asm 2: vmulpd 288(<input_1=%rsi),<square_x0=%ymm2,>r9=%ymm12
vmulpd 288(%rsi),%ymm2,%ymm12

# qhasm:   4x r10 = approx square_x0 * mem256[input_1 + 320]
# asm 1: vmulpd 320(<input_1=int64#2),<square_x0=reg256#3,>r10=reg256#14
# asm 2: vmulpd 320(<input_1=%rsi),<square_x0=%ymm2,>r10=%ymm13
vmulpd 320(%rsi),%ymm2,%ymm13

# qhasm:   4x r11 = approx square_x0 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x0=reg256#3,>r11=reg256#3
# asm 2: vmulpd 352(<input_1=%rsi),<square_x0=%ymm2,>r11=%ymm2
vmulpd 352(%rsi),%ymm2,%ymm2

# qhasm:   square_x1 aligned= mem256[input_1 + 32]
# asm 1: vmovapd   32(<input_1=int64#2),>square_x1=reg256#15
# asm 2: vmovapd   32(<input_1=%rsi),>square_x1=%ymm14
vmovapd   32(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x1 * square_x1
# asm 1: vmulpd <square_x1=reg256#15,<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x1=%ymm14,<square_x1=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_x1 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x1=reg256#15,>square_x1=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x1=%ymm14,>square_x1=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 64]
# asm 1: vmulpd 64(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 64(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 64(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 96]
# asm 1: vmulpd 96(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 96(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 96(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 128]
# asm 1: vmulpd 128(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 128(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 128(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 160]
# asm 1: vmulpd 160(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 160(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 160(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 192]
# asm 1: vmulpd 192(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 192(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 224]
# asm 1: vmulpd 224(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 224(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 256]
# asm 1: vmulpd 256(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 256(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 288]
# asm 1: vmulpd 288(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 288(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 320]
# asm 1: vmulpd 320(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 320(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x1 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x1=reg256#15,>square_x1=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x1=%ymm14,>square_x1=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm14
vmulpd 352(%rsi),%ymm14,%ymm14

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   square_x2 aligned= mem256[input_1 + 64]
# asm 1: vmovapd   64(<input_1=int64#2),>square_x2=reg256#15
# asm 2: vmovapd   64(<input_1=%rsi),>square_x2=%ymm14
vmovapd   64(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x2 * square_x2
# asm 1: vmulpd <square_x2=reg256#15,<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x2=%ymm14,<square_x2=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_x2 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x2=reg256#15,>square_x2=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x2=%ymm14,>square_x2=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 96]
# asm 1: vmulpd 96(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 96(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 96(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 128]
# asm 1: vmulpd 128(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 128(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 128(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 160]
# asm 1: vmulpd 160(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 160(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 160(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 192]
# asm 1: vmulpd 192(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 192(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 224]
# asm 1: vmulpd 224(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 224(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 256]
# asm 1: vmulpd 256(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 256(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 288]
# asm 1: vmulpd 288(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 288(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x2 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x2=reg256#15,>square_x2=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x2=%ymm14,>square_x2=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 320]
# asm 1: vmulpd 320(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 320(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm14
vmulpd 352(%rsi),%ymm14,%ymm14

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   square_x3 aligned= mem256[input_1 + 96]
# asm 1: vmovapd   96(<input_1=int64#2),>square_x3=reg256#15
# asm 2: vmovapd   96(<input_1=%rsi),>square_x3=%ymm14
vmovapd   96(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x3 * square_x3
# asm 1: vmulpd <square_x3=reg256#15,<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x3=%ymm14,<square_x3=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_x3 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x3=reg256#15,>square_x3=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x3=%ymm14,>square_x3=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 128]
# asm 1: vmulpd 128(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 128(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 128(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 160]
# asm 1: vmulpd 160(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 160(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 160(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 192]
# asm 1: vmulpd 192(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 192(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 224]
# asm 1: vmulpd 224(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 224(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 256]
# asm 1: vmulpd 256(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 256(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x3 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x3=reg256#15,>square_x3=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x3=%ymm14,>square_x3=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 288]
# asm 1: vmulpd 288(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 288(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 320]
# asm 1: vmulpd 320(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 320(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm14
vmulpd 352(%rsi),%ymm14,%ymm14

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   square_x4 aligned= mem256[input_1 + 128]
# asm 1: vmovapd   128(<input_1=int64#2),>square_x4=reg256#15
# asm 2: vmovapd   128(<input_1=%rsi),>square_x4=%ymm14
vmovapd   128(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x4 * square_x4
# asm 1: vmulpd <square_x4=reg256#15,<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x4=%ymm14,<square_x4=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_x4 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x4=reg256#15,>square_x4=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x4=%ymm14,>square_x4=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 160]
# asm 1: vmulpd 160(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 160(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 160(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 192]
# asm 1: vmulpd 192(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 192(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 224]
# asm 1: vmulpd 224(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 224(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x4 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x4=reg256#15,>square_x4=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x4=%ymm14,>square_x4=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 256]
# asm 1: vmulpd 256(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 256(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 288]
# asm 1: vmulpd 288(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 288(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 320]
# asm 1: vmulpd 320(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 320(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm14
vmulpd 352(%rsi),%ymm14,%ymm14

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   square_x5 aligned= mem256[input_1 + 160]
# asm 1: vmovapd   160(<input_1=int64#2),>square_x5=reg256#15
# asm 2: vmovapd   160(<input_1=%rsi),>square_x5=%ymm14
vmovapd   160(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x5 * square_x5
# asm 1: vmulpd <square_x5=reg256#15,<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x5=%ymm14,<square_x5=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_x5 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x5=reg256#15,>square_x5=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x5=%ymm14,>square_x5=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 192]
# asm 1: vmulpd 192(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 192(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x5 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x5=reg256#15,>square_x5=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x5=%ymm14,>square_x5=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 224]
# asm 1: vmulpd 224(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 224(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 256]
# asm 1: vmulpd 256(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 256(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 288]
# asm 1: vmulpd 288(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 288(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 320]
# asm 1: vmulpd 320(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 320(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm14
vmulpd 352(%rsi),%ymm14,%ymm14

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   square_x6 aligned= mem256[input_1 + 192]
# asm 1: vmovapd   192(<input_1=int64#2),>square_x6=reg256#15
# asm 2: vmovapd   192(<input_1=%rsi),>square_x6=%ymm14
vmovapd   192(%rsi),%ymm14

# qhasm:   4x square_x6 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x6=reg256#15,>square_x6=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x6=%ymm14,>square_x6=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 192]
# asm 1: vmulpd 192(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 192(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_x6 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x6=reg256#15,>square_x6=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x6=%ymm14,>square_x6=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 224]
# asm 1: vmulpd 224(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 224(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 256]
# asm 1: vmulpd 256(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 256(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 288]
# asm 1: vmulpd 288(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 288(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 320]
# asm 1: vmulpd 320(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 320(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm14
vmulpd 352(%rsi),%ymm14,%ymm14

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   square_x7 aligned= mem256[input_1 + 224]
# asm 1: vmovapd   224(<input_1=int64#2),>square_x7=reg256#15
# asm 2: vmovapd   224(<input_1=%rsi),>square_x7=%ymm14
vmovapd   224(%rsi),%ymm14

# qhasm:   4x square_x7 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x7=reg256#15,>square_x7=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x7=%ymm14,>square_x7=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 224]
# asm 1: vmulpd 224(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 224(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_x7 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x7=reg256#15,>square_x7=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x7=%ymm14,>square_x7=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 256]
# asm 1: vmulpd 256(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 256(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 288]
# asm 1: vmulpd 288(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 288(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 320]
# asm 1: vmulpd 320(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 320(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm14
vmulpd 352(%rsi),%ymm14,%ymm14

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   square_x8 aligned= mem256[input_1 + 256]
# asm 1: vmovapd   256(<input_1=int64#2),>square_x8=reg256#15
# asm 2: vmovapd   256(<input_1=%rsi),>square_x8=%ymm14
vmovapd   256(%rsi),%ymm14

# qhasm:   4x square_x8 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x8=reg256#15,>square_x8=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x8=%ymm14,>square_x8=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 256]
# asm 1: vmulpd 256(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 256(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_x8 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x8=reg256#15,>square_x8=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x8=%ymm14,>square_x8=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 288]
# asm 1: vmulpd 288(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 288(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 320]
# asm 1: vmulpd 320(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 320(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm14
vmulpd 352(%rsi),%ymm14,%ymm14

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   square_x9 aligned= mem256[input_1 + 288]
# asm 1: vmovapd   288(<input_1=int64#2),>square_x9=reg256#15
# asm 2: vmovapd   288(<input_1=%rsi),>square_x9=%ymm14
vmovapd   288(%rsi),%ymm14

# qhasm:   4x square_x9 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x9=reg256#15,>square_x9=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x9=%ymm14,>square_x9=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x9 * mem256[input_1 + 288]
# asm 1: vmulpd 288(<input_1=int64#2),<square_x9=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_1=%rsi),<square_x9=%ymm14,>square_t=%ymm15
vmulpd 288(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_x9 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x9=reg256#15,>square_x9=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x9=%ymm14,>square_x9=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x9 * mem256[input_1 + 320]
# asm 1: vmulpd 320(<input_1=int64#2),<square_x9=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_1=%rsi),<square_x9=%ymm14,>square_t=%ymm15
vmulpd 320(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x9 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x9=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_1=%rsi),<square_x9=%ymm14,>square_t=%ymm14
vmulpd 352(%rsi),%ymm14,%ymm14

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   square_x10 aligned= mem256[input_1 + 320]
# asm 1: vmovapd   320(<input_1=int64#2),>square_x10=reg256#15
# asm 2: vmovapd   320(<input_1=%rsi),>square_x10=%ymm14
vmovapd   320(%rsi),%ymm14

# qhasm:   4x square_x10 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x10=reg256#15,>square_x10=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x10=%ymm14,>square_x10=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x10 * mem256[input_1 + 320]
# asm 1: vmulpd 320(<input_1=int64#2),<square_x10=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_1=%rsi),<square_x10=%ymm14,>square_t=%ymm15
vmulpd 320(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_x10 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x10=reg256#15,>square_x10=reg256#2
# asm 2: vmulpd <square_two=%ymm1,<square_x10=%ymm14,>square_x10=%ymm1
vmulpd %ymm1,%ymm14,%ymm1

# qhasm:   4x square_t = approx square_x10 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x10=reg256#2,>square_t=reg256#2
# asm 2: vmulpd 352(<input_1=%rsi),<square_x10=%ymm1,>square_t=%ymm1
vmulpd 352(%rsi),%ymm1,%ymm1

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#2,<r9=reg256#13,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm1,<r9=%ymm12,>r9=%ymm1
vaddpd %ymm1,%ymm12,%ymm1

# qhasm:   square_x11 aligned= mem256[input_1 + 352]
# asm 1: vmovapd   352(<input_1=int64#2),>square_x11=reg256#13
# asm 2: vmovapd   352(<input_1=%rsi),>square_x11=%ymm12
vmovapd   352(%rsi),%ymm12

# qhasm:   4x square_x11 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x11=reg256#13,>square_x11=reg256#13
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x11=%ymm12,>square_x11=%ymm12
vmulpd %ymm0,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x11 * mem256[input_1 + 352]
# asm 1: vmulpd 352(<input_1=int64#2),<square_x11=reg256#13,>square_t=reg256#13
# asm 2: vmulpd 352(<input_1=%rsi),<square_x11=%ymm12,>square_t=%ymm12
vmulpd 352(%rsi),%ymm12,%ymm12

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#13,<r10=reg256#14,>r10=reg256#13
# asm 2: vaddpd <square_t=%ymm12,<r10=%ymm13,>r10=%ymm12
vaddpd %ymm12,%ymm13,%ymm12

# qhasm:   square_c aligned= mem256[alpha22]
# asm 1: vmovapd alpha22,>square_c=reg256#14
# asm 2: vmovapd alpha22,>square_c=%ymm13
vmovapd alpha22,%ymm13

# qhasm:   4x square_t = approx r0 +square_c
# asm 1: vaddpd <r0=reg256#4,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r0=%ymm3,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm3,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r0 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r0=reg256#4,>r0=reg256#4
# asm 2: vsubpd <square_t=%ymm13,<r0=%ymm3,>r0=%ymm3
vsubpd %ymm13,%ymm3,%ymm3

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm13,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm13,%ymm4,%ymm4

# qhasm:   square_c aligned= mem256[alpha107]
# asm 1: vmovapd alpha107,>square_c=reg256#14
# asm 2: vmovapd alpha107,>square_c=%ymm13
vmovapd alpha107,%ymm13

# qhasm:   4x square_t = approx r4 +square_c
# asm 1: vaddpd <r4=reg256#8,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r4=%ymm7,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm7,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r4 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r4=reg256#8,>r4=reg256#8
# asm 2: vsubpd <square_t=%ymm13,<r4=%ymm7,>r4=%ymm7
vsubpd %ymm13,%ymm7,%ymm7

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm13,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm13,%ymm8,%ymm8

# qhasm:   square_c aligned= mem256[alpha192]
# asm 1: vmovapd alpha192,>square_c=reg256#14
# asm 2: vmovapd alpha192,>square_c=%ymm13
vmovapd alpha192,%ymm13

# qhasm:   4x square_t = approx r8 +square_c
# asm 1: vaddpd <r8=reg256#12,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r8=%ymm11,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm11,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r8 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r8=reg256#12,>r8=reg256#12
# asm 2: vsubpd <square_t=%ymm13,<r8=%ymm11,>r8=%ymm11
vsubpd %ymm13,%ymm11,%ymm11

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r9=reg256#2,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm13,<r9=%ymm1,>r9=%ymm1
vaddpd %ymm13,%ymm1,%ymm1

# qhasm:   square_c aligned= mem256[alpha43]
# asm 1: vmovapd alpha43,>square_c=reg256#14
# asm 2: vmovapd alpha43,>square_c=%ymm13
vmovapd alpha43,%ymm13

# qhasm:   4x square_t = approx r1 +square_c
# asm 1: vaddpd <r1=reg256#5,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r1=%ymm4,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm4,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r1 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r1=reg256#5,>r1=reg256#5
# asm 2: vsubpd <square_t=%ymm13,<r1=%ymm4,>r1=%ymm4
vsubpd %ymm13,%ymm4,%ymm4

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm13,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm13,%ymm5,%ymm5

# qhasm:   square_c aligned= mem256[alpha128]
# asm 1: vmovapd alpha128,>square_c=reg256#14
# asm 2: vmovapd alpha128,>square_c=%ymm13
vmovapd alpha128,%ymm13

# qhasm:   4x square_t = approx r5 +square_c
# asm 1: vaddpd <r5=reg256#9,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r5=%ymm8,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm8,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r5 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r5=reg256#9,>r5=reg256#9
# asm 2: vsubpd <square_t=%ymm13,<r5=%ymm8,>r5=%ymm8
vsubpd %ymm13,%ymm8,%ymm8

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm13,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm13,%ymm9,%ymm9

# qhasm:   square_c aligned= mem256[alpha213]
# asm 1: vmovapd alpha213,>square_c=reg256#14
# asm 2: vmovapd alpha213,>square_c=%ymm13
vmovapd alpha213,%ymm13

# qhasm:   4x square_t = approx r9 +square_c
# asm 1: vaddpd <r9=reg256#2,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r9=%ymm1,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm1,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r9 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r9=reg256#2,>r9=reg256#2
# asm 2: vsubpd <square_t=%ymm13,<r9=%ymm1,>r9=%ymm1
vsubpd %ymm13,%ymm1,%ymm1

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r10=reg256#13,>r10=reg256#13
# asm 2: vaddpd <square_t=%ymm13,<r10=%ymm12,>r10=%ymm12
vaddpd %ymm13,%ymm12,%ymm12

# qhasm:   square_c aligned= mem256[alpha64]
# asm 1: vmovapd alpha64,>square_c=reg256#14
# asm 2: vmovapd alpha64,>square_c=%ymm13
vmovapd alpha64,%ymm13

# qhasm:   4x square_t = approx r2 +square_c
# asm 1: vaddpd <r2=reg256#6,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r2=%ymm5,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm5,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r2 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r2=reg256#6,>r2=reg256#6
# asm 2: vsubpd <square_t=%ymm13,<r2=%ymm5,>r2=%ymm5
vsubpd %ymm13,%ymm5,%ymm5

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm13,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm13,%ymm6,%ymm6

# qhasm:   square_c aligned= mem256[alpha149]
# asm 1: vmovapd alpha149,>square_c=reg256#14
# asm 2: vmovapd alpha149,>square_c=%ymm13
vmovapd alpha149,%ymm13

# qhasm:   4x square_t = approx r6 +square_c
# asm 1: vaddpd <r6=reg256#10,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r6=%ymm9,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm9,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r6 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r6=reg256#10,>r6=reg256#10
# asm 2: vsubpd <square_t=%ymm13,<r6=%ymm9,>r6=%ymm9
vsubpd %ymm13,%ymm9,%ymm9

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm13,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm13,%ymm10,%ymm10

# qhasm:   square_c aligned= mem256[alpha234]
# asm 1: vmovapd alpha234,>square_c=reg256#14
# asm 2: vmovapd alpha234,>square_c=%ymm13
vmovapd alpha234,%ymm13

# qhasm:   4x square_t = approx r10 +square_c
# asm 1: vaddpd <r10=reg256#13,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r10=%ymm12,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm12,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r10 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r10=reg256#13,>r10=reg256#13
# asm 2: vsubpd <square_t=%ymm13,<r10=%ymm12,>r10=%ymm12
vsubpd %ymm13,%ymm12,%ymm12

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm13,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm13,%ymm2,%ymm2

# qhasm:   square_c aligned= mem256[alpha85]
# asm 1: vmovapd alpha85,>square_c=reg256#14
# asm 2: vmovapd alpha85,>square_c=%ymm13
vmovapd alpha85,%ymm13

# qhasm:   4x square_t = approx r3 +square_c
# asm 1: vaddpd <r3=reg256#7,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r3=%ymm6,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm6,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r3 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r3=reg256#7,>r3=reg256#7
# asm 2: vsubpd <square_t=%ymm13,<r3=%ymm6,>r3=%ymm6
vsubpd %ymm13,%ymm6,%ymm6

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm13,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm13,%ymm7,%ymm7

# qhasm:   square_c aligned= mem256[alpha170]
# asm 1: vmovapd alpha170,>square_c=reg256#14
# asm 2: vmovapd alpha170,>square_c=%ymm13
vmovapd alpha170,%ymm13

# qhasm:   4x square_t = approx r7 +square_c
# asm 1: vaddpd <r7=reg256#11,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r7=%ymm10,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm10,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r7 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r7=reg256#11,>r7=reg256#11
# asm 2: vsubpd <square_t=%ymm13,<r7=%ymm10,>r7=%ymm10
vsubpd %ymm13,%ymm10,%ymm10

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm13,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm13,%ymm11,%ymm11

# qhasm:   square_c aligned= mem256[alpha255]
# asm 1: vmovapd alpha255,>square_c=reg256#14
# asm 2: vmovapd alpha255,>square_c=%ymm13
vmovapd alpha255,%ymm13

# qhasm:   4x square_t = approx r11 +square_c
# asm 1: vaddpd <r11=reg256#3,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r11=%ymm2,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm2,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r11 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r11=reg256#3,>r11=reg256#3
# asm 2: vsubpd <square_t=%ymm13,<r11=%ymm2,>r11=%ymm2
vsubpd %ymm13,%ymm2,%ymm2

# qhasm:   4x square_t approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_t=reg256#14,>square_t=reg256#1
# asm 2: vmulpd <square_nineteen=%ymm0,<square_t=%ymm13,>square_t=%ymm0
vmulpd %ymm0,%ymm13,%ymm0

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#1,<r0=reg256#4,>r0=reg256#1
# asm 2: vaddpd <square_t=%ymm0,<r0=%ymm3,>r0=%ymm0
vaddpd %ymm0,%ymm3,%ymm0

# qhasm:   square_c aligned= mem256[alpha22]
# asm 1: vmovapd alpha22,>square_c=reg256#4
# asm 2: vmovapd alpha22,>square_c=%ymm3
vmovapd alpha22,%ymm3

# qhasm:   4x square_t = approx r0 +square_c
# asm 1: vaddpd <r0=reg256#1,<square_c=reg256#4,>square_t=reg256#14
# asm 2: vaddpd <r0=%ymm0,<square_c=%ymm3,>square_t=%ymm13
vaddpd %ymm0,%ymm3,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#4,<square_t=reg256#14,>square_t=reg256#4
# asm 2: vsubpd <square_c=%ymm3,<square_t=%ymm13,>square_t=%ymm3
vsubpd %ymm3,%ymm13,%ymm3

# qhasm:   4x r0 approx-= square_t
# asm 1: vsubpd <square_t=reg256#4,<r0=reg256#1,>r0=reg256#1
# asm 2: vsubpd <square_t=%ymm3,<r0=%ymm0,>r0=%ymm0
vsubpd %ymm3,%ymm0,%ymm0

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#4,<r1=reg256#5,>r1=reg256#4
# asm 2: vaddpd <square_t=%ymm3,<r1=%ymm4,>r1=%ymm3
vaddpd %ymm3,%ymm4,%ymm3

# qhasm:   square_c aligned= mem256[alpha107]
# asm 1: vmovapd alpha107,>square_c=reg256#5
# asm 2: vmovapd alpha107,>square_c=%ymm4
vmovapd alpha107,%ymm4

# qhasm:   4x square_t = approx r4 +square_c
# asm 1: vaddpd <r4=reg256#8,<square_c=reg256#5,>square_t=reg256#14
# asm 2: vaddpd <r4=%ymm7,<square_c=%ymm4,>square_t=%ymm13
vaddpd %ymm7,%ymm4,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#5,<square_t=reg256#14,>square_t=reg256#5
# asm 2: vsubpd <square_c=%ymm4,<square_t=%ymm13,>square_t=%ymm4
vsubpd %ymm4,%ymm13,%ymm4

# qhasm:   4x r4 approx-= square_t
# asm 1: vsubpd <square_t=reg256#5,<r4=reg256#8,>r4=reg256#8
# asm 2: vsubpd <square_t=%ymm4,<r4=%ymm7,>r4=%ymm7
vsubpd %ymm4,%ymm7,%ymm7

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#5,<r5=reg256#9,>r5=reg256#5
# asm 2: vaddpd <square_t=%ymm4,<r5=%ymm8,>r5=%ymm4
vaddpd %ymm4,%ymm8,%ymm4

# qhasm:   square_c aligned= mem256[alpha192]
# asm 1: vmovapd alpha192,>square_c=reg256#9
# asm 2: vmovapd alpha192,>square_c=%ymm8
vmovapd alpha192,%ymm8

# qhasm:   4x square_t = approx r8 +square_c
# asm 1: vaddpd <r8=reg256#12,<square_c=reg256#9,>square_t=reg256#14
# asm 2: vaddpd <r8=%ymm11,<square_c=%ymm8,>square_t=%ymm13
vaddpd %ymm11,%ymm8,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#9,<square_t=reg256#14,>square_t=reg256#9
# asm 2: vsubpd <square_c=%ymm8,<square_t=%ymm13,>square_t=%ymm8
vsubpd %ymm8,%ymm13,%ymm8

# qhasm:   4x r8 approx-= square_t
# asm 1: vsubpd <square_t=reg256#9,<r8=reg256#12,>r8=reg256#12
# asm 2: vsubpd <square_t=%ymm8,<r8=%ymm11,>r8=%ymm11
vsubpd %ymm8,%ymm11,%ymm11

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#9,<r9=reg256#2,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm8,<r9=%ymm1,>r9=%ymm1
vaddpd %ymm8,%ymm1,%ymm1

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
# asm 1: vmovapd   <r9=reg256#2,288(<input_0=int64#1)
# asm 2: vmovapd   <r9=%ymm1,288(<input_0=%rdi)
vmovapd   %ymm1,288(%rdi)

# qhasm: mem256[input_0 + 320] aligned= r10
# asm 1: vmovapd   <r10=reg256#13,320(<input_0=int64#1)
# asm 2: vmovapd   <r10=%ymm12,320(<input_0=%rdi)
vmovapd   %ymm12,320(%rdi)

# qhasm: mem256[input_0 + 352] aligned= r11
# asm 1: vmovapd   <r11=reg256#3,352(<input_0=int64#1)
# asm 2: vmovapd   <r11=%ymm2,352(<input_0=%rdi)
vmovapd   %ymm2,352(%rdi)

# qhasm:   square_nineteen aligned= mem256[scale19]
# asm 1: vmovapd scale19,>square_nineteen=reg256#1
# asm 2: vmovapd scale19,>square_nineteen=%ymm0
vmovapd scale19,%ymm0

# qhasm:   square_two aligned= mem256[two4x]
# asm 1: vmovapd two4x,>square_two=reg256#2
# asm 2: vmovapd two4x,>square_two=%ymm1
vmovapd two4x,%ymm1

# qhasm:   square_x0 aligned= mem256[input_1 + 384]
# asm 1: vmovapd   384(<input_1=int64#2),>square_x0=reg256#3
# asm 2: vmovapd   384(<input_1=%rsi),>square_x0=%ymm2
vmovapd   384(%rsi),%ymm2

# qhasm:   4x r0 = approx square_x0 * square_x0
# asm 1: vmulpd <square_x0=reg256#3,<square_x0=reg256#3,>r0=reg256#4
# asm 2: vmulpd <square_x0=%ymm2,<square_x0=%ymm2,>r0=%ymm3
vmulpd %ymm2,%ymm2,%ymm3

# qhasm:   4x square_x0 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x0=reg256#3,>square_x0=reg256#3
# asm 2: vmulpd <square_two=%ymm1,<square_x0=%ymm2,>square_x0=%ymm2
vmulpd %ymm1,%ymm2,%ymm2

# qhasm:   4x r1 = approx square_x0 * mem256[input_1 + 416]
# asm 1: vmulpd 416(<input_1=int64#2),<square_x0=reg256#3,>r1=reg256#5
# asm 2: vmulpd 416(<input_1=%rsi),<square_x0=%ymm2,>r1=%ymm4
vmulpd 416(%rsi),%ymm2,%ymm4

# qhasm:   4x r2 = approx square_x0 * mem256[input_1 + 448]
# asm 1: vmulpd 448(<input_1=int64#2),<square_x0=reg256#3,>r2=reg256#6
# asm 2: vmulpd 448(<input_1=%rsi),<square_x0=%ymm2,>r2=%ymm5
vmulpd 448(%rsi),%ymm2,%ymm5

# qhasm:   4x r3 = approx square_x0 * mem256[input_1 + 480]
# asm 1: vmulpd 480(<input_1=int64#2),<square_x0=reg256#3,>r3=reg256#7
# asm 2: vmulpd 480(<input_1=%rsi),<square_x0=%ymm2,>r3=%ymm6
vmulpd 480(%rsi),%ymm2,%ymm6

# qhasm:   4x r4 = approx square_x0 * mem256[input_1 + 512]
# asm 1: vmulpd 512(<input_1=int64#2),<square_x0=reg256#3,>r4=reg256#8
# asm 2: vmulpd 512(<input_1=%rsi),<square_x0=%ymm2,>r4=%ymm7
vmulpd 512(%rsi),%ymm2,%ymm7

# qhasm:   4x r5 = approx square_x0 * mem256[input_1 + 544]
# asm 1: vmulpd 544(<input_1=int64#2),<square_x0=reg256#3,>r5=reg256#9
# asm 2: vmulpd 544(<input_1=%rsi),<square_x0=%ymm2,>r5=%ymm8
vmulpd 544(%rsi),%ymm2,%ymm8

# qhasm:   4x r6 = approx square_x0 * mem256[input_1 + 576]
# asm 1: vmulpd 576(<input_1=int64#2),<square_x0=reg256#3,>r6=reg256#10
# asm 2: vmulpd 576(<input_1=%rsi),<square_x0=%ymm2,>r6=%ymm9
vmulpd 576(%rsi),%ymm2,%ymm9

# qhasm:   4x r7 = approx square_x0 * mem256[input_1 + 608]
# asm 1: vmulpd 608(<input_1=int64#2),<square_x0=reg256#3,>r7=reg256#11
# asm 2: vmulpd 608(<input_1=%rsi),<square_x0=%ymm2,>r7=%ymm10
vmulpd 608(%rsi),%ymm2,%ymm10

# qhasm:   4x r8 = approx square_x0 * mem256[input_1 + 640]
# asm 1: vmulpd 640(<input_1=int64#2),<square_x0=reg256#3,>r8=reg256#12
# asm 2: vmulpd 640(<input_1=%rsi),<square_x0=%ymm2,>r8=%ymm11
vmulpd 640(%rsi),%ymm2,%ymm11

# qhasm:   4x r9 = approx square_x0 * mem256[input_1 + 672]
# asm 1: vmulpd 672(<input_1=int64#2),<square_x0=reg256#3,>r9=reg256#13
# asm 2: vmulpd 672(<input_1=%rsi),<square_x0=%ymm2,>r9=%ymm12
vmulpd 672(%rsi),%ymm2,%ymm12

# qhasm:   4x r10 = approx square_x0 * mem256[input_1 + 704]
# asm 1: vmulpd 704(<input_1=int64#2),<square_x0=reg256#3,>r10=reg256#14
# asm 2: vmulpd 704(<input_1=%rsi),<square_x0=%ymm2,>r10=%ymm13
vmulpd 704(%rsi),%ymm2,%ymm13

# qhasm:   4x r11 = approx square_x0 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x0=reg256#3,>r11=reg256#3
# asm 2: vmulpd 736(<input_1=%rsi),<square_x0=%ymm2,>r11=%ymm2
vmulpd 736(%rsi),%ymm2,%ymm2

# qhasm:   square_x1 aligned= mem256[input_1 + 416]
# asm 1: vmovapd   416(<input_1=int64#2),>square_x1=reg256#15
# asm 2: vmovapd   416(<input_1=%rsi),>square_x1=%ymm14
vmovapd   416(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x1 * square_x1
# asm 1: vmulpd <square_x1=reg256#15,<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x1=%ymm14,<square_x1=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_x1 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x1=reg256#15,>square_x1=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x1=%ymm14,>square_x1=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 448]
# asm 1: vmulpd 448(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 448(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 448(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 480]
# asm 1: vmulpd 480(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 480(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 480(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 512]
# asm 1: vmulpd 512(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 512(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 512(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 544]
# asm 1: vmulpd 544(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 544(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 544(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 576]
# asm 1: vmulpd 576(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 576(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 576(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 608]
# asm 1: vmulpd 608(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 608(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 608(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 640]
# asm 1: vmulpd 640(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 640(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 640(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 672]
# asm 1: vmulpd 672(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 672(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 672(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 704]
# asm 1: vmulpd 704(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 704(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 704(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x1 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x1=reg256#15,>square_x1=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x1=%ymm14,>square_x1=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 736(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm14
vmulpd 736(%rsi),%ymm14,%ymm14

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   square_x2 aligned= mem256[input_1 + 448]
# asm 1: vmovapd   448(<input_1=int64#2),>square_x2=reg256#15
# asm 2: vmovapd   448(<input_1=%rsi),>square_x2=%ymm14
vmovapd   448(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x2 * square_x2
# asm 1: vmulpd <square_x2=reg256#15,<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x2=%ymm14,<square_x2=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_x2 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x2=reg256#15,>square_x2=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x2=%ymm14,>square_x2=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 480]
# asm 1: vmulpd 480(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 480(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 480(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 512]
# asm 1: vmulpd 512(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 512(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 512(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 544]
# asm 1: vmulpd 544(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 544(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 544(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 576]
# asm 1: vmulpd 576(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 576(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 576(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 608]
# asm 1: vmulpd 608(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 608(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 608(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 640]
# asm 1: vmulpd 640(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 640(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 640(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 672]
# asm 1: vmulpd 672(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 672(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 672(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x2 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x2=reg256#15,>square_x2=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x2=%ymm14,>square_x2=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 704]
# asm 1: vmulpd 704(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 704(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 704(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 736(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm14
vmulpd 736(%rsi),%ymm14,%ymm14

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   square_x3 aligned= mem256[input_1 + 480]
# asm 1: vmovapd   480(<input_1=int64#2),>square_x3=reg256#15
# asm 2: vmovapd   480(<input_1=%rsi),>square_x3=%ymm14
vmovapd   480(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x3 * square_x3
# asm 1: vmulpd <square_x3=reg256#15,<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x3=%ymm14,<square_x3=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_x3 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x3=reg256#15,>square_x3=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x3=%ymm14,>square_x3=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 512]
# asm 1: vmulpd 512(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 512(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 512(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 544]
# asm 1: vmulpd 544(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 544(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 544(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 576]
# asm 1: vmulpd 576(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 576(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 576(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 608]
# asm 1: vmulpd 608(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 608(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 608(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 640]
# asm 1: vmulpd 640(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 640(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 640(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x3 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x3=reg256#15,>square_x3=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x3=%ymm14,>square_x3=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 672]
# asm 1: vmulpd 672(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 672(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 672(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 704]
# asm 1: vmulpd 704(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 704(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 704(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 736(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm14
vmulpd 736(%rsi),%ymm14,%ymm14

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   square_x4 aligned= mem256[input_1 + 512]
# asm 1: vmovapd   512(<input_1=int64#2),>square_x4=reg256#15
# asm 2: vmovapd   512(<input_1=%rsi),>square_x4=%ymm14
vmovapd   512(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x4 * square_x4
# asm 1: vmulpd <square_x4=reg256#15,<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x4=%ymm14,<square_x4=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_x4 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x4=reg256#15,>square_x4=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x4=%ymm14,>square_x4=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 544]
# asm 1: vmulpd 544(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 544(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 544(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 576]
# asm 1: vmulpd 576(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 576(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 576(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 608]
# asm 1: vmulpd 608(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 608(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 608(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x4 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x4=reg256#15,>square_x4=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x4=%ymm14,>square_x4=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 640]
# asm 1: vmulpd 640(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 640(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 640(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 672]
# asm 1: vmulpd 672(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 672(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 672(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 704]
# asm 1: vmulpd 704(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 704(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 704(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 736(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm14
vmulpd 736(%rsi),%ymm14,%ymm14

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   square_x5 aligned= mem256[input_1 + 544]
# asm 1: vmovapd   544(<input_1=int64#2),>square_x5=reg256#15
# asm 2: vmovapd   544(<input_1=%rsi),>square_x5=%ymm14
vmovapd   544(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x5 * square_x5
# asm 1: vmulpd <square_x5=reg256#15,<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x5=%ymm14,<square_x5=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_x5 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x5=reg256#15,>square_x5=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x5=%ymm14,>square_x5=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 576]
# asm 1: vmulpd 576(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 576(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 576(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x5 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x5=reg256#15,>square_x5=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x5=%ymm14,>square_x5=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 608]
# asm 1: vmulpd 608(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 608(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 608(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 640]
# asm 1: vmulpd 640(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 640(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 640(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 672]
# asm 1: vmulpd 672(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 672(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 672(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 704]
# asm 1: vmulpd 704(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 704(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 704(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 736(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm14
vmulpd 736(%rsi),%ymm14,%ymm14

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   square_x6 aligned= mem256[input_1 + 576]
# asm 1: vmovapd   576(<input_1=int64#2),>square_x6=reg256#15
# asm 2: vmovapd   576(<input_1=%rsi),>square_x6=%ymm14
vmovapd   576(%rsi),%ymm14

# qhasm:   4x square_x6 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x6=reg256#15,>square_x6=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x6=%ymm14,>square_x6=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 576]
# asm 1: vmulpd 576(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 576(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 576(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_x6 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x6=reg256#15,>square_x6=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x6=%ymm14,>square_x6=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 608]
# asm 1: vmulpd 608(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 608(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 608(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 640]
# asm 1: vmulpd 640(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 640(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 640(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 672]
# asm 1: vmulpd 672(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 672(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 672(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 704]
# asm 1: vmulpd 704(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 704(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 704(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 736(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm14
vmulpd 736(%rsi),%ymm14,%ymm14

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   square_x7 aligned= mem256[input_1 + 608]
# asm 1: vmovapd   608(<input_1=int64#2),>square_x7=reg256#15
# asm 2: vmovapd   608(<input_1=%rsi),>square_x7=%ymm14
vmovapd   608(%rsi),%ymm14

# qhasm:   4x square_x7 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x7=reg256#15,>square_x7=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x7=%ymm14,>square_x7=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 608]
# asm 1: vmulpd 608(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 608(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 608(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_x7 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x7=reg256#15,>square_x7=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x7=%ymm14,>square_x7=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 640]
# asm 1: vmulpd 640(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 640(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 640(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 672]
# asm 1: vmulpd 672(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 672(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 672(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 704]
# asm 1: vmulpd 704(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 704(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 704(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 736(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm14
vmulpd 736(%rsi),%ymm14,%ymm14

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   square_x8 aligned= mem256[input_1 + 640]
# asm 1: vmovapd   640(<input_1=int64#2),>square_x8=reg256#15
# asm 2: vmovapd   640(<input_1=%rsi),>square_x8=%ymm14
vmovapd   640(%rsi),%ymm14

# qhasm:   4x square_x8 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x8=reg256#15,>square_x8=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x8=%ymm14,>square_x8=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 640]
# asm 1: vmulpd 640(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 640(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 640(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_x8 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x8=reg256#15,>square_x8=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x8=%ymm14,>square_x8=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 672]
# asm 1: vmulpd 672(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 672(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 672(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 704]
# asm 1: vmulpd 704(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 704(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 704(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 736(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm14
vmulpd 736(%rsi),%ymm14,%ymm14

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   square_x9 aligned= mem256[input_1 + 672]
# asm 1: vmovapd   672(<input_1=int64#2),>square_x9=reg256#15
# asm 2: vmovapd   672(<input_1=%rsi),>square_x9=%ymm14
vmovapd   672(%rsi),%ymm14

# qhasm:   4x square_x9 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x9=reg256#15,>square_x9=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x9=%ymm14,>square_x9=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x9 * mem256[input_1 + 672]
# asm 1: vmulpd 672(<input_1=int64#2),<square_x9=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 672(<input_1=%rsi),<square_x9=%ymm14,>square_t=%ymm15
vmulpd 672(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_x9 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x9=reg256#15,>square_x9=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x9=%ymm14,>square_x9=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x9 * mem256[input_1 + 704]
# asm 1: vmulpd 704(<input_1=int64#2),<square_x9=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 704(<input_1=%rsi),<square_x9=%ymm14,>square_t=%ymm15
vmulpd 704(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x9 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x9=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 736(<input_1=%rsi),<square_x9=%ymm14,>square_t=%ymm14
vmulpd 736(%rsi),%ymm14,%ymm14

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   square_x10 aligned= mem256[input_1 + 704]
# asm 1: vmovapd   704(<input_1=int64#2),>square_x10=reg256#15
# asm 2: vmovapd   704(<input_1=%rsi),>square_x10=%ymm14
vmovapd   704(%rsi),%ymm14

# qhasm:   4x square_x10 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x10=reg256#15,>square_x10=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x10=%ymm14,>square_x10=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x10 * mem256[input_1 + 704]
# asm 1: vmulpd 704(<input_1=int64#2),<square_x10=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 704(<input_1=%rsi),<square_x10=%ymm14,>square_t=%ymm15
vmulpd 704(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_x10 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x10=reg256#15,>square_x10=reg256#2
# asm 2: vmulpd <square_two=%ymm1,<square_x10=%ymm14,>square_x10=%ymm1
vmulpd %ymm1,%ymm14,%ymm1

# qhasm:   4x square_t = approx square_x10 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x10=reg256#2,>square_t=reg256#2
# asm 2: vmulpd 736(<input_1=%rsi),<square_x10=%ymm1,>square_t=%ymm1
vmulpd 736(%rsi),%ymm1,%ymm1

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#2,<r9=reg256#13,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm1,<r9=%ymm12,>r9=%ymm1
vaddpd %ymm1,%ymm12,%ymm1

# qhasm:   square_x11 aligned= mem256[input_1 + 736]
# asm 1: vmovapd   736(<input_1=int64#2),>square_x11=reg256#13
# asm 2: vmovapd   736(<input_1=%rsi),>square_x11=%ymm12
vmovapd   736(%rsi),%ymm12

# qhasm:   4x square_x11 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x11=reg256#13,>square_x11=reg256#13
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x11=%ymm12,>square_x11=%ymm12
vmulpd %ymm0,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x11 * mem256[input_1 + 736]
# asm 1: vmulpd 736(<input_1=int64#2),<square_x11=reg256#13,>square_t=reg256#13
# asm 2: vmulpd 736(<input_1=%rsi),<square_x11=%ymm12,>square_t=%ymm12
vmulpd 736(%rsi),%ymm12,%ymm12

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#13,<r10=reg256#14,>r10=reg256#13
# asm 2: vaddpd <square_t=%ymm12,<r10=%ymm13,>r10=%ymm12
vaddpd %ymm12,%ymm13,%ymm12

# qhasm:   square_c aligned= mem256[alpha22]
# asm 1: vmovapd alpha22,>square_c=reg256#14
# asm 2: vmovapd alpha22,>square_c=%ymm13
vmovapd alpha22,%ymm13

# qhasm:   4x square_t = approx r0 +square_c
# asm 1: vaddpd <r0=reg256#4,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r0=%ymm3,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm3,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r0 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r0=reg256#4,>r0=reg256#4
# asm 2: vsubpd <square_t=%ymm13,<r0=%ymm3,>r0=%ymm3
vsubpd %ymm13,%ymm3,%ymm3

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm13,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm13,%ymm4,%ymm4

# qhasm:   square_c aligned= mem256[alpha107]
# asm 1: vmovapd alpha107,>square_c=reg256#14
# asm 2: vmovapd alpha107,>square_c=%ymm13
vmovapd alpha107,%ymm13

# qhasm:   4x square_t = approx r4 +square_c
# asm 1: vaddpd <r4=reg256#8,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r4=%ymm7,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm7,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r4 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r4=reg256#8,>r4=reg256#8
# asm 2: vsubpd <square_t=%ymm13,<r4=%ymm7,>r4=%ymm7
vsubpd %ymm13,%ymm7,%ymm7

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm13,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm13,%ymm8,%ymm8

# qhasm:   square_c aligned= mem256[alpha192]
# asm 1: vmovapd alpha192,>square_c=reg256#14
# asm 2: vmovapd alpha192,>square_c=%ymm13
vmovapd alpha192,%ymm13

# qhasm:   4x square_t = approx r8 +square_c
# asm 1: vaddpd <r8=reg256#12,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r8=%ymm11,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm11,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r8 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r8=reg256#12,>r8=reg256#12
# asm 2: vsubpd <square_t=%ymm13,<r8=%ymm11,>r8=%ymm11
vsubpd %ymm13,%ymm11,%ymm11

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r9=reg256#2,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm13,<r9=%ymm1,>r9=%ymm1
vaddpd %ymm13,%ymm1,%ymm1

# qhasm:   square_c aligned= mem256[alpha43]
# asm 1: vmovapd alpha43,>square_c=reg256#14
# asm 2: vmovapd alpha43,>square_c=%ymm13
vmovapd alpha43,%ymm13

# qhasm:   4x square_t = approx r1 +square_c
# asm 1: vaddpd <r1=reg256#5,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r1=%ymm4,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm4,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r1 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r1=reg256#5,>r1=reg256#5
# asm 2: vsubpd <square_t=%ymm13,<r1=%ymm4,>r1=%ymm4
vsubpd %ymm13,%ymm4,%ymm4

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm13,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm13,%ymm5,%ymm5

# qhasm:   square_c aligned= mem256[alpha128]
# asm 1: vmovapd alpha128,>square_c=reg256#14
# asm 2: vmovapd alpha128,>square_c=%ymm13
vmovapd alpha128,%ymm13

# qhasm:   4x square_t = approx r5 +square_c
# asm 1: vaddpd <r5=reg256#9,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r5=%ymm8,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm8,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r5 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r5=reg256#9,>r5=reg256#9
# asm 2: vsubpd <square_t=%ymm13,<r5=%ymm8,>r5=%ymm8
vsubpd %ymm13,%ymm8,%ymm8

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm13,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm13,%ymm9,%ymm9

# qhasm:   square_c aligned= mem256[alpha213]
# asm 1: vmovapd alpha213,>square_c=reg256#14
# asm 2: vmovapd alpha213,>square_c=%ymm13
vmovapd alpha213,%ymm13

# qhasm:   4x square_t = approx r9 +square_c
# asm 1: vaddpd <r9=reg256#2,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r9=%ymm1,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm1,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r9 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r9=reg256#2,>r9=reg256#2
# asm 2: vsubpd <square_t=%ymm13,<r9=%ymm1,>r9=%ymm1
vsubpd %ymm13,%ymm1,%ymm1

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r10=reg256#13,>r10=reg256#13
# asm 2: vaddpd <square_t=%ymm13,<r10=%ymm12,>r10=%ymm12
vaddpd %ymm13,%ymm12,%ymm12

# qhasm:   square_c aligned= mem256[alpha64]
# asm 1: vmovapd alpha64,>square_c=reg256#14
# asm 2: vmovapd alpha64,>square_c=%ymm13
vmovapd alpha64,%ymm13

# qhasm:   4x square_t = approx r2 +square_c
# asm 1: vaddpd <r2=reg256#6,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r2=%ymm5,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm5,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r2 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r2=reg256#6,>r2=reg256#6
# asm 2: vsubpd <square_t=%ymm13,<r2=%ymm5,>r2=%ymm5
vsubpd %ymm13,%ymm5,%ymm5

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm13,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm13,%ymm6,%ymm6

# qhasm:   square_c aligned= mem256[alpha149]
# asm 1: vmovapd alpha149,>square_c=reg256#14
# asm 2: vmovapd alpha149,>square_c=%ymm13
vmovapd alpha149,%ymm13

# qhasm:   4x square_t = approx r6 +square_c
# asm 1: vaddpd <r6=reg256#10,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r6=%ymm9,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm9,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r6 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r6=reg256#10,>r6=reg256#10
# asm 2: vsubpd <square_t=%ymm13,<r6=%ymm9,>r6=%ymm9
vsubpd %ymm13,%ymm9,%ymm9

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm13,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm13,%ymm10,%ymm10

# qhasm:   square_c aligned= mem256[alpha234]
# asm 1: vmovapd alpha234,>square_c=reg256#14
# asm 2: vmovapd alpha234,>square_c=%ymm13
vmovapd alpha234,%ymm13

# qhasm:   4x square_t = approx r10 +square_c
# asm 1: vaddpd <r10=reg256#13,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r10=%ymm12,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm12,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r10 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r10=reg256#13,>r10=reg256#13
# asm 2: vsubpd <square_t=%ymm13,<r10=%ymm12,>r10=%ymm12
vsubpd %ymm13,%ymm12,%ymm12

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm13,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm13,%ymm2,%ymm2

# qhasm:   square_c aligned= mem256[alpha85]
# asm 1: vmovapd alpha85,>square_c=reg256#14
# asm 2: vmovapd alpha85,>square_c=%ymm13
vmovapd alpha85,%ymm13

# qhasm:   4x square_t = approx r3 +square_c
# asm 1: vaddpd <r3=reg256#7,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r3=%ymm6,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm6,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r3 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r3=reg256#7,>r3=reg256#7
# asm 2: vsubpd <square_t=%ymm13,<r3=%ymm6,>r3=%ymm6
vsubpd %ymm13,%ymm6,%ymm6

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm13,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm13,%ymm7,%ymm7

# qhasm:   square_c aligned= mem256[alpha170]
# asm 1: vmovapd alpha170,>square_c=reg256#14
# asm 2: vmovapd alpha170,>square_c=%ymm13
vmovapd alpha170,%ymm13

# qhasm:   4x square_t = approx r7 +square_c
# asm 1: vaddpd <r7=reg256#11,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r7=%ymm10,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm10,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r7 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r7=reg256#11,>r7=reg256#11
# asm 2: vsubpd <square_t=%ymm13,<r7=%ymm10,>r7=%ymm10
vsubpd %ymm13,%ymm10,%ymm10

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm13,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm13,%ymm11,%ymm11

# qhasm:   square_c aligned= mem256[alpha255]
# asm 1: vmovapd alpha255,>square_c=reg256#14
# asm 2: vmovapd alpha255,>square_c=%ymm13
vmovapd alpha255,%ymm13

# qhasm:   4x square_t = approx r11 +square_c
# asm 1: vaddpd <r11=reg256#3,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r11=%ymm2,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm2,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r11 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r11=reg256#3,>r11=reg256#3
# asm 2: vsubpd <square_t=%ymm13,<r11=%ymm2,>r11=%ymm2
vsubpd %ymm13,%ymm2,%ymm2

# qhasm:   4x square_t approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_t=reg256#14,>square_t=reg256#1
# asm 2: vmulpd <square_nineteen=%ymm0,<square_t=%ymm13,>square_t=%ymm0
vmulpd %ymm0,%ymm13,%ymm0

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#1,<r0=reg256#4,>r0=reg256#1
# asm 2: vaddpd <square_t=%ymm0,<r0=%ymm3,>r0=%ymm0
vaddpd %ymm0,%ymm3,%ymm0

# qhasm:   square_c aligned= mem256[alpha22]
# asm 1: vmovapd alpha22,>square_c=reg256#4
# asm 2: vmovapd alpha22,>square_c=%ymm3
vmovapd alpha22,%ymm3

# qhasm:   4x square_t = approx r0 +square_c
# asm 1: vaddpd <r0=reg256#1,<square_c=reg256#4,>square_t=reg256#14
# asm 2: vaddpd <r0=%ymm0,<square_c=%ymm3,>square_t=%ymm13
vaddpd %ymm0,%ymm3,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#4,<square_t=reg256#14,>square_t=reg256#4
# asm 2: vsubpd <square_c=%ymm3,<square_t=%ymm13,>square_t=%ymm3
vsubpd %ymm3,%ymm13,%ymm3

# qhasm:   4x r0 approx-= square_t
# asm 1: vsubpd <square_t=reg256#4,<r0=reg256#1,>r0=reg256#1
# asm 2: vsubpd <square_t=%ymm3,<r0=%ymm0,>r0=%ymm0
vsubpd %ymm3,%ymm0,%ymm0

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#4,<r1=reg256#5,>r1=reg256#4
# asm 2: vaddpd <square_t=%ymm3,<r1=%ymm4,>r1=%ymm3
vaddpd %ymm3,%ymm4,%ymm3

# qhasm:   square_c aligned= mem256[alpha107]
# asm 1: vmovapd alpha107,>square_c=reg256#5
# asm 2: vmovapd alpha107,>square_c=%ymm4
vmovapd alpha107,%ymm4

# qhasm:   4x square_t = approx r4 +square_c
# asm 1: vaddpd <r4=reg256#8,<square_c=reg256#5,>square_t=reg256#14
# asm 2: vaddpd <r4=%ymm7,<square_c=%ymm4,>square_t=%ymm13
vaddpd %ymm7,%ymm4,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#5,<square_t=reg256#14,>square_t=reg256#5
# asm 2: vsubpd <square_c=%ymm4,<square_t=%ymm13,>square_t=%ymm4
vsubpd %ymm4,%ymm13,%ymm4

# qhasm:   4x r4 approx-= square_t
# asm 1: vsubpd <square_t=reg256#5,<r4=reg256#8,>r4=reg256#8
# asm 2: vsubpd <square_t=%ymm4,<r4=%ymm7,>r4=%ymm7
vsubpd %ymm4,%ymm7,%ymm7

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#5,<r5=reg256#9,>r5=reg256#5
# asm 2: vaddpd <square_t=%ymm4,<r5=%ymm8,>r5=%ymm4
vaddpd %ymm4,%ymm8,%ymm4

# qhasm:   square_c aligned= mem256[alpha192]
# asm 1: vmovapd alpha192,>square_c=reg256#9
# asm 2: vmovapd alpha192,>square_c=%ymm8
vmovapd alpha192,%ymm8

# qhasm:   4x square_t = approx r8 +square_c
# asm 1: vaddpd <r8=reg256#12,<square_c=reg256#9,>square_t=reg256#14
# asm 2: vaddpd <r8=%ymm11,<square_c=%ymm8,>square_t=%ymm13
vaddpd %ymm11,%ymm8,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#9,<square_t=reg256#14,>square_t=reg256#9
# asm 2: vsubpd <square_c=%ymm8,<square_t=%ymm13,>square_t=%ymm8
vsubpd %ymm8,%ymm13,%ymm8

# qhasm:   4x r8 approx-= square_t
# asm 1: vsubpd <square_t=reg256#9,<r8=reg256#12,>r8=reg256#12
# asm 2: vsubpd <square_t=%ymm8,<r8=%ymm11,>r8=%ymm11
vsubpd %ymm8,%ymm11,%ymm11

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#9,<r9=reg256#2,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm8,<r9=%ymm1,>r9=%ymm1
vaddpd %ymm8,%ymm1,%ymm1

# qhasm: 4x s = approx r0 - mem256[input_0 + 0]
# asm 1: vsubpd 0(<input_0=int64#1),<r0=reg256#1,>s=reg256#9
# asm 2: vsubpd 0(<input_0=%rdi),<r0=%ymm0,>s=%ymm8
vsubpd 0(%rdi),%ymm0,%ymm8

# qhasm: mem256[input_0 + 768] aligned= s
# asm 1: vmovapd   <s=reg256#9,768(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,768(<input_0=%rdi)
vmovapd   %ymm8,768(%rdi)

# qhasm: 4x s = approx r1 - mem256[input_0 + 32]
# asm 1: vsubpd 32(<input_0=int64#1),<r1=reg256#4,>s=reg256#9
# asm 2: vsubpd 32(<input_0=%rdi),<r1=%ymm3,>s=%ymm8
vsubpd 32(%rdi),%ymm3,%ymm8

# qhasm: mem256[input_0 + 800] aligned= s
# asm 1: vmovapd   <s=reg256#9,800(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,800(<input_0=%rdi)
vmovapd   %ymm8,800(%rdi)

# qhasm: 4x s = approx r2 - mem256[input_0 + 64]
# asm 1: vsubpd 64(<input_0=int64#1),<r2=reg256#6,>s=reg256#9
# asm 2: vsubpd 64(<input_0=%rdi),<r2=%ymm5,>s=%ymm8
vsubpd 64(%rdi),%ymm5,%ymm8

# qhasm: mem256[input_0 + 832] aligned= s
# asm 1: vmovapd   <s=reg256#9,832(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,832(<input_0=%rdi)
vmovapd   %ymm8,832(%rdi)

# qhasm: 4x s = approx r3 - mem256[input_0 + 96]
# asm 1: vsubpd 96(<input_0=int64#1),<r3=reg256#7,>s=reg256#9
# asm 2: vsubpd 96(<input_0=%rdi),<r3=%ymm6,>s=%ymm8
vsubpd 96(%rdi),%ymm6,%ymm8

# qhasm: mem256[input_0 + 864] aligned= s
# asm 1: vmovapd   <s=reg256#9,864(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,864(<input_0=%rdi)
vmovapd   %ymm8,864(%rdi)

# qhasm: 4x s = approx r4 - mem256[input_0 + 128]
# asm 1: vsubpd 128(<input_0=int64#1),<r4=reg256#8,>s=reg256#9
# asm 2: vsubpd 128(<input_0=%rdi),<r4=%ymm7,>s=%ymm8
vsubpd 128(%rdi),%ymm7,%ymm8

# qhasm: mem256[input_0 + 896] aligned= s
# asm 1: vmovapd   <s=reg256#9,896(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,896(<input_0=%rdi)
vmovapd   %ymm8,896(%rdi)

# qhasm: 4x s = approx r5 - mem256[input_0 + 160]
# asm 1: vsubpd 160(<input_0=int64#1),<r5=reg256#5,>s=reg256#9
# asm 2: vsubpd 160(<input_0=%rdi),<r5=%ymm4,>s=%ymm8
vsubpd 160(%rdi),%ymm4,%ymm8

# qhasm: mem256[input_0 + 928] aligned= s
# asm 1: vmovapd   <s=reg256#9,928(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,928(<input_0=%rdi)
vmovapd   %ymm8,928(%rdi)

# qhasm: 4x s = approx r6 - mem256[input_0 + 192]
# asm 1: vsubpd 192(<input_0=int64#1),<r6=reg256#10,>s=reg256#9
# asm 2: vsubpd 192(<input_0=%rdi),<r6=%ymm9,>s=%ymm8
vsubpd 192(%rdi),%ymm9,%ymm8

# qhasm: mem256[input_0 + 960] aligned= s
# asm 1: vmovapd   <s=reg256#9,960(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,960(<input_0=%rdi)
vmovapd   %ymm8,960(%rdi)

# qhasm: 4x s = approx r7 - mem256[input_0 + 224]
# asm 1: vsubpd 224(<input_0=int64#1),<r7=reg256#11,>s=reg256#9
# asm 2: vsubpd 224(<input_0=%rdi),<r7=%ymm10,>s=%ymm8
vsubpd 224(%rdi),%ymm10,%ymm8

# qhasm: mem256[input_0 + 992] aligned= s
# asm 1: vmovapd   <s=reg256#9,992(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,992(<input_0=%rdi)
vmovapd   %ymm8,992(%rdi)

# qhasm: 4x s = approx r8 - mem256[input_0 + 256]
# asm 1: vsubpd 256(<input_0=int64#1),<r8=reg256#12,>s=reg256#9
# asm 2: vsubpd 256(<input_0=%rdi),<r8=%ymm11,>s=%ymm8
vsubpd 256(%rdi),%ymm11,%ymm8

# qhasm: mem256[input_0 + 1024] aligned= s
# asm 1: vmovapd   <s=reg256#9,1024(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,1024(<input_0=%rdi)
vmovapd   %ymm8,1024(%rdi)

# qhasm: 4x s = approx r9 - mem256[input_0 + 288]
# asm 1: vsubpd 288(<input_0=int64#1),<r9=reg256#2,>s=reg256#9
# asm 2: vsubpd 288(<input_0=%rdi),<r9=%ymm1,>s=%ymm8
vsubpd 288(%rdi),%ymm1,%ymm8

# qhasm: mem256[input_0 + 1056] aligned= s
# asm 1: vmovapd   <s=reg256#9,1056(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,1056(<input_0=%rdi)
vmovapd   %ymm8,1056(%rdi)

# qhasm: 4x s = approx r10 - mem256[input_0 + 320]
# asm 1: vsubpd 320(<input_0=int64#1),<r10=reg256#13,>s=reg256#9
# asm 2: vsubpd 320(<input_0=%rdi),<r10=%ymm12,>s=%ymm8
vsubpd 320(%rdi),%ymm12,%ymm8

# qhasm: mem256[input_0 + 1088] aligned= s
# asm 1: vmovapd   <s=reg256#9,1088(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,1088(<input_0=%rdi)
vmovapd   %ymm8,1088(%rdi)

# qhasm: 4x s = approx r11 - mem256[input_0 + 352]
# asm 1: vsubpd 352(<input_0=int64#1),<r11=reg256#3,>s=reg256#9
# asm 2: vsubpd 352(<input_0=%rdi),<r11=%ymm2,>s=%ymm8
vsubpd 352(%rdi),%ymm2,%ymm8

# qhasm: mem256[input_0 + 1120] aligned= s
# asm 1: vmovapd   <s=reg256#9,1120(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm8,1120(<input_0=%rdi)
vmovapd   %ymm8,1120(%rdi)

# qhasm: 4x s = approx r0 + mem256[input_0 + 0]
# asm 1: vaddpd 0(<input_0=int64#1),<r0=reg256#1,>s=reg256#1
# asm 2: vaddpd 0(<input_0=%rdi),<r0=%ymm0,>s=%ymm0
vaddpd 0(%rdi),%ymm0,%ymm0

# qhasm: mem256[input_0 + 384] aligned= s
# asm 1: vmovapd   <s=reg256#1,384(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,384(<input_0=%rdi)
vmovapd   %ymm0,384(%rdi)

# qhasm: 4x s = approx r1 + mem256[input_0 + 32]
# asm 1: vaddpd 32(<input_0=int64#1),<r1=reg256#4,>s=reg256#1
# asm 2: vaddpd 32(<input_0=%rdi),<r1=%ymm3,>s=%ymm0
vaddpd 32(%rdi),%ymm3,%ymm0

# qhasm: mem256[input_0 + 416] aligned= s
# asm 1: vmovapd   <s=reg256#1,416(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,416(<input_0=%rdi)
vmovapd   %ymm0,416(%rdi)

# qhasm: 4x s = approx r2 + mem256[input_0 + 64]
# asm 1: vaddpd 64(<input_0=int64#1),<r2=reg256#6,>s=reg256#1
# asm 2: vaddpd 64(<input_0=%rdi),<r2=%ymm5,>s=%ymm0
vaddpd 64(%rdi),%ymm5,%ymm0

# qhasm: mem256[input_0 + 448] aligned= s
# asm 1: vmovapd   <s=reg256#1,448(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,448(<input_0=%rdi)
vmovapd   %ymm0,448(%rdi)

# qhasm: 4x s = approx r3 + mem256[input_0 + 96]
# asm 1: vaddpd 96(<input_0=int64#1),<r3=reg256#7,>s=reg256#1
# asm 2: vaddpd 96(<input_0=%rdi),<r3=%ymm6,>s=%ymm0
vaddpd 96(%rdi),%ymm6,%ymm0

# qhasm: mem256[input_0 + 480] aligned= s
# asm 1: vmovapd   <s=reg256#1,480(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,480(<input_0=%rdi)
vmovapd   %ymm0,480(%rdi)

# qhasm: 4x s = approx r4 + mem256[input_0 + 128]
# asm 1: vaddpd 128(<input_0=int64#1),<r4=reg256#8,>s=reg256#1
# asm 2: vaddpd 128(<input_0=%rdi),<r4=%ymm7,>s=%ymm0
vaddpd 128(%rdi),%ymm7,%ymm0

# qhasm: mem256[input_0 + 512] aligned= s
# asm 1: vmovapd   <s=reg256#1,512(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,512(<input_0=%rdi)
vmovapd   %ymm0,512(%rdi)

# qhasm: 4x s = approx r5 + mem256[input_0 + 160]
# asm 1: vaddpd 160(<input_0=int64#1),<r5=reg256#5,>s=reg256#1
# asm 2: vaddpd 160(<input_0=%rdi),<r5=%ymm4,>s=%ymm0
vaddpd 160(%rdi),%ymm4,%ymm0

# qhasm: mem256[input_0 + 544] aligned= s
# asm 1: vmovapd   <s=reg256#1,544(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,544(<input_0=%rdi)
vmovapd   %ymm0,544(%rdi)

# qhasm: 4x s = approx r6 + mem256[input_0 + 192]
# asm 1: vaddpd 192(<input_0=int64#1),<r6=reg256#10,>s=reg256#1
# asm 2: vaddpd 192(<input_0=%rdi),<r6=%ymm9,>s=%ymm0
vaddpd 192(%rdi),%ymm9,%ymm0

# qhasm: mem256[input_0 + 576] aligned= s
# asm 1: vmovapd   <s=reg256#1,576(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,576(<input_0=%rdi)
vmovapd   %ymm0,576(%rdi)

# qhasm: 4x s = approx r7 + mem256[input_0 + 224]
# asm 1: vaddpd 224(<input_0=int64#1),<r7=reg256#11,>s=reg256#1
# asm 2: vaddpd 224(<input_0=%rdi),<r7=%ymm10,>s=%ymm0
vaddpd 224(%rdi),%ymm10,%ymm0

# qhasm: mem256[input_0 + 608] aligned= s
# asm 1: vmovapd   <s=reg256#1,608(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,608(<input_0=%rdi)
vmovapd   %ymm0,608(%rdi)

# qhasm: 4x s = approx r8 + mem256[input_0 + 256]
# asm 1: vaddpd 256(<input_0=int64#1),<r8=reg256#12,>s=reg256#1
# asm 2: vaddpd 256(<input_0=%rdi),<r8=%ymm11,>s=%ymm0
vaddpd 256(%rdi),%ymm11,%ymm0

# qhasm: mem256[input_0 + 640] aligned= s
# asm 1: vmovapd   <s=reg256#1,640(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,640(<input_0=%rdi)
vmovapd   %ymm0,640(%rdi)

# qhasm: 4x s = approx r9 + mem256[input_0 + 288]
# asm 1: vaddpd 288(<input_0=int64#1),<r9=reg256#2,>s=reg256#1
# asm 2: vaddpd 288(<input_0=%rdi),<r9=%ymm1,>s=%ymm0
vaddpd 288(%rdi),%ymm1,%ymm0

# qhasm: mem256[input_0 + 672] aligned= s
# asm 1: vmovapd   <s=reg256#1,672(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,672(<input_0=%rdi)
vmovapd   %ymm0,672(%rdi)

# qhasm: 4x s = approx r10 + mem256[input_0 + 320]
# asm 1: vaddpd 320(<input_0=int64#1),<r10=reg256#13,>s=reg256#1
# asm 2: vaddpd 320(<input_0=%rdi),<r10=%ymm12,>s=%ymm0
vaddpd 320(%rdi),%ymm12,%ymm0

# qhasm: mem256[input_0 + 704] aligned= s
# asm 1: vmovapd   <s=reg256#1,704(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,704(<input_0=%rdi)
vmovapd   %ymm0,704(%rdi)

# qhasm: 4x s = approx r11 + mem256[input_0 + 352]
# asm 1: vaddpd 352(<input_0=int64#1),<r11=reg256#3,>s=reg256#1
# asm 2: vaddpd 352(<input_0=%rdi),<r11=%ymm2,>s=%ymm0
vaddpd 352(%rdi),%ymm2,%ymm0

# qhasm: mem256[input_0 + 736] aligned= s
# asm 1: vmovapd   <s=reg256#1,736(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,736(<input_0=%rdi)
vmovapd   %ymm0,736(%rdi)

# qhasm:   square_nineteen aligned= mem256[scale19]
# asm 1: vmovapd scale19,>square_nineteen=reg256#1
# asm 2: vmovapd scale19,>square_nineteen=%ymm0
vmovapd scale19,%ymm0

# qhasm:   square_two aligned= mem256[two4x]
# asm 1: vmovapd two4x,>square_two=reg256#2
# asm 2: vmovapd two4x,>square_two=%ymm1
vmovapd two4x,%ymm1

# qhasm:   square_x0 aligned= mem256[input_1 + 768]
# asm 1: vmovapd   768(<input_1=int64#2),>square_x0=reg256#3
# asm 2: vmovapd   768(<input_1=%rsi),>square_x0=%ymm2
vmovapd   768(%rsi),%ymm2

# qhasm:   4x r0 = approx square_x0 * square_x0
# asm 1: vmulpd <square_x0=reg256#3,<square_x0=reg256#3,>r0=reg256#4
# asm 2: vmulpd <square_x0=%ymm2,<square_x0=%ymm2,>r0=%ymm3
vmulpd %ymm2,%ymm2,%ymm3

# qhasm:   4x square_x0 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x0=reg256#3,>square_x0=reg256#3
# asm 2: vmulpd <square_two=%ymm1,<square_x0=%ymm2,>square_x0=%ymm2
vmulpd %ymm1,%ymm2,%ymm2

# qhasm:   4x r1 = approx square_x0 * mem256[input_1 + 800]
# asm 1: vmulpd 800(<input_1=int64#2),<square_x0=reg256#3,>r1=reg256#5
# asm 2: vmulpd 800(<input_1=%rsi),<square_x0=%ymm2,>r1=%ymm4
vmulpd 800(%rsi),%ymm2,%ymm4

# qhasm:   4x r2 = approx square_x0 * mem256[input_1 + 832]
# asm 1: vmulpd 832(<input_1=int64#2),<square_x0=reg256#3,>r2=reg256#6
# asm 2: vmulpd 832(<input_1=%rsi),<square_x0=%ymm2,>r2=%ymm5
vmulpd 832(%rsi),%ymm2,%ymm5

# qhasm:   4x r3 = approx square_x0 * mem256[input_1 + 864]
# asm 1: vmulpd 864(<input_1=int64#2),<square_x0=reg256#3,>r3=reg256#7
# asm 2: vmulpd 864(<input_1=%rsi),<square_x0=%ymm2,>r3=%ymm6
vmulpd 864(%rsi),%ymm2,%ymm6

# qhasm:   4x r4 = approx square_x0 * mem256[input_1 + 896]
# asm 1: vmulpd 896(<input_1=int64#2),<square_x0=reg256#3,>r4=reg256#8
# asm 2: vmulpd 896(<input_1=%rsi),<square_x0=%ymm2,>r4=%ymm7
vmulpd 896(%rsi),%ymm2,%ymm7

# qhasm:   4x r5 = approx square_x0 * mem256[input_1 + 928]
# asm 1: vmulpd 928(<input_1=int64#2),<square_x0=reg256#3,>r5=reg256#9
# asm 2: vmulpd 928(<input_1=%rsi),<square_x0=%ymm2,>r5=%ymm8
vmulpd 928(%rsi),%ymm2,%ymm8

# qhasm:   4x r6 = approx square_x0 * mem256[input_1 + 960]
# asm 1: vmulpd 960(<input_1=int64#2),<square_x0=reg256#3,>r6=reg256#10
# asm 2: vmulpd 960(<input_1=%rsi),<square_x0=%ymm2,>r6=%ymm9
vmulpd 960(%rsi),%ymm2,%ymm9

# qhasm:   4x r7 = approx square_x0 * mem256[input_1 + 992]
# asm 1: vmulpd 992(<input_1=int64#2),<square_x0=reg256#3,>r7=reg256#11
# asm 2: vmulpd 992(<input_1=%rsi),<square_x0=%ymm2,>r7=%ymm10
vmulpd 992(%rsi),%ymm2,%ymm10

# qhasm:   4x r8 = approx square_x0 * mem256[input_1 + 1024]
# asm 1: vmulpd 1024(<input_1=int64#2),<square_x0=reg256#3,>r8=reg256#12
# asm 2: vmulpd 1024(<input_1=%rsi),<square_x0=%ymm2,>r8=%ymm11
vmulpd 1024(%rsi),%ymm2,%ymm11

# qhasm:   4x r9 = approx square_x0 * mem256[input_1 + 1056]
# asm 1: vmulpd 1056(<input_1=int64#2),<square_x0=reg256#3,>r9=reg256#13
# asm 2: vmulpd 1056(<input_1=%rsi),<square_x0=%ymm2,>r9=%ymm12
vmulpd 1056(%rsi),%ymm2,%ymm12

# qhasm:   4x r10 = approx square_x0 * mem256[input_1 + 1088]
# asm 1: vmulpd 1088(<input_1=int64#2),<square_x0=reg256#3,>r10=reg256#14
# asm 2: vmulpd 1088(<input_1=%rsi),<square_x0=%ymm2,>r10=%ymm13
vmulpd 1088(%rsi),%ymm2,%ymm13

# qhasm:   4x r11 = approx square_x0 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x0=reg256#3,>r11=reg256#3
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x0=%ymm2,>r11=%ymm2
vmulpd 1120(%rsi),%ymm2,%ymm2

# qhasm:   square_x1 aligned= mem256[input_1 + 800]
# asm 1: vmovapd   800(<input_1=int64#2),>square_x1=reg256#15
# asm 2: vmovapd   800(<input_1=%rsi),>square_x1=%ymm14
vmovapd   800(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x1 * square_x1
# asm 1: vmulpd <square_x1=reg256#15,<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x1=%ymm14,<square_x1=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_x1 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x1=reg256#15,>square_x1=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x1=%ymm14,>square_x1=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 832]
# asm 1: vmulpd 832(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 832(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 832(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 864]
# asm 1: vmulpd 864(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 864(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 864(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 896]
# asm 1: vmulpd 896(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 896(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 896(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 928]
# asm 1: vmulpd 928(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 928(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 928(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 960]
# asm 1: vmulpd 960(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 960(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 960(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 992]
# asm 1: vmulpd 992(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 992(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 992(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 1024]
# asm 1: vmulpd 1024(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1024(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 1024(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 1056]
# asm 1: vmulpd 1056(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1056(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 1056(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 1088]
# asm 1: vmulpd 1088(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1088(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 1088(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x1 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x1=reg256#15,>square_x1=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x1=%ymm14,>square_x1=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x1 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x1=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x1=%ymm14,>square_t=%ymm14
vmulpd 1120(%rsi),%ymm14,%ymm14

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   square_x2 aligned= mem256[input_1 + 832]
# asm 1: vmovapd   832(<input_1=int64#2),>square_x2=reg256#15
# asm 2: vmovapd   832(<input_1=%rsi),>square_x2=%ymm14
vmovapd   832(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x2 * square_x2
# asm 1: vmulpd <square_x2=reg256#15,<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x2=%ymm14,<square_x2=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_x2 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x2=reg256#15,>square_x2=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x2=%ymm14,>square_x2=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 864]
# asm 1: vmulpd 864(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 864(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 864(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 896]
# asm 1: vmulpd 896(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 896(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 896(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 928]
# asm 1: vmulpd 928(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 928(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 928(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 960]
# asm 1: vmulpd 960(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 960(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 960(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 992]
# asm 1: vmulpd 992(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 992(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 992(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 1024]
# asm 1: vmulpd 1024(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1024(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 1024(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 1056]
# asm 1: vmulpd 1056(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1056(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 1056(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x2 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x2=reg256#15,>square_x2=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x2=%ymm14,>square_x2=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 1088]
# asm 1: vmulpd 1088(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1088(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 1088(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x2 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x2=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x2=%ymm14,>square_t=%ymm14
vmulpd 1120(%rsi),%ymm14,%ymm14

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   square_x3 aligned= mem256[input_1 + 864]
# asm 1: vmovapd   864(<input_1=int64#2),>square_x3=reg256#15
# asm 2: vmovapd   864(<input_1=%rsi),>square_x3=%ymm14
vmovapd   864(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x3 * square_x3
# asm 1: vmulpd <square_x3=reg256#15,<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x3=%ymm14,<square_x3=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_x3 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x3=reg256#15,>square_x3=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x3=%ymm14,>square_x3=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 896]
# asm 1: vmulpd 896(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 896(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 896(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 928]
# asm 1: vmulpd 928(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 928(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 928(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 960]
# asm 1: vmulpd 960(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 960(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 960(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 992]
# asm 1: vmulpd 992(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 992(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 992(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 1024]
# asm 1: vmulpd 1024(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1024(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 1024(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x3 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x3=reg256#15,>square_x3=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x3=%ymm14,>square_x3=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 1056]
# asm 1: vmulpd 1056(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1056(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 1056(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 1088]
# asm 1: vmulpd 1088(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1088(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 1088(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x3 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x3=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x3=%ymm14,>square_t=%ymm14
vmulpd 1120(%rsi),%ymm14,%ymm14

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   square_x4 aligned= mem256[input_1 + 896]
# asm 1: vmovapd   896(<input_1=int64#2),>square_x4=reg256#15
# asm 2: vmovapd   896(<input_1=%rsi),>square_x4=%ymm14
vmovapd   896(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x4 * square_x4
# asm 1: vmulpd <square_x4=reg256#15,<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x4=%ymm14,<square_x4=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_x4 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x4=reg256#15,>square_x4=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x4=%ymm14,>square_x4=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 928]
# asm 1: vmulpd 928(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 928(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 928(%rsi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 960]
# asm 1: vmulpd 960(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 960(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 960(%rsi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 992]
# asm 1: vmulpd 992(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 992(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 992(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x4 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x4=reg256#15,>square_x4=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x4=%ymm14,>square_x4=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 1024]
# asm 1: vmulpd 1024(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1024(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 1024(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 1056]
# asm 1: vmulpd 1056(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1056(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 1056(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 1088]
# asm 1: vmulpd 1088(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1088(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 1088(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x4 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x4=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x4=%ymm14,>square_t=%ymm14
vmulpd 1120(%rsi),%ymm14,%ymm14

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   square_x5 aligned= mem256[input_1 + 928]
# asm 1: vmovapd   928(<input_1=int64#2),>square_x5=reg256#15
# asm 2: vmovapd   928(<input_1=%rsi),>square_x5=%ymm14
vmovapd   928(%rsi),%ymm14

# qhasm:   4x square_t = approx square_x5 * square_x5
# asm 1: vmulpd <square_x5=reg256#15,<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x5=%ymm14,<square_x5=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_x5 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x5=reg256#15,>square_x5=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x5=%ymm14,>square_x5=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 960]
# asm 1: vmulpd 960(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 960(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 960(%rsi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x5 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x5=reg256#15,>square_x5=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x5=%ymm14,>square_x5=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 992]
# asm 1: vmulpd 992(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 992(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 992(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 1024]
# asm 1: vmulpd 1024(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1024(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 1024(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 1056]
# asm 1: vmulpd 1056(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1056(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 1056(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 1088]
# asm 1: vmulpd 1088(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1088(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 1088(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x5 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x5=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x5=%ymm14,>square_t=%ymm14
vmulpd 1120(%rsi),%ymm14,%ymm14

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   square_x6 aligned= mem256[input_1 + 960]
# asm 1: vmovapd   960(<input_1=int64#2),>square_x6=reg256#15
# asm 2: vmovapd   960(<input_1=%rsi),>square_x6=%ymm14
vmovapd   960(%rsi),%ymm14

# qhasm:   4x square_x6 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x6=reg256#15,>square_x6=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x6=%ymm14,>square_x6=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 960]
# asm 1: vmulpd 960(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 960(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 960(%rsi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_x6 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x6=reg256#15,>square_x6=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x6=%ymm14,>square_x6=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 992]
# asm 1: vmulpd 992(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 992(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 992(%rsi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 1024]
# asm 1: vmulpd 1024(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1024(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 1024(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 1056]
# asm 1: vmulpd 1056(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1056(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 1056(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 1088]
# asm 1: vmulpd 1088(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1088(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 1088(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x6 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x6=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x6=%ymm14,>square_t=%ymm14
vmulpd 1120(%rsi),%ymm14,%ymm14

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   square_x7 aligned= mem256[input_1 + 992]
# asm 1: vmovapd   992(<input_1=int64#2),>square_x7=reg256#15
# asm 2: vmovapd   992(<input_1=%rsi),>square_x7=%ymm14
vmovapd   992(%rsi),%ymm14

# qhasm:   4x square_x7 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x7=reg256#15,>square_x7=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x7=%ymm14,>square_x7=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 992]
# asm 1: vmulpd 992(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 992(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 992(%rsi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_x7 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x7=reg256#15,>square_x7=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x7=%ymm14,>square_x7=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 1024]
# asm 1: vmulpd 1024(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1024(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 1024(%rsi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 1056]
# asm 1: vmulpd 1056(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1056(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 1056(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 1088]
# asm 1: vmulpd 1088(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1088(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 1088(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x7 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x7=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x7=%ymm14,>square_t=%ymm14
vmulpd 1120(%rsi),%ymm14,%ymm14

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   square_x8 aligned= mem256[input_1 + 1024]
# asm 1: vmovapd   1024(<input_1=int64#2),>square_x8=reg256#15
# asm 2: vmovapd   1024(<input_1=%rsi),>square_x8=%ymm14
vmovapd   1024(%rsi),%ymm14

# qhasm:   4x square_x8 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x8=reg256#15,>square_x8=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x8=%ymm14,>square_x8=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 1024]
# asm 1: vmulpd 1024(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1024(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 1024(%rsi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_x8 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x8=reg256#15,>square_x8=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x8=%ymm14,>square_x8=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 1056]
# asm 1: vmulpd 1056(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1056(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 1056(%rsi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 1088]
# asm 1: vmulpd 1088(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1088(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 1088(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x8 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x8=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x8=%ymm14,>square_t=%ymm14
vmulpd 1120(%rsi),%ymm14,%ymm14

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   square_x9 aligned= mem256[input_1 + 1056]
# asm 1: vmovapd   1056(<input_1=int64#2),>square_x9=reg256#15
# asm 2: vmovapd   1056(<input_1=%rsi),>square_x9=%ymm14
vmovapd   1056(%rsi),%ymm14

# qhasm:   4x square_x9 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x9=reg256#15,>square_x9=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x9=%ymm14,>square_x9=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x9 * mem256[input_1 + 1056]
# asm 1: vmulpd 1056(<input_1=int64#2),<square_x9=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1056(<input_1=%rsi),<square_x9=%ymm14,>square_t=%ymm15
vmulpd 1056(%rsi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_x9 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x9=reg256#15,>square_x9=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x9=%ymm14,>square_x9=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x9 * mem256[input_1 + 1088]
# asm 1: vmulpd 1088(<input_1=int64#2),<square_x9=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1088(<input_1=%rsi),<square_x9=%ymm14,>square_t=%ymm15
vmulpd 1088(%rsi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x9 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x9=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x9=%ymm14,>square_t=%ymm14
vmulpd 1120(%rsi),%ymm14,%ymm14

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   square_x10 aligned= mem256[input_1 + 1088]
# asm 1: vmovapd   1088(<input_1=int64#2),>square_x10=reg256#15
# asm 2: vmovapd   1088(<input_1=%rsi),>square_x10=%ymm14
vmovapd   1088(%rsi),%ymm14

# qhasm:   4x square_x10 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x10=reg256#15,>square_x10=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x10=%ymm14,>square_x10=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x10 * mem256[input_1 + 1088]
# asm 1: vmulpd 1088(<input_1=int64#2),<square_x10=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 1088(<input_1=%rsi),<square_x10=%ymm14,>square_t=%ymm15
vmulpd 1088(%rsi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_x10 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x10=reg256#15,>square_x10=reg256#2
# asm 2: vmulpd <square_two=%ymm1,<square_x10=%ymm14,>square_x10=%ymm1
vmulpd %ymm1,%ymm14,%ymm1

# qhasm:   4x square_t = approx square_x10 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x10=reg256#2,>square_t=reg256#2
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x10=%ymm1,>square_t=%ymm1
vmulpd 1120(%rsi),%ymm1,%ymm1

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#2,<r9=reg256#13,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm1,<r9=%ymm12,>r9=%ymm1
vaddpd %ymm1,%ymm12,%ymm1

# qhasm:   square_x11 aligned= mem256[input_1 + 1120]
# asm 1: vmovapd   1120(<input_1=int64#2),>square_x11=reg256#13
# asm 2: vmovapd   1120(<input_1=%rsi),>square_x11=%ymm12
vmovapd   1120(%rsi),%ymm12

# qhasm:   4x square_x11 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x11=reg256#13,>square_x11=reg256#13
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x11=%ymm12,>square_x11=%ymm12
vmulpd %ymm0,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x11 * mem256[input_1 + 1120]
# asm 1: vmulpd 1120(<input_1=int64#2),<square_x11=reg256#13,>square_t=reg256#13
# asm 2: vmulpd 1120(<input_1=%rsi),<square_x11=%ymm12,>square_t=%ymm12
vmulpd 1120(%rsi),%ymm12,%ymm12

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#13,<r10=reg256#14,>r10=reg256#13
# asm 2: vaddpd <square_t=%ymm12,<r10=%ymm13,>r10=%ymm12
vaddpd %ymm12,%ymm13,%ymm12

# qhasm:   square_c aligned= mem256[alpha22]
# asm 1: vmovapd alpha22,>square_c=reg256#14
# asm 2: vmovapd alpha22,>square_c=%ymm13
vmovapd alpha22,%ymm13

# qhasm:   4x square_t = approx r0 +square_c
# asm 1: vaddpd <r0=reg256#4,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r0=%ymm3,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm3,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r0 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r0=reg256#4,>r0=reg256#4
# asm 2: vsubpd <square_t=%ymm13,<r0=%ymm3,>r0=%ymm3
vsubpd %ymm13,%ymm3,%ymm3

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm13,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm13,%ymm4,%ymm4

# qhasm:   square_c aligned= mem256[alpha107]
# asm 1: vmovapd alpha107,>square_c=reg256#14
# asm 2: vmovapd alpha107,>square_c=%ymm13
vmovapd alpha107,%ymm13

# qhasm:   4x square_t = approx r4 +square_c
# asm 1: vaddpd <r4=reg256#8,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r4=%ymm7,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm7,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r4 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r4=reg256#8,>r4=reg256#8
# asm 2: vsubpd <square_t=%ymm13,<r4=%ymm7,>r4=%ymm7
vsubpd %ymm13,%ymm7,%ymm7

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm13,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm13,%ymm8,%ymm8

# qhasm:   square_c aligned= mem256[alpha192]
# asm 1: vmovapd alpha192,>square_c=reg256#14
# asm 2: vmovapd alpha192,>square_c=%ymm13
vmovapd alpha192,%ymm13

# qhasm:   4x square_t = approx r8 +square_c
# asm 1: vaddpd <r8=reg256#12,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r8=%ymm11,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm11,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r8 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r8=reg256#12,>r8=reg256#12
# asm 2: vsubpd <square_t=%ymm13,<r8=%ymm11,>r8=%ymm11
vsubpd %ymm13,%ymm11,%ymm11

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r9=reg256#2,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm13,<r9=%ymm1,>r9=%ymm1
vaddpd %ymm13,%ymm1,%ymm1

# qhasm:   square_c aligned= mem256[alpha43]
# asm 1: vmovapd alpha43,>square_c=reg256#14
# asm 2: vmovapd alpha43,>square_c=%ymm13
vmovapd alpha43,%ymm13

# qhasm:   4x square_t = approx r1 +square_c
# asm 1: vaddpd <r1=reg256#5,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r1=%ymm4,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm4,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r1 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r1=reg256#5,>r1=reg256#5
# asm 2: vsubpd <square_t=%ymm13,<r1=%ymm4,>r1=%ymm4
vsubpd %ymm13,%ymm4,%ymm4

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm13,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm13,%ymm5,%ymm5

# qhasm:   square_c aligned= mem256[alpha128]
# asm 1: vmovapd alpha128,>square_c=reg256#14
# asm 2: vmovapd alpha128,>square_c=%ymm13
vmovapd alpha128,%ymm13

# qhasm:   4x square_t = approx r5 +square_c
# asm 1: vaddpd <r5=reg256#9,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r5=%ymm8,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm8,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r5 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r5=reg256#9,>r5=reg256#9
# asm 2: vsubpd <square_t=%ymm13,<r5=%ymm8,>r5=%ymm8
vsubpd %ymm13,%ymm8,%ymm8

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm13,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm13,%ymm9,%ymm9

# qhasm:   square_c aligned= mem256[alpha213]
# asm 1: vmovapd alpha213,>square_c=reg256#14
# asm 2: vmovapd alpha213,>square_c=%ymm13
vmovapd alpha213,%ymm13

# qhasm:   4x square_t = approx r9 +square_c
# asm 1: vaddpd <r9=reg256#2,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r9=%ymm1,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm1,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r9 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r9=reg256#2,>r9=reg256#2
# asm 2: vsubpd <square_t=%ymm13,<r9=%ymm1,>r9=%ymm1
vsubpd %ymm13,%ymm1,%ymm1

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r10=reg256#13,>r10=reg256#13
# asm 2: vaddpd <square_t=%ymm13,<r10=%ymm12,>r10=%ymm12
vaddpd %ymm13,%ymm12,%ymm12

# qhasm:   square_c aligned= mem256[alpha64]
# asm 1: vmovapd alpha64,>square_c=reg256#14
# asm 2: vmovapd alpha64,>square_c=%ymm13
vmovapd alpha64,%ymm13

# qhasm:   4x square_t = approx r2 +square_c
# asm 1: vaddpd <r2=reg256#6,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r2=%ymm5,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm5,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r2 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r2=reg256#6,>r2=reg256#6
# asm 2: vsubpd <square_t=%ymm13,<r2=%ymm5,>r2=%ymm5
vsubpd %ymm13,%ymm5,%ymm5

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm13,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm13,%ymm6,%ymm6

# qhasm:   square_c aligned= mem256[alpha149]
# asm 1: vmovapd alpha149,>square_c=reg256#14
# asm 2: vmovapd alpha149,>square_c=%ymm13
vmovapd alpha149,%ymm13

# qhasm:   4x square_t = approx r6 +square_c
# asm 1: vaddpd <r6=reg256#10,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r6=%ymm9,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm9,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r6 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r6=reg256#10,>r6=reg256#10
# asm 2: vsubpd <square_t=%ymm13,<r6=%ymm9,>r6=%ymm9
vsubpd %ymm13,%ymm9,%ymm9

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm13,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm13,%ymm10,%ymm10

# qhasm:   square_c aligned= mem256[alpha234]
# asm 1: vmovapd alpha234,>square_c=reg256#14
# asm 2: vmovapd alpha234,>square_c=%ymm13
vmovapd alpha234,%ymm13

# qhasm:   4x square_t = approx r10 +square_c
# asm 1: vaddpd <r10=reg256#13,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r10=%ymm12,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm12,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r10 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r10=reg256#13,>r10=reg256#13
# asm 2: vsubpd <square_t=%ymm13,<r10=%ymm12,>r10=%ymm12
vsubpd %ymm13,%ymm12,%ymm12

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm13,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm13,%ymm2,%ymm2

# qhasm:   square_c aligned= mem256[alpha85]
# asm 1: vmovapd alpha85,>square_c=reg256#14
# asm 2: vmovapd alpha85,>square_c=%ymm13
vmovapd alpha85,%ymm13

# qhasm:   4x square_t = approx r3 +square_c
# asm 1: vaddpd <r3=reg256#7,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r3=%ymm6,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm6,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r3 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r3=reg256#7,>r3=reg256#7
# asm 2: vsubpd <square_t=%ymm13,<r3=%ymm6,>r3=%ymm6
vsubpd %ymm13,%ymm6,%ymm6

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm13,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm13,%ymm7,%ymm7

# qhasm:   square_c aligned= mem256[alpha170]
# asm 1: vmovapd alpha170,>square_c=reg256#14
# asm 2: vmovapd alpha170,>square_c=%ymm13
vmovapd alpha170,%ymm13

# qhasm:   4x square_t = approx r7 +square_c
# asm 1: vaddpd <r7=reg256#11,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r7=%ymm10,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm10,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r7 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r7=reg256#11,>r7=reg256#11
# asm 2: vsubpd <square_t=%ymm13,<r7=%ymm10,>r7=%ymm10
vsubpd %ymm13,%ymm10,%ymm10

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm13,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm13,%ymm11,%ymm11

# qhasm:   square_c aligned= mem256[alpha255]
# asm 1: vmovapd alpha255,>square_c=reg256#14
# asm 2: vmovapd alpha255,>square_c=%ymm13
vmovapd alpha255,%ymm13

# qhasm:   4x square_t = approx r11 +square_c
# asm 1: vaddpd <r11=reg256#3,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r11=%ymm2,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm2,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r11 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r11=reg256#3,>r11=reg256#3
# asm 2: vsubpd <square_t=%ymm13,<r11=%ymm2,>r11=%ymm2
vsubpd %ymm13,%ymm2,%ymm2

# qhasm:   4x square_t approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_t=reg256#14,>square_t=reg256#1
# asm 2: vmulpd <square_nineteen=%ymm0,<square_t=%ymm13,>square_t=%ymm0
vmulpd %ymm0,%ymm13,%ymm0

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#1,<r0=reg256#4,>r0=reg256#1
# asm 2: vaddpd <square_t=%ymm0,<r0=%ymm3,>r0=%ymm0
vaddpd %ymm0,%ymm3,%ymm0

# qhasm:   square_c aligned= mem256[alpha22]
# asm 1: vmovapd alpha22,>square_c=reg256#4
# asm 2: vmovapd alpha22,>square_c=%ymm3
vmovapd alpha22,%ymm3

# qhasm:   4x square_t = approx r0 +square_c
# asm 1: vaddpd <r0=reg256#1,<square_c=reg256#4,>square_t=reg256#14
# asm 2: vaddpd <r0=%ymm0,<square_c=%ymm3,>square_t=%ymm13
vaddpd %ymm0,%ymm3,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#4,<square_t=reg256#14,>square_t=reg256#4
# asm 2: vsubpd <square_c=%ymm3,<square_t=%ymm13,>square_t=%ymm3
vsubpd %ymm3,%ymm13,%ymm3

# qhasm:   4x r0 approx-= square_t
# asm 1: vsubpd <square_t=reg256#4,<r0=reg256#1,>r0=reg256#1
# asm 2: vsubpd <square_t=%ymm3,<r0=%ymm0,>r0=%ymm0
vsubpd %ymm3,%ymm0,%ymm0

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#4,<r1=reg256#5,>r1=reg256#4
# asm 2: vaddpd <square_t=%ymm3,<r1=%ymm4,>r1=%ymm3
vaddpd %ymm3,%ymm4,%ymm3

# qhasm:   square_c aligned= mem256[alpha107]
# asm 1: vmovapd alpha107,>square_c=reg256#5
# asm 2: vmovapd alpha107,>square_c=%ymm4
vmovapd alpha107,%ymm4

# qhasm:   4x square_t = approx r4 +square_c
# asm 1: vaddpd <r4=reg256#8,<square_c=reg256#5,>square_t=reg256#14
# asm 2: vaddpd <r4=%ymm7,<square_c=%ymm4,>square_t=%ymm13
vaddpd %ymm7,%ymm4,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#5,<square_t=reg256#14,>square_t=reg256#5
# asm 2: vsubpd <square_c=%ymm4,<square_t=%ymm13,>square_t=%ymm4
vsubpd %ymm4,%ymm13,%ymm4

# qhasm:   4x r4 approx-= square_t
# asm 1: vsubpd <square_t=reg256#5,<r4=reg256#8,>r4=reg256#8
# asm 2: vsubpd <square_t=%ymm4,<r4=%ymm7,>r4=%ymm7
vsubpd %ymm4,%ymm7,%ymm7

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#5,<r5=reg256#9,>r5=reg256#5
# asm 2: vaddpd <square_t=%ymm4,<r5=%ymm8,>r5=%ymm4
vaddpd %ymm4,%ymm8,%ymm4

# qhasm:   square_c aligned= mem256[alpha192]
# asm 1: vmovapd alpha192,>square_c=reg256#9
# asm 2: vmovapd alpha192,>square_c=%ymm8
vmovapd alpha192,%ymm8

# qhasm:   4x square_t = approx r8 +square_c
# asm 1: vaddpd <r8=reg256#12,<square_c=reg256#9,>square_t=reg256#14
# asm 2: vaddpd <r8=%ymm11,<square_c=%ymm8,>square_t=%ymm13
vaddpd %ymm11,%ymm8,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#9,<square_t=reg256#14,>square_t=reg256#9
# asm 2: vsubpd <square_c=%ymm8,<square_t=%ymm13,>square_t=%ymm8
vsubpd %ymm8,%ymm13,%ymm8

# qhasm:   4x r8 approx-= square_t
# asm 1: vsubpd <square_t=reg256#9,<r8=reg256#12,>r8=reg256#12
# asm 2: vsubpd <square_t=%ymm8,<r8=%ymm11,>r8=%ymm11
vsubpd %ymm8,%ymm11,%ymm11

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#9,<r9=reg256#2,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm8,<r9=%ymm1,>r9=%ymm1
vaddpd %ymm8,%ymm1,%ymm1

# qhasm: 4x r0 approx+= r0
# asm 1: vaddpd <r0=reg256#1,<r0=reg256#1,>r0=reg256#1
# asm 2: vaddpd <r0=%ymm0,<r0=%ymm0,>r0=%ymm0
vaddpd %ymm0,%ymm0,%ymm0

# qhasm: 4x r1 approx+= r1
# asm 1: vaddpd <r1=reg256#4,<r1=reg256#4,>r1=reg256#4
# asm 2: vaddpd <r1=%ymm3,<r1=%ymm3,>r1=%ymm3
vaddpd %ymm3,%ymm3,%ymm3

# qhasm: 4x r2 approx+= r2
# asm 1: vaddpd <r2=reg256#6,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <r2=%ymm5,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm5,%ymm5,%ymm5

# qhasm: 4x r3 approx+= r3
# asm 1: vaddpd <r3=reg256#7,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <r3=%ymm6,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm6,%ymm6,%ymm6

# qhasm: 4x r4 approx+= r4
# asm 1: vaddpd <r4=reg256#8,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <r4=%ymm7,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm7,%ymm7,%ymm7

# qhasm: 4x r5 approx+= r5
# asm 1: vaddpd <r5=reg256#5,<r5=reg256#5,>r5=reg256#5
# asm 2: vaddpd <r5=%ymm4,<r5=%ymm4,>r5=%ymm4
vaddpd %ymm4,%ymm4,%ymm4

# qhasm: 4x r6 approx+= r6
# asm 1: vaddpd <r6=reg256#10,<r6=reg256#10,>r6=reg256#9
# asm 2: vaddpd <r6=%ymm9,<r6=%ymm9,>r6=%ymm8
vaddpd %ymm9,%ymm9,%ymm8

# qhasm: 4x r7 approx+= r7
# asm 1: vaddpd <r7=reg256#11,<r7=reg256#11,>r7=reg256#10
# asm 2: vaddpd <r7=%ymm10,<r7=%ymm10,>r7=%ymm9
vaddpd %ymm10,%ymm10,%ymm9

# qhasm: 4x r8 approx+= r8
# asm 1: vaddpd <r8=reg256#12,<r8=reg256#12,>r8=reg256#11
# asm 2: vaddpd <r8=%ymm11,<r8=%ymm11,>r8=%ymm10
vaddpd %ymm11,%ymm11,%ymm10

# qhasm: 4x r9 approx+= r9
# asm 1: vaddpd <r9=reg256#2,<r9=reg256#2,>r9=reg256#2
# asm 2: vaddpd <r9=%ymm1,<r9=%ymm1,>r9=%ymm1
vaddpd %ymm1,%ymm1,%ymm1

# qhasm: 4x r10 approx+= r10
# asm 1: vaddpd <r10=reg256#13,<r10=reg256#13,>r10=reg256#12
# asm 2: vaddpd <r10=%ymm12,<r10=%ymm12,>r10=%ymm11
vaddpd %ymm12,%ymm12,%ymm11

# qhasm: 4x r11 approx+= r11
# asm 1: vaddpd <r11=reg256#3,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <r11=%ymm2,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm2,%ymm2,%ymm2

# qhasm: 4x s = approx r0 - mem256[input_0 + 768]
# asm 1: vsubpd 768(<input_0=int64#1),<r0=reg256#1,>s=reg256#1
# asm 2: vsubpd 768(<input_0=%rdi),<r0=%ymm0,>s=%ymm0
vsubpd 768(%rdi),%ymm0,%ymm0

# qhasm: mem256[input_0 + 1152] aligned= s
# asm 1: vmovapd   <s=reg256#1,1152(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1152(<input_0=%rdi)
vmovapd   %ymm0,1152(%rdi)

# qhasm: 4x s = approx r1 - mem256[input_0 + 800]
# asm 1: vsubpd 800(<input_0=int64#1),<r1=reg256#4,>s=reg256#1
# asm 2: vsubpd 800(<input_0=%rdi),<r1=%ymm3,>s=%ymm0
vsubpd 800(%rdi),%ymm3,%ymm0

# qhasm: mem256[input_0 + 1184] aligned= s
# asm 1: vmovapd   <s=reg256#1,1184(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1184(<input_0=%rdi)
vmovapd   %ymm0,1184(%rdi)

# qhasm: 4x s = approx r2 - mem256[input_0 + 832]
# asm 1: vsubpd 832(<input_0=int64#1),<r2=reg256#6,>s=reg256#1
# asm 2: vsubpd 832(<input_0=%rdi),<r2=%ymm5,>s=%ymm0
vsubpd 832(%rdi),%ymm5,%ymm0

# qhasm: mem256[input_0 + 1216] aligned= s
# asm 1: vmovapd   <s=reg256#1,1216(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1216(<input_0=%rdi)
vmovapd   %ymm0,1216(%rdi)

# qhasm: 4x s = approx r3 - mem256[input_0 + 864]
# asm 1: vsubpd 864(<input_0=int64#1),<r3=reg256#7,>s=reg256#1
# asm 2: vsubpd 864(<input_0=%rdi),<r3=%ymm6,>s=%ymm0
vsubpd 864(%rdi),%ymm6,%ymm0

# qhasm: mem256[input_0 + 1248] aligned= s
# asm 1: vmovapd   <s=reg256#1,1248(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1248(<input_0=%rdi)
vmovapd   %ymm0,1248(%rdi)

# qhasm: 4x s = approx r4 - mem256[input_0 + 896]
# asm 1: vsubpd 896(<input_0=int64#1),<r4=reg256#8,>s=reg256#1
# asm 2: vsubpd 896(<input_0=%rdi),<r4=%ymm7,>s=%ymm0
vsubpd 896(%rdi),%ymm7,%ymm0

# qhasm: mem256[input_0 + 1280] aligned= s
# asm 1: vmovapd   <s=reg256#1,1280(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1280(<input_0=%rdi)
vmovapd   %ymm0,1280(%rdi)

# qhasm: 4x s = approx r5 - mem256[input_0 + 928]
# asm 1: vsubpd 928(<input_0=int64#1),<r5=reg256#5,>s=reg256#1
# asm 2: vsubpd 928(<input_0=%rdi),<r5=%ymm4,>s=%ymm0
vsubpd 928(%rdi),%ymm4,%ymm0

# qhasm: mem256[input_0 + 1312] aligned= s
# asm 1: vmovapd   <s=reg256#1,1312(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1312(<input_0=%rdi)
vmovapd   %ymm0,1312(%rdi)

# qhasm: 4x s = approx r6 - mem256[input_0 + 960]
# asm 1: vsubpd 960(<input_0=int64#1),<r6=reg256#9,>s=reg256#1
# asm 2: vsubpd 960(<input_0=%rdi),<r6=%ymm8,>s=%ymm0
vsubpd 960(%rdi),%ymm8,%ymm0

# qhasm: mem256[input_0 + 1344] aligned= s
# asm 1: vmovapd   <s=reg256#1,1344(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1344(<input_0=%rdi)
vmovapd   %ymm0,1344(%rdi)

# qhasm: 4x s = approx r7 - mem256[input_0 + 992]
# asm 1: vsubpd 992(<input_0=int64#1),<r7=reg256#10,>s=reg256#1
# asm 2: vsubpd 992(<input_0=%rdi),<r7=%ymm9,>s=%ymm0
vsubpd 992(%rdi),%ymm9,%ymm0

# qhasm: mem256[input_0 + 1376] aligned= s
# asm 1: vmovapd   <s=reg256#1,1376(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1376(<input_0=%rdi)
vmovapd   %ymm0,1376(%rdi)

# qhasm: 4x s = approx r8 - mem256[input_0 + 1024]
# asm 1: vsubpd 1024(<input_0=int64#1),<r8=reg256#11,>s=reg256#1
# asm 2: vsubpd 1024(<input_0=%rdi),<r8=%ymm10,>s=%ymm0
vsubpd 1024(%rdi),%ymm10,%ymm0

# qhasm: mem256[input_0 + 1408] aligned= s
# asm 1: vmovapd   <s=reg256#1,1408(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1408(<input_0=%rdi)
vmovapd   %ymm0,1408(%rdi)

# qhasm: 4x s = approx r9 - mem256[input_0 + 1056]
# asm 1: vsubpd 1056(<input_0=int64#1),<r9=reg256#2,>s=reg256#1
# asm 2: vsubpd 1056(<input_0=%rdi),<r9=%ymm1,>s=%ymm0
vsubpd 1056(%rdi),%ymm1,%ymm0

# qhasm: mem256[input_0 + 1440] aligned= s
# asm 1: vmovapd   <s=reg256#1,1440(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1440(<input_0=%rdi)
vmovapd   %ymm0,1440(%rdi)

# qhasm: 4x s = approx r10 - mem256[input_0 + 1088]
# asm 1: vsubpd 1088(<input_0=int64#1),<r10=reg256#12,>s=reg256#1
# asm 2: vsubpd 1088(<input_0=%rdi),<r10=%ymm11,>s=%ymm0
vsubpd 1088(%rdi),%ymm11,%ymm0

# qhasm: mem256[input_0 + 1472] aligned= s
# asm 1: vmovapd   <s=reg256#1,1472(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1472(<input_0=%rdi)
vmovapd   %ymm0,1472(%rdi)

# qhasm: 4x s = approx r11 - mem256[input_0 + 1120]
# asm 1: vsubpd 1120(<input_0=int64#1),<r11=reg256#3,>s=reg256#1
# asm 2: vsubpd 1120(<input_0=%rdi),<r11=%ymm2,>s=%ymm0
vsubpd 1120(%rdi),%ymm2,%ymm0

# qhasm: mem256[input_0 + 1504] aligned= s
# asm 1: vmovapd   <s=reg256#1,1504(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,1504(<input_0=%rdi)
vmovapd   %ymm0,1504(%rdi)

# qhasm: r0 aligned= mem256[input_1 + 0]
# asm 1: vmovapd   0(<input_1=int64#2),>r0=reg256#1
# asm 2: vmovapd   0(<input_1=%rsi),>r0=%ymm0
vmovapd   0(%rsi),%ymm0

# qhasm: r1 aligned= mem256[input_1 + 32]
# asm 1: vmovapd   32(<input_1=int64#2),>r1=reg256#2
# asm 2: vmovapd   32(<input_1=%rsi),>r1=%ymm1
vmovapd   32(%rsi),%ymm1

# qhasm: r2 aligned= mem256[input_1 + 64]
# asm 1: vmovapd   64(<input_1=int64#2),>r2=reg256#3
# asm 2: vmovapd   64(<input_1=%rsi),>r2=%ymm2
vmovapd   64(%rsi),%ymm2

# qhasm: r3 aligned= mem256[input_1 + 96]
# asm 1: vmovapd   96(<input_1=int64#2),>r3=reg256#4
# asm 2: vmovapd   96(<input_1=%rsi),>r3=%ymm3
vmovapd   96(%rsi),%ymm3

# qhasm: r4 aligned= mem256[input_1 + 128]
# asm 1: vmovapd   128(<input_1=int64#2),>r4=reg256#5
# asm 2: vmovapd   128(<input_1=%rsi),>r4=%ymm4
vmovapd   128(%rsi),%ymm4

# qhasm: r5 aligned= mem256[input_1 + 160]
# asm 1: vmovapd   160(<input_1=int64#2),>r5=reg256#6
# asm 2: vmovapd   160(<input_1=%rsi),>r5=%ymm5
vmovapd   160(%rsi),%ymm5

# qhasm: r6 aligned= mem256[input_1 + 192]
# asm 1: vmovapd   192(<input_1=int64#2),>r6=reg256#7
# asm 2: vmovapd   192(<input_1=%rsi),>r6=%ymm6
vmovapd   192(%rsi),%ymm6

# qhasm: r7 aligned= mem256[input_1 + 224]
# asm 1: vmovapd   224(<input_1=int64#2),>r7=reg256#8
# asm 2: vmovapd   224(<input_1=%rsi),>r7=%ymm7
vmovapd   224(%rsi),%ymm7

# qhasm: r8 aligned= mem256[input_1 + 256]
# asm 1: vmovapd   256(<input_1=int64#2),>r8=reg256#9
# asm 2: vmovapd   256(<input_1=%rsi),>r8=%ymm8
vmovapd   256(%rsi),%ymm8

# qhasm: r9 aligned= mem256[input_1 + 288]
# asm 1: vmovapd   288(<input_1=int64#2),>r9=reg256#10
# asm 2: vmovapd   288(<input_1=%rsi),>r9=%ymm9
vmovapd   288(%rsi),%ymm9

# qhasm: r10 aligned= mem256[input_1 + 320]
# asm 1: vmovapd   320(<input_1=int64#2),>r10=reg256#11
# asm 2: vmovapd   320(<input_1=%rsi),>r10=%ymm10
vmovapd   320(%rsi),%ymm10

# qhasm: r11 aligned= mem256[input_1 + 352]
# asm 1: vmovapd   352(<input_1=int64#2),>r11=reg256#12
# asm 2: vmovapd   352(<input_1=%rsi),>r11=%ymm11
vmovapd   352(%rsi),%ymm11

# qhasm: 4x s = approx r0 + mem256[input_1 + 384]
# asm 1: vaddpd 384(<input_1=int64#2),<r0=reg256#1,>s=reg256#1
# asm 2: vaddpd 384(<input_1=%rsi),<r0=%ymm0,>s=%ymm0
vaddpd 384(%rsi),%ymm0,%ymm0

# qhasm: mem256[input_0 + 0] aligned= s
# asm 1: vmovapd   <s=reg256#1,0(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,0(<input_0=%rdi)
vmovapd   %ymm0,0(%rdi)

# qhasm: 4x s = approx r1 + mem256[input_1 + 416]
# asm 1: vaddpd 416(<input_1=int64#2),<r1=reg256#2,>s=reg256#1
# asm 2: vaddpd 416(<input_1=%rsi),<r1=%ymm1,>s=%ymm0
vaddpd 416(%rsi),%ymm1,%ymm0

# qhasm: mem256[input_0 + 32] aligned= s
# asm 1: vmovapd   <s=reg256#1,32(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,32(<input_0=%rdi)
vmovapd   %ymm0,32(%rdi)

# qhasm: 4x s = approx r2 + mem256[input_1 + 448]
# asm 1: vaddpd 448(<input_1=int64#2),<r2=reg256#3,>s=reg256#1
# asm 2: vaddpd 448(<input_1=%rsi),<r2=%ymm2,>s=%ymm0
vaddpd 448(%rsi),%ymm2,%ymm0

# qhasm: mem256[input_0 + 64] aligned= s
# asm 1: vmovapd   <s=reg256#1,64(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,64(<input_0=%rdi)
vmovapd   %ymm0,64(%rdi)

# qhasm: 4x s = approx r3 + mem256[input_1 + 480]
# asm 1: vaddpd 480(<input_1=int64#2),<r3=reg256#4,>s=reg256#1
# asm 2: vaddpd 480(<input_1=%rsi),<r3=%ymm3,>s=%ymm0
vaddpd 480(%rsi),%ymm3,%ymm0

# qhasm: mem256[input_0 + 96] aligned= s
# asm 1: vmovapd   <s=reg256#1,96(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,96(<input_0=%rdi)
vmovapd   %ymm0,96(%rdi)

# qhasm: 4x s = approx r4 + mem256[input_1 + 512]
# asm 1: vaddpd 512(<input_1=int64#2),<r4=reg256#5,>s=reg256#1
# asm 2: vaddpd 512(<input_1=%rsi),<r4=%ymm4,>s=%ymm0
vaddpd 512(%rsi),%ymm4,%ymm0

# qhasm: mem256[input_0 + 128] aligned= s
# asm 1: vmovapd   <s=reg256#1,128(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,128(<input_0=%rdi)
vmovapd   %ymm0,128(%rdi)

# qhasm: 4x s = approx r5 + mem256[input_1 + 544]
# asm 1: vaddpd 544(<input_1=int64#2),<r5=reg256#6,>s=reg256#1
# asm 2: vaddpd 544(<input_1=%rsi),<r5=%ymm5,>s=%ymm0
vaddpd 544(%rsi),%ymm5,%ymm0

# qhasm: mem256[input_0 + 160] aligned= s
# asm 1: vmovapd   <s=reg256#1,160(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,160(<input_0=%rdi)
vmovapd   %ymm0,160(%rdi)

# qhasm: 4x s = approx r6 + mem256[input_1 + 576]
# asm 1: vaddpd 576(<input_1=int64#2),<r6=reg256#7,>s=reg256#1
# asm 2: vaddpd 576(<input_1=%rsi),<r6=%ymm6,>s=%ymm0
vaddpd 576(%rsi),%ymm6,%ymm0

# qhasm: mem256[input_0 + 192] aligned= s
# asm 1: vmovapd   <s=reg256#1,192(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,192(<input_0=%rdi)
vmovapd   %ymm0,192(%rdi)

# qhasm: 4x s = approx r7 + mem256[input_1 + 608]
# asm 1: vaddpd 608(<input_1=int64#2),<r7=reg256#8,>s=reg256#1
# asm 2: vaddpd 608(<input_1=%rsi),<r7=%ymm7,>s=%ymm0
vaddpd 608(%rsi),%ymm7,%ymm0

# qhasm: mem256[input_0 + 224] aligned= s
# asm 1: vmovapd   <s=reg256#1,224(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,224(<input_0=%rdi)
vmovapd   %ymm0,224(%rdi)

# qhasm: 4x s = approx r8 + mem256[input_1 + 640]
# asm 1: vaddpd 640(<input_1=int64#2),<r8=reg256#9,>s=reg256#1
# asm 2: vaddpd 640(<input_1=%rsi),<r8=%ymm8,>s=%ymm0
vaddpd 640(%rsi),%ymm8,%ymm0

# qhasm: mem256[input_0 + 256] aligned= s
# asm 1: vmovapd   <s=reg256#1,256(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,256(<input_0=%rdi)
vmovapd   %ymm0,256(%rdi)

# qhasm: 4x s = approx r9 + mem256[input_1 + 672]
# asm 1: vaddpd 672(<input_1=int64#2),<r9=reg256#10,>s=reg256#1
# asm 2: vaddpd 672(<input_1=%rsi),<r9=%ymm9,>s=%ymm0
vaddpd 672(%rsi),%ymm9,%ymm0

# qhasm: mem256[input_0 + 288] aligned= s
# asm 1: vmovapd   <s=reg256#1,288(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,288(<input_0=%rdi)
vmovapd   %ymm0,288(%rdi)

# qhasm: 4x s = approx r10 + mem256[input_1 + 704]
# asm 1: vaddpd 704(<input_1=int64#2),<r10=reg256#11,>s=reg256#1
# asm 2: vaddpd 704(<input_1=%rsi),<r10=%ymm10,>s=%ymm0
vaddpd 704(%rsi),%ymm10,%ymm0

# qhasm: mem256[input_0 + 320] aligned= s
# asm 1: vmovapd   <s=reg256#1,320(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,320(<input_0=%rdi)
vmovapd   %ymm0,320(%rdi)

# qhasm: 4x s = approx r11 + mem256[input_1 + 736]
# asm 1: vaddpd 736(<input_1=int64#2),<r11=reg256#12,>s=reg256#1
# asm 2: vaddpd 736(<input_1=%rsi),<r11=%ymm11,>s=%ymm0
vaddpd 736(%rsi),%ymm11,%ymm0

# qhasm: mem256[input_0 + 352] aligned= s
# asm 1: vmovapd   <s=reg256#1,352(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,352(<input_0=%rdi)
vmovapd   %ymm0,352(%rdi)

# qhasm:   square_nineteen aligned= mem256[scale19]
# asm 1: vmovapd scale19,>square_nineteen=reg256#1
# asm 2: vmovapd scale19,>square_nineteen=%ymm0
vmovapd scale19,%ymm0

# qhasm:   square_two aligned= mem256[two4x]
# asm 1: vmovapd two4x,>square_two=reg256#2
# asm 2: vmovapd two4x,>square_two=%ymm1
vmovapd two4x,%ymm1

# qhasm:   square_x0 aligned= mem256[input_0 + 0]
# asm 1: vmovapd   0(<input_0=int64#1),>square_x0=reg256#3
# asm 2: vmovapd   0(<input_0=%rdi),>square_x0=%ymm2
vmovapd   0(%rdi),%ymm2

# qhasm:   4x r0 = approx square_x0 * square_x0
# asm 1: vmulpd <square_x0=reg256#3,<square_x0=reg256#3,>r0=reg256#4
# asm 2: vmulpd <square_x0=%ymm2,<square_x0=%ymm2,>r0=%ymm3
vmulpd %ymm2,%ymm2,%ymm3

# qhasm:   4x square_x0 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x0=reg256#3,>square_x0=reg256#3
# asm 2: vmulpd <square_two=%ymm1,<square_x0=%ymm2,>square_x0=%ymm2
vmulpd %ymm1,%ymm2,%ymm2

# qhasm:   4x r1 = approx square_x0 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<square_x0=reg256#3,>r1=reg256#5
# asm 2: vmulpd 32(<input_0=%rdi),<square_x0=%ymm2,>r1=%ymm4
vmulpd 32(%rdi),%ymm2,%ymm4

# qhasm:   4x r2 = approx square_x0 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<square_x0=reg256#3,>r2=reg256#6
# asm 2: vmulpd 64(<input_0=%rdi),<square_x0=%ymm2,>r2=%ymm5
vmulpd 64(%rdi),%ymm2,%ymm5

# qhasm:   4x r3 = approx square_x0 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<square_x0=reg256#3,>r3=reg256#7
# asm 2: vmulpd 96(<input_0=%rdi),<square_x0=%ymm2,>r3=%ymm6
vmulpd 96(%rdi),%ymm2,%ymm6

# qhasm:   4x r4 = approx square_x0 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<square_x0=reg256#3,>r4=reg256#8
# asm 2: vmulpd 128(<input_0=%rdi),<square_x0=%ymm2,>r4=%ymm7
vmulpd 128(%rdi),%ymm2,%ymm7

# qhasm:   4x r5 = approx square_x0 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<square_x0=reg256#3,>r5=reg256#9
# asm 2: vmulpd 160(<input_0=%rdi),<square_x0=%ymm2,>r5=%ymm8
vmulpd 160(%rdi),%ymm2,%ymm8

# qhasm:   4x r6 = approx square_x0 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<square_x0=reg256#3,>r6=reg256#10
# asm 2: vmulpd 192(<input_0=%rdi),<square_x0=%ymm2,>r6=%ymm9
vmulpd 192(%rdi),%ymm2,%ymm9

# qhasm:   4x r7 = approx square_x0 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<square_x0=reg256#3,>r7=reg256#11
# asm 2: vmulpd 224(<input_0=%rdi),<square_x0=%ymm2,>r7=%ymm10
vmulpd 224(%rdi),%ymm2,%ymm10

# qhasm:   4x r8 = approx square_x0 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<square_x0=reg256#3,>r8=reg256#12
# asm 2: vmulpd 256(<input_0=%rdi),<square_x0=%ymm2,>r8=%ymm11
vmulpd 256(%rdi),%ymm2,%ymm11

# qhasm:   4x r9 = approx square_x0 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<square_x0=reg256#3,>r9=reg256#13
# asm 2: vmulpd 288(<input_0=%rdi),<square_x0=%ymm2,>r9=%ymm12
vmulpd 288(%rdi),%ymm2,%ymm12

# qhasm:   4x r10 = approx square_x0 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<square_x0=reg256#3,>r10=reg256#14
# asm 2: vmulpd 320(<input_0=%rdi),<square_x0=%ymm2,>r10=%ymm13
vmulpd 320(%rdi),%ymm2,%ymm13

# qhasm:   4x r11 = approx square_x0 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x0=reg256#3,>r11=reg256#3
# asm 2: vmulpd 352(<input_0=%rdi),<square_x0=%ymm2,>r11=%ymm2
vmulpd 352(%rdi),%ymm2,%ymm2

# qhasm:   square_x1 aligned= mem256[input_0 + 32]
# asm 1: vmovapd   32(<input_0=int64#1),>square_x1=reg256#15
# asm 2: vmovapd   32(<input_0=%rdi),>square_x1=%ymm14
vmovapd   32(%rdi),%ymm14

# qhasm:   4x square_t = approx square_x1 * square_x1
# asm 1: vmulpd <square_x1=reg256#15,<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x1=%ymm14,<square_x1=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_x1 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x1=reg256#15,>square_x1=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x1=%ymm14,>square_x1=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x1 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 64(<input_0=%rdi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 64(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x1 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x1 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x1 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x1 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x1 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x1 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x1 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x1 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<square_x1=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<square_x1=%ymm14,>square_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x1 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x1=reg256#15,>square_x1=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x1=%ymm14,>square_x1=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x1 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x1=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<square_x1=%ymm14,>square_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   square_x2 aligned= mem256[input_0 + 64]
# asm 1: vmovapd   64(<input_0=int64#1),>square_x2=reg256#15
# asm 2: vmovapd   64(<input_0=%rdi),>square_x2=%ymm14
vmovapd   64(%rdi),%ymm14

# qhasm:   4x square_t = approx square_x2 * square_x2
# asm 1: vmulpd <square_x2=reg256#15,<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x2=%ymm14,<square_x2=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_x2 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x2=reg256#15,>square_x2=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x2=%ymm14,>square_x2=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x2 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x2 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x2 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x2 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x2 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x2 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x2 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x2 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x2=reg256#15,>square_x2=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x2=%ymm14,>square_x2=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x2 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<square_x2=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<square_x2=%ymm14,>square_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x2 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x2=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<square_x2=%ymm14,>square_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   square_x3 aligned= mem256[input_0 + 96]
# asm 1: vmovapd   96(<input_0=int64#1),>square_x3=reg256#15
# asm 2: vmovapd   96(<input_0=%rdi),>square_x3=%ymm14
vmovapd   96(%rdi),%ymm14

# qhasm:   4x square_t = approx square_x3 * square_x3
# asm 1: vmulpd <square_x3=reg256#15,<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x3=%ymm14,<square_x3=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_x3 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x3=reg256#15,>square_x3=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x3=%ymm14,>square_x3=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x3 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x3 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_t = approx square_x3 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x3 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x3 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x3 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x3=reg256#15,>square_x3=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x3=%ymm14,>square_x3=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x3 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x3 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<square_x3=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<square_x3=%ymm14,>square_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x3 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x3=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<square_x3=%ymm14,>square_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   square_x4 aligned= mem256[input_0 + 128]
# asm 1: vmovapd   128(<input_0=int64#1),>square_x4=reg256#15
# asm 2: vmovapd   128(<input_0=%rdi),>square_x4=%ymm14
vmovapd   128(%rdi),%ymm14

# qhasm:   4x square_t = approx square_x4 * square_x4
# asm 1: vmulpd <square_x4=reg256#15,<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x4=%ymm14,<square_x4=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_x4 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x4=reg256#15,>square_x4=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x4=%ymm14,>square_x4=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x4 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <square_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x4 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_t = approx square_x4 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x4 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x4=reg256#15,>square_x4=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x4=%ymm14,>square_x4=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x4 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x4 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x4 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<square_x4=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<square_x4=%ymm14,>square_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x4 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x4=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<square_x4=%ymm14,>square_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   square_x5 aligned= mem256[input_0 + 160]
# asm 1: vmovapd   160(<input_0=int64#1),>square_x5=reg256#15
# asm 2: vmovapd   160(<input_0=%rdi),>square_x5=%ymm14
vmovapd   160(%rdi),%ymm14

# qhasm:   4x square_t = approx square_x5 * square_x5
# asm 1: vmulpd <square_x5=reg256#15,<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd <square_x5=%ymm14,<square_x5=%ymm14,>square_t=%ymm15
vmulpd %ymm14,%ymm14,%ymm15

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <square_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x square_x5 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x5=reg256#15,>square_x5=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x5=%ymm14,>square_x5=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x5 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm15,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm15,%ymm2,%ymm2

# qhasm:   4x square_x5 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x5=reg256#15,>square_x5=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x5=%ymm14,>square_x5=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x5 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_t = approx square_x5 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x5 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x5 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<square_x5=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<square_x5=%ymm14,>square_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x5 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x5=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<square_x5=%ymm14,>square_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   square_x6 aligned= mem256[input_0 + 192]
# asm 1: vmovapd   192(<input_0=int64#1),>square_x6=reg256#15
# asm 2: vmovapd   192(<input_0=%rdi),>square_x6=%ymm14
vmovapd   192(%rdi),%ymm14

# qhasm:   4x square_x6 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x6=reg256#15,>square_x6=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x6=%ymm14,>square_x6=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x6 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <square_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x square_x6 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x6=reg256#15,>square_x6=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x6=%ymm14,>square_x6=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x6 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x square_t = approx square_x6 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_t = approx square_x6 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x6 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<square_x6=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<square_x6=%ymm14,>square_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x6 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x6=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<square_x6=%ymm14,>square_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   square_x7 aligned= mem256[input_0 + 224]
# asm 1: vmovapd   224(<input_0=int64#1),>square_x7=reg256#15
# asm 2: vmovapd   224(<input_0=%rdi),>square_x7=%ymm14
vmovapd   224(%rdi),%ymm14

# qhasm:   4x square_x7 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x7=reg256#15,>square_x7=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x7=%ymm14,>square_x7=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x7 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x square_x7 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x7=reg256#15,>square_x7=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x7=%ymm14,>square_x7=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x7 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x square_t = approx square_x7 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_t = approx square_x7 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<square_x7=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<square_x7=%ymm14,>square_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x7 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x7=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<square_x7=%ymm14,>square_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   square_x8 aligned= mem256[input_0 + 256]
# asm 1: vmovapd   256(<input_0=int64#1),>square_x8=reg256#15
# asm 2: vmovapd   256(<input_0=%rdi),>square_x8=%ymm14
vmovapd   256(%rdi),%ymm14

# qhasm:   4x square_x8 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x8=reg256#15,>square_x8=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x8=%ymm14,>square_x8=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x8 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x square_x8 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x8=reg256#15,>square_x8=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x8=%ymm14,>square_x8=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x8 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x square_t = approx square_x8 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<square_x8=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<square_x8=%ymm14,>square_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_t = approx square_x8 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x8=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<square_x8=%ymm14,>square_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   square_x9 aligned= mem256[input_0 + 288]
# asm 1: vmovapd   288(<input_0=int64#1),>square_x9=reg256#15
# asm 2: vmovapd   288(<input_0=%rdi),>square_x9=%ymm14
vmovapd   288(%rdi),%ymm14

# qhasm:   4x square_x9 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x9=reg256#15,>square_x9=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x9=%ymm14,>square_x9=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x9 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<square_x9=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<square_x9=%ymm14,>square_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x square_x9 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x9=reg256#15,>square_x9=reg256#15
# asm 2: vmulpd <square_two=%ymm1,<square_x9=%ymm14,>square_x9=%ymm14
vmulpd %ymm1,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x9 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<square_x9=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<square_x9=%ymm14,>square_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x square_t = approx square_x9 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x9=reg256#15,>square_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<square_x9=%ymm14,>square_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   square_x10 aligned= mem256[input_0 + 320]
# asm 1: vmovapd   320(<input_0=int64#1),>square_x10=reg256#15
# asm 2: vmovapd   320(<input_0=%rdi),>square_x10=%ymm14
vmovapd   320(%rdi),%ymm14

# qhasm:   4x square_x10 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x10=reg256#15,>square_x10=reg256#15
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x10=%ymm14,>square_x10=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x square_t = approx square_x10 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<square_x10=reg256#15,>square_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<square_x10=%ymm14,>square_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x square_x10 approx*= square_two
# asm 1: vmulpd <square_two=reg256#2,<square_x10=reg256#15,>square_x10=reg256#2
# asm 2: vmulpd <square_two=%ymm1,<square_x10=%ymm14,>square_x10=%ymm1
vmulpd %ymm1,%ymm14,%ymm1

# qhasm:   4x square_t = approx square_x10 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x10=reg256#2,>square_t=reg256#2
# asm 2: vmulpd 352(<input_0=%rdi),<square_x10=%ymm1,>square_t=%ymm1
vmulpd 352(%rdi),%ymm1,%ymm1

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#2,<r9=reg256#13,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm1,<r9=%ymm12,>r9=%ymm1
vaddpd %ymm1,%ymm12,%ymm1

# qhasm:   square_x11 aligned= mem256[input_0 + 352]
# asm 1: vmovapd   352(<input_0=int64#1),>square_x11=reg256#13
# asm 2: vmovapd   352(<input_0=%rdi),>square_x11=%ymm12
vmovapd   352(%rdi),%ymm12

# qhasm:   4x square_x11 approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_x11=reg256#13,>square_x11=reg256#13
# asm 2: vmulpd <square_nineteen=%ymm0,<square_x11=%ymm12,>square_x11=%ymm12
vmulpd %ymm0,%ymm12,%ymm12

# qhasm:   4x square_t = approx square_x11 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<square_x11=reg256#13,>square_t=reg256#13
# asm 2: vmulpd 352(<input_0=%rdi),<square_x11=%ymm12,>square_t=%ymm12
vmulpd 352(%rdi),%ymm12,%ymm12

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#13,<r10=reg256#14,>r10=reg256#13
# asm 2: vaddpd <square_t=%ymm12,<r10=%ymm13,>r10=%ymm12
vaddpd %ymm12,%ymm13,%ymm12

# qhasm:   square_c aligned= mem256[alpha22]
# asm 1: vmovapd alpha22,>square_c=reg256#14
# asm 2: vmovapd alpha22,>square_c=%ymm13
vmovapd alpha22,%ymm13

# qhasm:   4x square_t = approx r0 +square_c
# asm 1: vaddpd <r0=reg256#4,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r0=%ymm3,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm3,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r0 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r0=reg256#4,>r0=reg256#4
# asm 2: vsubpd <square_t=%ymm13,<r0=%ymm3,>r0=%ymm3
vsubpd %ymm13,%ymm3,%ymm3

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <square_t=%ymm13,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm13,%ymm4,%ymm4

# qhasm:   square_c aligned= mem256[alpha107]
# asm 1: vmovapd alpha107,>square_c=reg256#14
# asm 2: vmovapd alpha107,>square_c=%ymm13
vmovapd alpha107,%ymm13

# qhasm:   4x square_t = approx r4 +square_c
# asm 1: vaddpd <r4=reg256#8,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r4=%ymm7,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm7,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r4 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r4=reg256#8,>r4=reg256#8
# asm 2: vsubpd <square_t=%ymm13,<r4=%ymm7,>r4=%ymm7
vsubpd %ymm13,%ymm7,%ymm7

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <square_t=%ymm13,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm13,%ymm8,%ymm8

# qhasm:   square_c aligned= mem256[alpha192]
# asm 1: vmovapd alpha192,>square_c=reg256#14
# asm 2: vmovapd alpha192,>square_c=%ymm13
vmovapd alpha192,%ymm13

# qhasm:   4x square_t = approx r8 +square_c
# asm 1: vaddpd <r8=reg256#12,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r8=%ymm11,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm11,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r8 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r8=reg256#12,>r8=reg256#12
# asm 2: vsubpd <square_t=%ymm13,<r8=%ymm11,>r8=%ymm11
vsubpd %ymm13,%ymm11,%ymm11

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r9=reg256#2,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm13,<r9=%ymm1,>r9=%ymm1
vaddpd %ymm13,%ymm1,%ymm1

# qhasm:   square_c aligned= mem256[alpha43]
# asm 1: vmovapd alpha43,>square_c=reg256#14
# asm 2: vmovapd alpha43,>square_c=%ymm13
vmovapd alpha43,%ymm13

# qhasm:   4x square_t = approx r1 +square_c
# asm 1: vaddpd <r1=reg256#5,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r1=%ymm4,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm4,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r1 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r1=reg256#5,>r1=reg256#5
# asm 2: vsubpd <square_t=%ymm13,<r1=%ymm4,>r1=%ymm4
vsubpd %ymm13,%ymm4,%ymm4

# qhasm:   4x r2 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <square_t=%ymm13,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm13,%ymm5,%ymm5

# qhasm:   square_c aligned= mem256[alpha128]
# asm 1: vmovapd alpha128,>square_c=reg256#14
# asm 2: vmovapd alpha128,>square_c=%ymm13
vmovapd alpha128,%ymm13

# qhasm:   4x square_t = approx r5 +square_c
# asm 1: vaddpd <r5=reg256#9,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r5=%ymm8,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm8,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r5 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r5=reg256#9,>r5=reg256#9
# asm 2: vsubpd <square_t=%ymm13,<r5=%ymm8,>r5=%ymm8
vsubpd %ymm13,%ymm8,%ymm8

# qhasm:   4x r6 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <square_t=%ymm13,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm13,%ymm9,%ymm9

# qhasm:   square_c aligned= mem256[alpha213]
# asm 1: vmovapd alpha213,>square_c=reg256#14
# asm 2: vmovapd alpha213,>square_c=%ymm13
vmovapd alpha213,%ymm13

# qhasm:   4x square_t = approx r9 +square_c
# asm 1: vaddpd <r9=reg256#2,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r9=%ymm1,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm1,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r9 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r9=reg256#2,>r9=reg256#2
# asm 2: vsubpd <square_t=%ymm13,<r9=%ymm1,>r9=%ymm1
vsubpd %ymm13,%ymm1,%ymm1

# qhasm:   4x r10 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r10=reg256#13,>r10=reg256#13
# asm 2: vaddpd <square_t=%ymm13,<r10=%ymm12,>r10=%ymm12
vaddpd %ymm13,%ymm12,%ymm12

# qhasm:   square_c aligned= mem256[alpha64]
# asm 1: vmovapd alpha64,>square_c=reg256#14
# asm 2: vmovapd alpha64,>square_c=%ymm13
vmovapd alpha64,%ymm13

# qhasm:   4x square_t = approx r2 +square_c
# asm 1: vaddpd <r2=reg256#6,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r2=%ymm5,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm5,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r2 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r2=reg256#6,>r2=reg256#6
# asm 2: vsubpd <square_t=%ymm13,<r2=%ymm5,>r2=%ymm5
vsubpd %ymm13,%ymm5,%ymm5

# qhasm:   4x r3 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <square_t=%ymm13,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm13,%ymm6,%ymm6

# qhasm:   square_c aligned= mem256[alpha149]
# asm 1: vmovapd alpha149,>square_c=reg256#14
# asm 2: vmovapd alpha149,>square_c=%ymm13
vmovapd alpha149,%ymm13

# qhasm:   4x square_t = approx r6 +square_c
# asm 1: vaddpd <r6=reg256#10,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r6=%ymm9,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm9,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r6 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r6=reg256#10,>r6=reg256#10
# asm 2: vsubpd <square_t=%ymm13,<r6=%ymm9,>r6=%ymm9
vsubpd %ymm13,%ymm9,%ymm9

# qhasm:   4x r7 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <square_t=%ymm13,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm13,%ymm10,%ymm10

# qhasm:   square_c aligned= mem256[alpha234]
# asm 1: vmovapd alpha234,>square_c=reg256#14
# asm 2: vmovapd alpha234,>square_c=%ymm13
vmovapd alpha234,%ymm13

# qhasm:   4x square_t = approx r10 +square_c
# asm 1: vaddpd <r10=reg256#13,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r10=%ymm12,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm12,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r10 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r10=reg256#13,>r10=reg256#13
# asm 2: vsubpd <square_t=%ymm13,<r10=%ymm12,>r10=%ymm12
vsubpd %ymm13,%ymm12,%ymm12

# qhasm:   4x r11 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r11=reg256#3,>r11=reg256#3
# asm 2: vaddpd <square_t=%ymm13,<r11=%ymm2,>r11=%ymm2
vaddpd %ymm13,%ymm2,%ymm2

# qhasm:   square_c aligned= mem256[alpha85]
# asm 1: vmovapd alpha85,>square_c=reg256#14
# asm 2: vmovapd alpha85,>square_c=%ymm13
vmovapd alpha85,%ymm13

# qhasm:   4x square_t = approx r3 +square_c
# asm 1: vaddpd <r3=reg256#7,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r3=%ymm6,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm6,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r3 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r3=reg256#7,>r3=reg256#7
# asm 2: vsubpd <square_t=%ymm13,<r3=%ymm6,>r3=%ymm6
vsubpd %ymm13,%ymm6,%ymm6

# qhasm:   4x r4 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <square_t=%ymm13,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm13,%ymm7,%ymm7

# qhasm:   square_c aligned= mem256[alpha170]
# asm 1: vmovapd alpha170,>square_c=reg256#14
# asm 2: vmovapd alpha170,>square_c=%ymm13
vmovapd alpha170,%ymm13

# qhasm:   4x square_t = approx r7 +square_c
# asm 1: vaddpd <r7=reg256#11,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r7=%ymm10,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm10,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r7 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r7=reg256#11,>r7=reg256#11
# asm 2: vsubpd <square_t=%ymm13,<r7=%ymm10,>r7=%ymm10
vsubpd %ymm13,%ymm10,%ymm10

# qhasm:   4x r8 approx+= square_t
# asm 1: vaddpd <square_t=reg256#14,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <square_t=%ymm13,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm13,%ymm11,%ymm11

# qhasm:   square_c aligned= mem256[alpha255]
# asm 1: vmovapd alpha255,>square_c=reg256#14
# asm 2: vmovapd alpha255,>square_c=%ymm13
vmovapd alpha255,%ymm13

# qhasm:   4x square_t = approx r11 +square_c
# asm 1: vaddpd <r11=reg256#3,<square_c=reg256#14,>square_t=reg256#15
# asm 2: vaddpd <r11=%ymm2,<square_c=%ymm13,>square_t=%ymm14
vaddpd %ymm2,%ymm13,%ymm14

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#14,<square_t=reg256#15,>square_t=reg256#14
# asm 2: vsubpd <square_c=%ymm13,<square_t=%ymm14,>square_t=%ymm13
vsubpd %ymm13,%ymm14,%ymm13

# qhasm:   4x r11 approx-= square_t
# asm 1: vsubpd <square_t=reg256#14,<r11=reg256#3,>r11=reg256#3
# asm 2: vsubpd <square_t=%ymm13,<r11=%ymm2,>r11=%ymm2
vsubpd %ymm13,%ymm2,%ymm2

# qhasm:   4x square_t approx*= square_nineteen
# asm 1: vmulpd <square_nineteen=reg256#1,<square_t=reg256#14,>square_t=reg256#1
# asm 2: vmulpd <square_nineteen=%ymm0,<square_t=%ymm13,>square_t=%ymm0
vmulpd %ymm0,%ymm13,%ymm0

# qhasm:   4x r0 approx+= square_t
# asm 1: vaddpd <square_t=reg256#1,<r0=reg256#4,>r0=reg256#1
# asm 2: vaddpd <square_t=%ymm0,<r0=%ymm3,>r0=%ymm0
vaddpd %ymm0,%ymm3,%ymm0

# qhasm:   square_c aligned= mem256[alpha22]
# asm 1: vmovapd alpha22,>square_c=reg256#4
# asm 2: vmovapd alpha22,>square_c=%ymm3
vmovapd alpha22,%ymm3

# qhasm:   4x square_t = approx r0 +square_c
# asm 1: vaddpd <r0=reg256#1,<square_c=reg256#4,>square_t=reg256#14
# asm 2: vaddpd <r0=%ymm0,<square_c=%ymm3,>square_t=%ymm13
vaddpd %ymm0,%ymm3,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#4,<square_t=reg256#14,>square_t=reg256#4
# asm 2: vsubpd <square_c=%ymm3,<square_t=%ymm13,>square_t=%ymm3
vsubpd %ymm3,%ymm13,%ymm3

# qhasm:   4x r0 approx-= square_t
# asm 1: vsubpd <square_t=reg256#4,<r0=reg256#1,>r0=reg256#1
# asm 2: vsubpd <square_t=%ymm3,<r0=%ymm0,>r0=%ymm0
vsubpd %ymm3,%ymm0,%ymm0

# qhasm:   4x r1 approx+= square_t
# asm 1: vaddpd <square_t=reg256#4,<r1=reg256#5,>r1=reg256#4
# asm 2: vaddpd <square_t=%ymm3,<r1=%ymm4,>r1=%ymm3
vaddpd %ymm3,%ymm4,%ymm3

# qhasm:   square_c aligned= mem256[alpha107]
# asm 1: vmovapd alpha107,>square_c=reg256#5
# asm 2: vmovapd alpha107,>square_c=%ymm4
vmovapd alpha107,%ymm4

# qhasm:   4x square_t = approx r4 +square_c
# asm 1: vaddpd <r4=reg256#8,<square_c=reg256#5,>square_t=reg256#14
# asm 2: vaddpd <r4=%ymm7,<square_c=%ymm4,>square_t=%ymm13
vaddpd %ymm7,%ymm4,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#5,<square_t=reg256#14,>square_t=reg256#5
# asm 2: vsubpd <square_c=%ymm4,<square_t=%ymm13,>square_t=%ymm4
vsubpd %ymm4,%ymm13,%ymm4

# qhasm:   4x r4 approx-= square_t
# asm 1: vsubpd <square_t=reg256#5,<r4=reg256#8,>r4=reg256#8
# asm 2: vsubpd <square_t=%ymm4,<r4=%ymm7,>r4=%ymm7
vsubpd %ymm4,%ymm7,%ymm7

# qhasm:   4x r5 approx+= square_t
# asm 1: vaddpd <square_t=reg256#5,<r5=reg256#9,>r5=reg256#5
# asm 2: vaddpd <square_t=%ymm4,<r5=%ymm8,>r5=%ymm4
vaddpd %ymm4,%ymm8,%ymm4

# qhasm:   square_c aligned= mem256[alpha192]
# asm 1: vmovapd alpha192,>square_c=reg256#9
# asm 2: vmovapd alpha192,>square_c=%ymm8
vmovapd alpha192,%ymm8

# qhasm:   4x square_t = approx r8 +square_c
# asm 1: vaddpd <r8=reg256#12,<square_c=reg256#9,>square_t=reg256#14
# asm 2: vaddpd <r8=%ymm11,<square_c=%ymm8,>square_t=%ymm13
vaddpd %ymm11,%ymm8,%ymm13

# qhasm:   4x square_t approx-=square_c
# asm 1: vsubpd <square_c=reg256#9,<square_t=reg256#14,>square_t=reg256#9
# asm 2: vsubpd <square_c=%ymm8,<square_t=%ymm13,>square_t=%ymm8
vsubpd %ymm8,%ymm13,%ymm8

# qhasm:   4x r8 approx-= square_t
# asm 1: vsubpd <square_t=reg256#9,<r8=reg256#12,>r8=reg256#12
# asm 2: vsubpd <square_t=%ymm8,<r8=%ymm11,>r8=%ymm11
vsubpd %ymm8,%ymm11,%ymm11

# qhasm:   4x r9 approx+= square_t
# asm 1: vaddpd <square_t=reg256#9,<r9=reg256#2,>r9=reg256#2
# asm 2: vaddpd <square_t=%ymm8,<r9=%ymm1,>r9=%ymm1
vaddpd %ymm8,%ymm1,%ymm1

# qhasm: 4x s = approx r0 - mem256[input_0 + 384]
# asm 1: vsubpd 384(<input_0=int64#1),<r0=reg256#1,>s=reg256#1
# asm 2: vsubpd 384(<input_0=%rdi),<r0=%ymm0,>s=%ymm0
vsubpd 384(%rdi),%ymm0,%ymm0

# qhasm: mem256[input_0 + 0] aligned= s
# asm 1: vmovapd   <s=reg256#1,0(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,0(<input_0=%rdi)
vmovapd   %ymm0,0(%rdi)

# qhasm: 4x s = approx r1 - mem256[input_0 + 416]
# asm 1: vsubpd 416(<input_0=int64#1),<r1=reg256#4,>s=reg256#1
# asm 2: vsubpd 416(<input_0=%rdi),<r1=%ymm3,>s=%ymm0
vsubpd 416(%rdi),%ymm3,%ymm0

# qhasm: mem256[input_0 + 32] aligned= s
# asm 1: vmovapd   <s=reg256#1,32(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,32(<input_0=%rdi)
vmovapd   %ymm0,32(%rdi)

# qhasm: 4x s = approx r2 - mem256[input_0 + 448]
# asm 1: vsubpd 448(<input_0=int64#1),<r2=reg256#6,>s=reg256#1
# asm 2: vsubpd 448(<input_0=%rdi),<r2=%ymm5,>s=%ymm0
vsubpd 448(%rdi),%ymm5,%ymm0

# qhasm: mem256[input_0 + 64] aligned= s
# asm 1: vmovapd   <s=reg256#1,64(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,64(<input_0=%rdi)
vmovapd   %ymm0,64(%rdi)

# qhasm: 4x s = approx r3 - mem256[input_0 + 480]
# asm 1: vsubpd 480(<input_0=int64#1),<r3=reg256#7,>s=reg256#1
# asm 2: vsubpd 480(<input_0=%rdi),<r3=%ymm6,>s=%ymm0
vsubpd 480(%rdi),%ymm6,%ymm0

# qhasm: mem256[input_0 + 96] aligned= s
# asm 1: vmovapd   <s=reg256#1,96(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,96(<input_0=%rdi)
vmovapd   %ymm0,96(%rdi)

# qhasm: 4x s = approx r4 - mem256[input_0 + 512]
# asm 1: vsubpd 512(<input_0=int64#1),<r4=reg256#8,>s=reg256#1
# asm 2: vsubpd 512(<input_0=%rdi),<r4=%ymm7,>s=%ymm0
vsubpd 512(%rdi),%ymm7,%ymm0

# qhasm: mem256[input_0 + 128] aligned= s
# asm 1: vmovapd   <s=reg256#1,128(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,128(<input_0=%rdi)
vmovapd   %ymm0,128(%rdi)

# qhasm: 4x s = approx r5 - mem256[input_0 + 544]
# asm 1: vsubpd 544(<input_0=int64#1),<r5=reg256#5,>s=reg256#1
# asm 2: vsubpd 544(<input_0=%rdi),<r5=%ymm4,>s=%ymm0
vsubpd 544(%rdi),%ymm4,%ymm0

# qhasm: mem256[input_0 + 160] aligned= s
# asm 1: vmovapd   <s=reg256#1,160(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,160(<input_0=%rdi)
vmovapd   %ymm0,160(%rdi)

# qhasm: 4x s = approx r6 - mem256[input_0 + 576]
# asm 1: vsubpd 576(<input_0=int64#1),<r6=reg256#10,>s=reg256#1
# asm 2: vsubpd 576(<input_0=%rdi),<r6=%ymm9,>s=%ymm0
vsubpd 576(%rdi),%ymm9,%ymm0

# qhasm: mem256[input_0 + 192] aligned= s
# asm 1: vmovapd   <s=reg256#1,192(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,192(<input_0=%rdi)
vmovapd   %ymm0,192(%rdi)

# qhasm: 4x s = approx r7 - mem256[input_0 + 608]
# asm 1: vsubpd 608(<input_0=int64#1),<r7=reg256#11,>s=reg256#1
# asm 2: vsubpd 608(<input_0=%rdi),<r7=%ymm10,>s=%ymm0
vsubpd 608(%rdi),%ymm10,%ymm0

# qhasm: mem256[input_0 + 224] aligned= s
# asm 1: vmovapd   <s=reg256#1,224(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,224(<input_0=%rdi)
vmovapd   %ymm0,224(%rdi)

# qhasm: 4x s = approx r8 - mem256[input_0 + 640]
# asm 1: vsubpd 640(<input_0=int64#1),<r8=reg256#12,>s=reg256#1
# asm 2: vsubpd 640(<input_0=%rdi),<r8=%ymm11,>s=%ymm0
vsubpd 640(%rdi),%ymm11,%ymm0

# qhasm: mem256[input_0 + 256] aligned= s
# asm 1: vmovapd   <s=reg256#1,256(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,256(<input_0=%rdi)
vmovapd   %ymm0,256(%rdi)

# qhasm: 4x s = approx r9 - mem256[input_0 + 672]
# asm 1: vsubpd 672(<input_0=int64#1),<r9=reg256#2,>s=reg256#1
# asm 2: vsubpd 672(<input_0=%rdi),<r9=%ymm1,>s=%ymm0
vsubpd 672(%rdi),%ymm1,%ymm0

# qhasm: mem256[input_0 + 288] aligned= s
# asm 1: vmovapd   <s=reg256#1,288(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,288(<input_0=%rdi)
vmovapd   %ymm0,288(%rdi)

# qhasm: 4x s = approx r10 - mem256[input_0 + 704]
# asm 1: vsubpd 704(<input_0=int64#1),<r10=reg256#13,>s=reg256#1
# asm 2: vsubpd 704(<input_0=%rdi),<r10=%ymm12,>s=%ymm0
vsubpd 704(%rdi),%ymm12,%ymm0

# qhasm: mem256[input_0 + 320] aligned= s
# asm 1: vmovapd   <s=reg256#1,320(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,320(<input_0=%rdi)
vmovapd   %ymm0,320(%rdi)

# qhasm: 4x s = approx r11 - mem256[input_0 + 736]
# asm 1: vsubpd 736(<input_0=int64#1),<r11=reg256#3,>s=reg256#1
# asm 2: vsubpd 736(<input_0=%rdi),<r11=%ymm2,>s=%ymm0
vsubpd 736(%rdi),%ymm2,%ymm0

# qhasm: mem256[input_0 + 352] aligned= s
# asm 1: vmovapd   <s=reg256#1,352(<input_0=int64#1)
# asm 2: vmovapd   <s=%ymm0,352(<input_0=%rdi)
vmovapd   %ymm0,352(%rdi)

# qhasm: return
add %r11,%rsp
ret
