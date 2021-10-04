
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

# qhasm: reg256 s

# qhasm: reg256 s0

# qhasm: reg256 s1

# qhasm: reg256 s2

# qhasm: reg256 s3

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

# qhasm: enter ge4x_add_p1p1_asm
.p2align 5
.global _ge4x_add_p1p1_asm
.global ge4x_add_p1p1_asm
_ge4x_add_p1p1_asm:
ge4x_add_p1p1_asm:
mov %rsp,%r11
and $31,%r11
add $0,%r11
sub %r11,%rsp

# qhasm: input_3 = Gk
# asm 1: mov  $Gk,>input_3=int64#4
# asm 2: mov  $Gk,>input_3=%rcx
mov  $Gk,%rcx

# qhasm: r0 aligned= mem256[input_1 + 384]
# asm 1: vmovapd   384(<input_1=int64#2),>r0=reg256#1
# asm 2: vmovapd   384(<input_1=%rsi),>r0=%ymm0
vmovapd   384(%rsi),%ymm0

# qhasm: r1 aligned= mem256[input_1 + 416]
# asm 1: vmovapd   416(<input_1=int64#2),>r1=reg256#2
# asm 2: vmovapd   416(<input_1=%rsi),>r1=%ymm1
vmovapd   416(%rsi),%ymm1

# qhasm: r2 aligned= mem256[input_1 + 448]
# asm 1: vmovapd   448(<input_1=int64#2),>r2=reg256#3
# asm 2: vmovapd   448(<input_1=%rsi),>r2=%ymm2
vmovapd   448(%rsi),%ymm2

# qhasm: r3 aligned= mem256[input_1 + 480]
# asm 1: vmovapd   480(<input_1=int64#2),>r3=reg256#4
# asm 2: vmovapd   480(<input_1=%rsi),>r3=%ymm3
vmovapd   480(%rsi),%ymm3

# qhasm: r4 aligned= mem256[input_1 + 512]
# asm 1: vmovapd   512(<input_1=int64#2),>r4=reg256#5
# asm 2: vmovapd   512(<input_1=%rsi),>r4=%ymm4
vmovapd   512(%rsi),%ymm4

# qhasm: r5 aligned= mem256[input_1 + 544]
# asm 1: vmovapd   544(<input_1=int64#2),>r5=reg256#6
# asm 2: vmovapd   544(<input_1=%rsi),>r5=%ymm5
vmovapd   544(%rsi),%ymm5

# qhasm: r6 aligned= mem256[input_1 + 576]
# asm 1: vmovapd   576(<input_1=int64#2),>r6=reg256#7
# asm 2: vmovapd   576(<input_1=%rsi),>r6=%ymm6
vmovapd   576(%rsi),%ymm6

# qhasm: r7 aligned= mem256[input_1 + 608]
# asm 1: vmovapd   608(<input_1=int64#2),>r7=reg256#8
# asm 2: vmovapd   608(<input_1=%rsi),>r7=%ymm7
vmovapd   608(%rsi),%ymm7

# qhasm: r8 aligned= mem256[input_1 + 640]
# asm 1: vmovapd   640(<input_1=int64#2),>r8=reg256#9
# asm 2: vmovapd   640(<input_1=%rsi),>r8=%ymm8
vmovapd   640(%rsi),%ymm8

# qhasm: r9 aligned= mem256[input_1 + 672]
# asm 1: vmovapd   672(<input_1=int64#2),>r9=reg256#10
# asm 2: vmovapd   672(<input_1=%rsi),>r9=%ymm9
vmovapd   672(%rsi),%ymm9

# qhasm: r10 aligned= mem256[input_1 + 704]
# asm 1: vmovapd   704(<input_1=int64#2),>r10=reg256#11
# asm 2: vmovapd   704(<input_1=%rsi),>r10=%ymm10
vmovapd   704(%rsi),%ymm10

# qhasm: r11 aligned= mem256[input_1 + 736]
# asm 1: vmovapd   736(<input_1=int64#2),>r11=reg256#12
# asm 2: vmovapd   736(<input_1=%rsi),>r11=%ymm11
vmovapd   736(%rsi),%ymm11

# qhasm: 4x s0 = approx r0 - mem256[input_1 + 0]
# asm 1: vsubpd 0(<input_1=int64#2),<r0=reg256#1,>s0=reg256#13
# asm 2: vsubpd 0(<input_1=%rsi),<r0=%ymm0,>s0=%ymm12
vsubpd 0(%rsi),%ymm0,%ymm12

# qhasm: 4x s1 = approx r1 - mem256[input_1 + 32]
# asm 1: vsubpd 32(<input_1=int64#2),<r1=reg256#2,>s1=reg256#14
# asm 2: vsubpd 32(<input_1=%rsi),<r1=%ymm1,>s1=%ymm13
vsubpd 32(%rsi),%ymm1,%ymm13

# qhasm: 4x s2 = approx r2 - mem256[input_1 + 64]
# asm 1: vsubpd 64(<input_1=int64#2),<r2=reg256#3,>s2=reg256#15
# asm 2: vsubpd 64(<input_1=%rsi),<r2=%ymm2,>s2=%ymm14
vsubpd 64(%rsi),%ymm2,%ymm14

# qhasm: 4x s3 = approx r3 - mem256[input_1 + 96]
# asm 1: vsubpd 96(<input_1=int64#2),<r3=reg256#4,>s3=reg256#16
# asm 2: vsubpd 96(<input_1=%rsi),<r3=%ymm3,>s3=%ymm15
vsubpd 96(%rsi),%ymm3,%ymm15

# qhasm: mem256[input_0 + 384] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,384(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,384(<input_0=%rdi)
vmovapd   %ymm12,384(%rdi)

# qhasm: mem256[input_0 + 416] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,416(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,416(<input_0=%rdi)
vmovapd   %ymm13,416(%rdi)

# qhasm: mem256[input_0 + 448] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,448(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,448(<input_0=%rdi)
vmovapd   %ymm14,448(%rdi)

# qhasm: mem256[input_0 + 480] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,480(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,480(<input_0=%rdi)
vmovapd   %ymm15,480(%rdi)

# qhasm: 4x s0 = approx r4 - mem256[input_1 + 128]
# asm 1: vsubpd 128(<input_1=int64#2),<r4=reg256#5,>s0=reg256#13
# asm 2: vsubpd 128(<input_1=%rsi),<r4=%ymm4,>s0=%ymm12
vsubpd 128(%rsi),%ymm4,%ymm12

# qhasm: 4x s1 = approx r5 - mem256[input_1 + 160]
# asm 1: vsubpd 160(<input_1=int64#2),<r5=reg256#6,>s1=reg256#14
# asm 2: vsubpd 160(<input_1=%rsi),<r5=%ymm5,>s1=%ymm13
vsubpd 160(%rsi),%ymm5,%ymm13

# qhasm: 4x s2 = approx r6 - mem256[input_1 + 192]
# asm 1: vsubpd 192(<input_1=int64#2),<r6=reg256#7,>s2=reg256#15
# asm 2: vsubpd 192(<input_1=%rsi),<r6=%ymm6,>s2=%ymm14
vsubpd 192(%rsi),%ymm6,%ymm14

# qhasm: 4x s3 = approx r7 - mem256[input_1 + 224]
# asm 1: vsubpd 224(<input_1=int64#2),<r7=reg256#8,>s3=reg256#16
# asm 2: vsubpd 224(<input_1=%rsi),<r7=%ymm7,>s3=%ymm15
vsubpd 224(%rsi),%ymm7,%ymm15

# qhasm: mem256[input_0 + 512] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,512(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,512(<input_0=%rdi)
vmovapd   %ymm12,512(%rdi)

# qhasm: mem256[input_0 + 544] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,544(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,544(<input_0=%rdi)
vmovapd   %ymm13,544(%rdi)

# qhasm: mem256[input_0 + 576] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,576(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,576(<input_0=%rdi)
vmovapd   %ymm14,576(%rdi)

# qhasm: mem256[input_0 + 608] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,608(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,608(<input_0=%rdi)
vmovapd   %ymm15,608(%rdi)

# qhasm: 4x s0 = approx r8 - mem256[input_1 + 256]
# asm 1: vsubpd 256(<input_1=int64#2),<r8=reg256#9,>s0=reg256#13
# asm 2: vsubpd 256(<input_1=%rsi),<r8=%ymm8,>s0=%ymm12
vsubpd 256(%rsi),%ymm8,%ymm12

# qhasm: 4x s1 = approx r9 - mem256[input_1 + 288]
# asm 1: vsubpd 288(<input_1=int64#2),<r9=reg256#10,>s1=reg256#14
# asm 2: vsubpd 288(<input_1=%rsi),<r9=%ymm9,>s1=%ymm13
vsubpd 288(%rsi),%ymm9,%ymm13

# qhasm: 4x s2 = approx r10 - mem256[input_1 + 320]
# asm 1: vsubpd 320(<input_1=int64#2),<r10=reg256#11,>s2=reg256#15
# asm 2: vsubpd 320(<input_1=%rsi),<r10=%ymm10,>s2=%ymm14
vsubpd 320(%rsi),%ymm10,%ymm14

# qhasm: 4x s3 = approx r11 - mem256[input_1 + 352]
# asm 1: vsubpd 352(<input_1=int64#2),<r11=reg256#12,>s3=reg256#16
# asm 2: vsubpd 352(<input_1=%rsi),<r11=%ymm11,>s3=%ymm15
vsubpd 352(%rsi),%ymm11,%ymm15

# qhasm: mem256[input_0 + 640] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,640(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,640(<input_0=%rdi)
vmovapd   %ymm12,640(%rdi)

# qhasm: mem256[input_0 + 672] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,672(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,672(<input_0=%rdi)
vmovapd   %ymm13,672(%rdi)

# qhasm: mem256[input_0 + 704] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,704(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,704(<input_0=%rdi)
vmovapd   %ymm14,704(%rdi)

# qhasm: mem256[input_0 + 736] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,736(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,736(<input_0=%rdi)
vmovapd   %ymm15,736(%rdi)

# qhasm: 4x s0 = approx r0 + mem256[input_1 + 0]
# asm 1: vaddpd 0(<input_1=int64#2),<r0=reg256#1,>s0=reg256#1
# asm 2: vaddpd 0(<input_1=%rsi),<r0=%ymm0,>s0=%ymm0
vaddpd 0(%rsi),%ymm0,%ymm0

# qhasm: 4x s1 = approx r1 + mem256[input_1 + 32]
# asm 1: vaddpd 32(<input_1=int64#2),<r1=reg256#2,>s1=reg256#2
# asm 2: vaddpd 32(<input_1=%rsi),<r1=%ymm1,>s1=%ymm1
vaddpd 32(%rsi),%ymm1,%ymm1

# qhasm: 4x s2 = approx r2 + mem256[input_1 + 64]
# asm 1: vaddpd 64(<input_1=int64#2),<r2=reg256#3,>s2=reg256#3
# asm 2: vaddpd 64(<input_1=%rsi),<r2=%ymm2,>s2=%ymm2
vaddpd 64(%rsi),%ymm2,%ymm2

# qhasm: 4x s3 = approx r3 + mem256[input_1 + 96]
# asm 1: vaddpd 96(<input_1=int64#2),<r3=reg256#4,>s3=reg256#4
# asm 2: vaddpd 96(<input_1=%rsi),<r3=%ymm3,>s3=%ymm3
vaddpd 96(%rsi),%ymm3,%ymm3

# qhasm: mem256[input_0 + 768] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,768(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,768(<input_0=%rdi)
vmovapd   %ymm0,768(%rdi)

# qhasm: mem256[input_0 + 800] aligned= s1
# asm 1: vmovapd   <s1=reg256#2,800(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm1,800(<input_0=%rdi)
vmovapd   %ymm1,800(%rdi)

# qhasm: mem256[input_0 + 832] aligned= s2
# asm 1: vmovapd   <s2=reg256#3,832(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm2,832(<input_0=%rdi)
vmovapd   %ymm2,832(%rdi)

# qhasm: mem256[input_0 + 864] aligned= s3
# asm 1: vmovapd   <s3=reg256#4,864(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm3,864(<input_0=%rdi)
vmovapd   %ymm3,864(%rdi)

# qhasm: 4x s0 = approx r4 + mem256[input_1 + 128]
# asm 1: vaddpd 128(<input_1=int64#2),<r4=reg256#5,>s0=reg256#1
# asm 2: vaddpd 128(<input_1=%rsi),<r4=%ymm4,>s0=%ymm0
vaddpd 128(%rsi),%ymm4,%ymm0

# qhasm: 4x s1 = approx r5 + mem256[input_1 + 160]
# asm 1: vaddpd 160(<input_1=int64#2),<r5=reg256#6,>s1=reg256#2
# asm 2: vaddpd 160(<input_1=%rsi),<r5=%ymm5,>s1=%ymm1
vaddpd 160(%rsi),%ymm5,%ymm1

# qhasm: 4x s2 = approx r6 + mem256[input_1 + 192]
# asm 1: vaddpd 192(<input_1=int64#2),<r6=reg256#7,>s2=reg256#3
# asm 2: vaddpd 192(<input_1=%rsi),<r6=%ymm6,>s2=%ymm2
vaddpd 192(%rsi),%ymm6,%ymm2

# qhasm: 4x s3 = approx r7 + mem256[input_1 + 224]
# asm 1: vaddpd 224(<input_1=int64#2),<r7=reg256#8,>s3=reg256#4
# asm 2: vaddpd 224(<input_1=%rsi),<r7=%ymm7,>s3=%ymm3
vaddpd 224(%rsi),%ymm7,%ymm3

# qhasm: mem256[input_0 + 896] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,896(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,896(<input_0=%rdi)
vmovapd   %ymm0,896(%rdi)

# qhasm: mem256[input_0 + 928] aligned= s1
# asm 1: vmovapd   <s1=reg256#2,928(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm1,928(<input_0=%rdi)
vmovapd   %ymm1,928(%rdi)

# qhasm: mem256[input_0 + 960] aligned= s2
# asm 1: vmovapd   <s2=reg256#3,960(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm2,960(<input_0=%rdi)
vmovapd   %ymm2,960(%rdi)

# qhasm: mem256[input_0 + 992] aligned= s3
# asm 1: vmovapd   <s3=reg256#4,992(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm3,992(<input_0=%rdi)
vmovapd   %ymm3,992(%rdi)

# qhasm: 4x s0 = approx r8 + mem256[input_1 + 256]
# asm 1: vaddpd 256(<input_1=int64#2),<r8=reg256#9,>s0=reg256#1
# asm 2: vaddpd 256(<input_1=%rsi),<r8=%ymm8,>s0=%ymm0
vaddpd 256(%rsi),%ymm8,%ymm0

# qhasm: 4x s1 = approx r9 + mem256[input_1 + 288]
# asm 1: vaddpd 288(<input_1=int64#2),<r9=reg256#10,>s1=reg256#2
# asm 2: vaddpd 288(<input_1=%rsi),<r9=%ymm9,>s1=%ymm1
vaddpd 288(%rsi),%ymm9,%ymm1

# qhasm: 4x s2 = approx r10 + mem256[input_1 + 320]
# asm 1: vaddpd 320(<input_1=int64#2),<r10=reg256#11,>s2=reg256#3
# asm 2: vaddpd 320(<input_1=%rsi),<r10=%ymm10,>s2=%ymm2
vaddpd 320(%rsi),%ymm10,%ymm2

# qhasm: 4x s3 = approx r11 + mem256[input_1 + 352]
# asm 1: vaddpd 352(<input_1=int64#2),<r11=reg256#12,>s3=reg256#4
# asm 2: vaddpd 352(<input_1=%rsi),<r11=%ymm11,>s3=%ymm3
vaddpd 352(%rsi),%ymm11,%ymm3

# qhasm: mem256[input_0 + 1024] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,1024(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,1024(<input_0=%rdi)
vmovapd   %ymm0,1024(%rdi)

# qhasm: mem256[input_0 + 1056] aligned= s1
# asm 1: vmovapd   <s1=reg256#2,1056(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm1,1056(<input_0=%rdi)
vmovapd   %ymm1,1056(%rdi)

# qhasm: mem256[input_0 + 1088] aligned= s2
# asm 1: vmovapd   <s2=reg256#3,1088(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm2,1088(<input_0=%rdi)
vmovapd   %ymm2,1088(%rdi)

# qhasm: mem256[input_0 + 1120] aligned= s3
# asm 1: vmovapd   <s3=reg256#4,1120(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm3,1120(<input_0=%rdi)
vmovapd   %ymm3,1120(%rdi)

# qhasm: r0 aligned= mem256[input_2 + 384]
# asm 1: vmovapd   384(<input_2=int64#3),>r0=reg256#1
# asm 2: vmovapd   384(<input_2=%rdx),>r0=%ymm0
vmovapd   384(%rdx),%ymm0

# qhasm: r1 aligned= mem256[input_2 + 416]
# asm 1: vmovapd   416(<input_2=int64#3),>r1=reg256#2
# asm 2: vmovapd   416(<input_2=%rdx),>r1=%ymm1
vmovapd   416(%rdx),%ymm1

# qhasm: r2 aligned= mem256[input_2 + 448]
# asm 1: vmovapd   448(<input_2=int64#3),>r2=reg256#3
# asm 2: vmovapd   448(<input_2=%rdx),>r2=%ymm2
vmovapd   448(%rdx),%ymm2

# qhasm: r3 aligned= mem256[input_2 + 480]
# asm 1: vmovapd   480(<input_2=int64#3),>r3=reg256#4
# asm 2: vmovapd   480(<input_2=%rdx),>r3=%ymm3
vmovapd   480(%rdx),%ymm3

# qhasm: r4 aligned= mem256[input_2 + 512]
# asm 1: vmovapd   512(<input_2=int64#3),>r4=reg256#5
# asm 2: vmovapd   512(<input_2=%rdx),>r4=%ymm4
vmovapd   512(%rdx),%ymm4

# qhasm: r5 aligned= mem256[input_2 + 544]
# asm 1: vmovapd   544(<input_2=int64#3),>r5=reg256#6
# asm 2: vmovapd   544(<input_2=%rdx),>r5=%ymm5
vmovapd   544(%rdx),%ymm5

# qhasm: r6 aligned= mem256[input_2 + 576]
# asm 1: vmovapd   576(<input_2=int64#3),>r6=reg256#7
# asm 2: vmovapd   576(<input_2=%rdx),>r6=%ymm6
vmovapd   576(%rdx),%ymm6

# qhasm: r7 aligned= mem256[input_2 + 608]
# asm 1: vmovapd   608(<input_2=int64#3),>r7=reg256#8
# asm 2: vmovapd   608(<input_2=%rdx),>r7=%ymm7
vmovapd   608(%rdx),%ymm7

# qhasm: r8 aligned= mem256[input_2 + 640]
# asm 1: vmovapd   640(<input_2=int64#3),>r8=reg256#9
# asm 2: vmovapd   640(<input_2=%rdx),>r8=%ymm8
vmovapd   640(%rdx),%ymm8

# qhasm: r9 aligned= mem256[input_2 + 672]
# asm 1: vmovapd   672(<input_2=int64#3),>r9=reg256#10
# asm 2: vmovapd   672(<input_2=%rdx),>r9=%ymm9
vmovapd   672(%rdx),%ymm9

# qhasm: r10 aligned= mem256[input_2 + 704]
# asm 1: vmovapd   704(<input_2=int64#3),>r10=reg256#11
# asm 2: vmovapd   704(<input_2=%rdx),>r10=%ymm10
vmovapd   704(%rdx),%ymm10

# qhasm: r11 aligned= mem256[input_2 + 736]
# asm 1: vmovapd   736(<input_2=int64#3),>r11=reg256#12
# asm 2: vmovapd   736(<input_2=%rdx),>r11=%ymm11
vmovapd   736(%rdx),%ymm11

# qhasm: 4x s0 = approx r0 - mem256[input_2 + 0]
# asm 1: vsubpd 0(<input_2=int64#3),<r0=reg256#1,>s0=reg256#13
# asm 2: vsubpd 0(<input_2=%rdx),<r0=%ymm0,>s0=%ymm12
vsubpd 0(%rdx),%ymm0,%ymm12

# qhasm: 4x s1 = approx r1 - mem256[input_2 + 32]
# asm 1: vsubpd 32(<input_2=int64#3),<r1=reg256#2,>s1=reg256#14
# asm 2: vsubpd 32(<input_2=%rdx),<r1=%ymm1,>s1=%ymm13
vsubpd 32(%rdx),%ymm1,%ymm13

# qhasm: 4x s2 = approx r2 - mem256[input_2 + 64]
# asm 1: vsubpd 64(<input_2=int64#3),<r2=reg256#3,>s2=reg256#15
# asm 2: vsubpd 64(<input_2=%rdx),<r2=%ymm2,>s2=%ymm14
vsubpd 64(%rdx),%ymm2,%ymm14

# qhasm: 4x s3 = approx r3 - mem256[input_2 + 96]
# asm 1: vsubpd 96(<input_2=int64#3),<r3=reg256#4,>s3=reg256#16
# asm 2: vsubpd 96(<input_2=%rdx),<r3=%ymm3,>s3=%ymm15
vsubpd 96(%rdx),%ymm3,%ymm15

# qhasm: mem256[input_0 + 0] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,0(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,0(<input_0=%rdi)
vmovapd   %ymm12,0(%rdi)

# qhasm: mem256[input_0 + 32] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,32(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,32(<input_0=%rdi)
vmovapd   %ymm13,32(%rdi)

# qhasm: mem256[input_0 + 64] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,64(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,64(<input_0=%rdi)
vmovapd   %ymm14,64(%rdi)

# qhasm: mem256[input_0 + 96] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,96(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,96(<input_0=%rdi)
vmovapd   %ymm15,96(%rdi)

# qhasm: 4x s0 = approx r4 - mem256[input_2 + 128]
# asm 1: vsubpd 128(<input_2=int64#3),<r4=reg256#5,>s0=reg256#13
# asm 2: vsubpd 128(<input_2=%rdx),<r4=%ymm4,>s0=%ymm12
vsubpd 128(%rdx),%ymm4,%ymm12

# qhasm: 4x s1 = approx r5 - mem256[input_2 + 160]
# asm 1: vsubpd 160(<input_2=int64#3),<r5=reg256#6,>s1=reg256#14
# asm 2: vsubpd 160(<input_2=%rdx),<r5=%ymm5,>s1=%ymm13
vsubpd 160(%rdx),%ymm5,%ymm13

# qhasm: 4x s2 = approx r6 - mem256[input_2 + 192]
# asm 1: vsubpd 192(<input_2=int64#3),<r6=reg256#7,>s2=reg256#15
# asm 2: vsubpd 192(<input_2=%rdx),<r6=%ymm6,>s2=%ymm14
vsubpd 192(%rdx),%ymm6,%ymm14

# qhasm: 4x s3 = approx r7 - mem256[input_2 + 224]
# asm 1: vsubpd 224(<input_2=int64#3),<r7=reg256#8,>s3=reg256#16
# asm 2: vsubpd 224(<input_2=%rdx),<r7=%ymm7,>s3=%ymm15
vsubpd 224(%rdx),%ymm7,%ymm15

# qhasm: mem256[input_0 + 128] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,128(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,128(<input_0=%rdi)
vmovapd   %ymm12,128(%rdi)

# qhasm: mem256[input_0 + 160] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,160(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,160(<input_0=%rdi)
vmovapd   %ymm13,160(%rdi)

# qhasm: mem256[input_0 + 192] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,192(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,192(<input_0=%rdi)
vmovapd   %ymm14,192(%rdi)

# qhasm: mem256[input_0 + 224] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,224(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,224(<input_0=%rdi)
vmovapd   %ymm15,224(%rdi)

# qhasm: 4x s0 = approx r8 - mem256[input_2 + 256]
# asm 1: vsubpd 256(<input_2=int64#3),<r8=reg256#9,>s0=reg256#13
# asm 2: vsubpd 256(<input_2=%rdx),<r8=%ymm8,>s0=%ymm12
vsubpd 256(%rdx),%ymm8,%ymm12

# qhasm: 4x s1 = approx r9 - mem256[input_2 + 288]
# asm 1: vsubpd 288(<input_2=int64#3),<r9=reg256#10,>s1=reg256#14
# asm 2: vsubpd 288(<input_2=%rdx),<r9=%ymm9,>s1=%ymm13
vsubpd 288(%rdx),%ymm9,%ymm13

# qhasm: 4x s2 = approx r10 - mem256[input_2 + 320]
# asm 1: vsubpd 320(<input_2=int64#3),<r10=reg256#11,>s2=reg256#15
# asm 2: vsubpd 320(<input_2=%rdx),<r10=%ymm10,>s2=%ymm14
vsubpd 320(%rdx),%ymm10,%ymm14

# qhasm: 4x s3 = approx r11 - mem256[input_2 + 352]
# asm 1: vsubpd 352(<input_2=int64#3),<r11=reg256#12,>s3=reg256#16
# asm 2: vsubpd 352(<input_2=%rdx),<r11=%ymm11,>s3=%ymm15
vsubpd 352(%rdx),%ymm11,%ymm15

# qhasm: mem256[input_0 + 256] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,256(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,256(<input_0=%rdi)
vmovapd   %ymm12,256(%rdi)

# qhasm: mem256[input_0 + 288] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,288(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,288(<input_0=%rdi)
vmovapd   %ymm13,288(%rdi)

# qhasm: mem256[input_0 + 320] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,320(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,320(<input_0=%rdi)
vmovapd   %ymm14,320(%rdi)

# qhasm: mem256[input_0 + 352] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,352(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,352(<input_0=%rdi)
vmovapd   %ymm15,352(%rdi)

# qhasm: 4x s0 = approx r0 + mem256[input_2 + 0]
# asm 1: vaddpd 0(<input_2=int64#3),<r0=reg256#1,>s0=reg256#1
# asm 2: vaddpd 0(<input_2=%rdx),<r0=%ymm0,>s0=%ymm0
vaddpd 0(%rdx),%ymm0,%ymm0

# qhasm: 4x s1 = approx r1 + mem256[input_2 + 32]
# asm 1: vaddpd 32(<input_2=int64#3),<r1=reg256#2,>s1=reg256#2
# asm 2: vaddpd 32(<input_2=%rdx),<r1=%ymm1,>s1=%ymm1
vaddpd 32(%rdx),%ymm1,%ymm1

# qhasm: 4x s2 = approx r2 + mem256[input_2 + 64]
# asm 1: vaddpd 64(<input_2=int64#3),<r2=reg256#3,>s2=reg256#3
# asm 2: vaddpd 64(<input_2=%rdx),<r2=%ymm2,>s2=%ymm2
vaddpd 64(%rdx),%ymm2,%ymm2

# qhasm: 4x s3 = approx r3 + mem256[input_2 + 96]
# asm 1: vaddpd 96(<input_2=int64#3),<r3=reg256#4,>s3=reg256#4
# asm 2: vaddpd 96(<input_2=%rdx),<r3=%ymm3,>s3=%ymm3
vaddpd 96(%rdx),%ymm3,%ymm3

# qhasm: mem256[input_0 + 1152] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,1152(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,1152(<input_0=%rdi)
vmovapd   %ymm0,1152(%rdi)

# qhasm: mem256[input_0 + 1184] aligned= s1
# asm 1: vmovapd   <s1=reg256#2,1184(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm1,1184(<input_0=%rdi)
vmovapd   %ymm1,1184(%rdi)

# qhasm: mem256[input_0 + 1216] aligned= s2
# asm 1: vmovapd   <s2=reg256#3,1216(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm2,1216(<input_0=%rdi)
vmovapd   %ymm2,1216(%rdi)

# qhasm: mem256[input_0 + 1248] aligned= s3
# asm 1: vmovapd   <s3=reg256#4,1248(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm3,1248(<input_0=%rdi)
vmovapd   %ymm3,1248(%rdi)

# qhasm: 4x s0 = approx r4 + mem256[input_2 + 128]
# asm 1: vaddpd 128(<input_2=int64#3),<r4=reg256#5,>s0=reg256#1
# asm 2: vaddpd 128(<input_2=%rdx),<r4=%ymm4,>s0=%ymm0
vaddpd 128(%rdx),%ymm4,%ymm0

# qhasm: 4x s1 = approx r5 + mem256[input_2 + 160]
# asm 1: vaddpd 160(<input_2=int64#3),<r5=reg256#6,>s1=reg256#2
# asm 2: vaddpd 160(<input_2=%rdx),<r5=%ymm5,>s1=%ymm1
vaddpd 160(%rdx),%ymm5,%ymm1

# qhasm: 4x s2 = approx r6 + mem256[input_2 + 192]
# asm 1: vaddpd 192(<input_2=int64#3),<r6=reg256#7,>s2=reg256#3
# asm 2: vaddpd 192(<input_2=%rdx),<r6=%ymm6,>s2=%ymm2
vaddpd 192(%rdx),%ymm6,%ymm2

# qhasm: 4x s3 = approx r7 + mem256[input_2 + 224]
# asm 1: vaddpd 224(<input_2=int64#3),<r7=reg256#8,>s3=reg256#4
# asm 2: vaddpd 224(<input_2=%rdx),<r7=%ymm7,>s3=%ymm3
vaddpd 224(%rdx),%ymm7,%ymm3

# qhasm: mem256[input_0 + 1280] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,1280(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,1280(<input_0=%rdi)
vmovapd   %ymm0,1280(%rdi)

# qhasm: mem256[input_0 + 1312] aligned= s1
# asm 1: vmovapd   <s1=reg256#2,1312(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm1,1312(<input_0=%rdi)
vmovapd   %ymm1,1312(%rdi)

# qhasm: mem256[input_0 + 1344] aligned= s2
# asm 1: vmovapd   <s2=reg256#3,1344(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm2,1344(<input_0=%rdi)
vmovapd   %ymm2,1344(%rdi)

# qhasm: mem256[input_0 + 1376] aligned= s3
# asm 1: vmovapd   <s3=reg256#4,1376(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm3,1376(<input_0=%rdi)
vmovapd   %ymm3,1376(%rdi)

# qhasm: 4x s0 = approx r8 + mem256[input_2 + 256]
# asm 1: vaddpd 256(<input_2=int64#3),<r8=reg256#9,>s0=reg256#1
# asm 2: vaddpd 256(<input_2=%rdx),<r8=%ymm8,>s0=%ymm0
vaddpd 256(%rdx),%ymm8,%ymm0

# qhasm: 4x s1 = approx r9 + mem256[input_2 + 288]
# asm 1: vaddpd 288(<input_2=int64#3),<r9=reg256#10,>s1=reg256#2
# asm 2: vaddpd 288(<input_2=%rdx),<r9=%ymm9,>s1=%ymm1
vaddpd 288(%rdx),%ymm9,%ymm1

# qhasm: 4x s2 = approx r10 + mem256[input_2 + 320]
# asm 1: vaddpd 320(<input_2=int64#3),<r10=reg256#11,>s2=reg256#3
# asm 2: vaddpd 320(<input_2=%rdx),<r10=%ymm10,>s2=%ymm2
vaddpd 320(%rdx),%ymm10,%ymm2

# qhasm: 4x s3 = approx r11 + mem256[input_2 + 352]
# asm 1: vaddpd 352(<input_2=int64#3),<r11=reg256#12,>s3=reg256#4
# asm 2: vaddpd 352(<input_2=%rdx),<r11=%ymm11,>s3=%ymm3
vaddpd 352(%rdx),%ymm11,%ymm3

# qhasm: mem256[input_0 + 1408] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,1408(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,1408(<input_0=%rdi)
vmovapd   %ymm0,1408(%rdi)

# qhasm: mem256[input_0 + 1440] aligned= s1
# asm 1: vmovapd   <s1=reg256#2,1440(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm1,1440(<input_0=%rdi)
vmovapd   %ymm1,1440(%rdi)

# qhasm: mem256[input_0 + 1472] aligned= s2
# asm 1: vmovapd   <s2=reg256#3,1472(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm2,1472(<input_0=%rdi)
vmovapd   %ymm2,1472(%rdi)

# qhasm: mem256[input_0 + 1504] aligned= s3
# asm 1: vmovapd   <s3=reg256#4,1504(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm3,1504(<input_0=%rdi)
vmovapd   %ymm3,1504(%rdi)

# qhasm:   mul_nineteen aligned= mem256[scale19]
# asm 1: vmovapd scale19,>mul_nineteen=reg256#1
# asm 2: vmovapd scale19,>mul_nineteen=%ymm0
vmovapd scale19,%ymm0

# qhasm:   mul_x0 aligned= mem256[input_0 + 384]
# asm 1: vmovapd   384(<input_0=int64#1),>mul_x0=reg256#2
# asm 2: vmovapd   384(<input_0=%rdi),>mul_x0=%ymm1
vmovapd   384(%rdi),%ymm1

# qhasm:   mul_y0 aligned= mem256[input_0 + 0]
# asm 1: vmovapd   0(<input_0=int64#1),>mul_y0=reg256#3
# asm 2: vmovapd   0(<input_0=%rdi),>mul_y0=%ymm2
vmovapd   0(%rdi),%ymm2

# qhasm:   4x r0 = approx mul_x0 * mul_y0
# asm 1: vmulpd <mul_x0=reg256#2,<mul_y0=reg256#3,>r0=reg256#4
# asm 2: vmulpd <mul_x0=%ymm1,<mul_y0=%ymm2,>r0=%ymm3
vmulpd %ymm1,%ymm2,%ymm3

# qhasm:   4x r1 = approx mul_x0 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x0=reg256#2,>r1=reg256#5
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x0=%ymm1,>r1=%ymm4
vmulpd 32(%rdi),%ymm1,%ymm4

# qhasm:   4x r2 = approx mul_x0 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x0=reg256#2,>r2=reg256#6
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x0=%ymm1,>r2=%ymm5
vmulpd 64(%rdi),%ymm1,%ymm5

# qhasm:   4x r3 = approx mul_x0 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x0=reg256#2,>r3=reg256#7
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x0=%ymm1,>r3=%ymm6
vmulpd 96(%rdi),%ymm1,%ymm6

# qhasm:   4x r4 = approx mul_x0 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x0=reg256#2,>r4=reg256#8
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x0=%ymm1,>r4=%ymm7
vmulpd 128(%rdi),%ymm1,%ymm7

# qhasm:   4x r5 = approx mul_x0 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x0=reg256#2,>r5=reg256#9
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x0=%ymm1,>r5=%ymm8
vmulpd 160(%rdi),%ymm1,%ymm8

# qhasm:   4x r6 = approx mul_x0 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x0=reg256#2,>r6=reg256#10
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x0=%ymm1,>r6=%ymm9
vmulpd 192(%rdi),%ymm1,%ymm9

# qhasm:   4x r7 = approx mul_x0 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x0=reg256#2,>r7=reg256#11
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x0=%ymm1,>r7=%ymm10
vmulpd 224(%rdi),%ymm1,%ymm10

# qhasm:   4x r8 = approx mul_x0 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x0=reg256#2,>r8=reg256#12
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x0=%ymm1,>r8=%ymm11
vmulpd 256(%rdi),%ymm1,%ymm11

# qhasm:   4x r9 = approx mul_x0 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x0=reg256#2,>r9=reg256#13
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x0=%ymm1,>r9=%ymm12
vmulpd 288(%rdi),%ymm1,%ymm12

# qhasm:   4x r10 = approx mul_x0 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x0=reg256#2,>r10=reg256#14
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x0=%ymm1,>r10=%ymm13
vmulpd 320(%rdi),%ymm1,%ymm13

# qhasm:   4x r11 = approx mul_x0 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x0=reg256#2,>r11=reg256#2
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x0=%ymm1,>r11=%ymm1
vmulpd 352(%rdi),%ymm1,%ymm1

# qhasm:   mul_x1 aligned= mem256[input_0 + 416]
# asm 1: vmovapd   416(<input_0=int64#1),>mul_x1=reg256#15
# asm 2: vmovapd   416(<input_0=%rdi),>mul_x1=%ymm14
vmovapd   416(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mul_y0
# asm 1: vmulpd <mul_x1=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x1=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x1 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x1=reg256#15,>mul_x1=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x1=%ymm14,>mul_x1=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   mul_x2 aligned= mem256[input_0 + 448]
# asm 1: vmovapd   448(<input_0=int64#1),>mul_x2=reg256#15
# asm 2: vmovapd   448(<input_0=%rdi),>mul_x2=%ymm14
vmovapd   448(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mul_y0
# asm 1: vmulpd <mul_x2=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x2=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x2 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x2=reg256#15,>mul_x2=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x2=%ymm14,>mul_x2=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   mul_x3 aligned= mem256[input_0 + 480]
# asm 1: vmovapd   480(<input_0=int64#1),>mul_x3=reg256#15
# asm 2: vmovapd   480(<input_0=%rdi),>mul_x3=%ymm14
vmovapd   480(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mul_y0
# asm 1: vmulpd <mul_x3=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x3=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x3 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x3=reg256#15,>mul_x3=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x3=%ymm14,>mul_x3=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   mul_x4 aligned= mem256[input_0 + 512]
# asm 1: vmovapd   512(<input_0=int64#1),>mul_x4=reg256#15
# asm 2: vmovapd   512(<input_0=%rdi),>mul_x4=%ymm14
vmovapd   512(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mul_y0
# asm 1: vmulpd <mul_x4=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x4=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x4 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x4=reg256#15,>mul_x4=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x4=%ymm14,>mul_x4=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   mul_x5 aligned= mem256[input_0 + 544]
# asm 1: vmovapd   544(<input_0=int64#1),>mul_x5=reg256#15
# asm 2: vmovapd   544(<input_0=%rdi),>mul_x5=%ymm14
vmovapd   544(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mul_y0
# asm 1: vmulpd <mul_x5=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x5=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x5 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x5=reg256#15,>mul_x5=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x5=%ymm14,>mul_x5=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   mul_x6 aligned= mem256[input_0 + 576]
# asm 1: vmovapd   576(<input_0=int64#1),>mul_x6=reg256#15
# asm 2: vmovapd   576(<input_0=%rdi),>mul_x6=%ymm14
vmovapd   576(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mul_y0
# asm 1: vmulpd <mul_x6=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x6=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x6 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x6=reg256#15,>mul_x6=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x6=%ymm14,>mul_x6=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   mul_x7 aligned= mem256[input_0 + 608]
# asm 1: vmovapd   608(<input_0=int64#1),>mul_x7=reg256#15
# asm 2: vmovapd   608(<input_0=%rdi),>mul_x7=%ymm14
vmovapd   608(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mul_y0
# asm 1: vmulpd <mul_x7=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x7=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x7 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x7=reg256#15,>mul_x7=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x7=%ymm14,>mul_x7=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   mul_x8 aligned= mem256[input_0 + 640]
# asm 1: vmovapd   640(<input_0=int64#1),>mul_x8=reg256#15
# asm 2: vmovapd   640(<input_0=%rdi),>mul_x8=%ymm14
vmovapd   640(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mul_y0
# asm 1: vmulpd <mul_x8=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x8=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x8 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x8=reg256#15,>mul_x8=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x8=%ymm14,>mul_x8=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   mul_x9 aligned= mem256[input_0 + 672]
# asm 1: vmovapd   672(<input_0=int64#1),>mul_x9=reg256#15
# asm 2: vmovapd   672(<input_0=%rdi),>mul_x9=%ymm14
vmovapd   672(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mul_y0
# asm 1: vmulpd <mul_x9=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x9=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x9 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x9=reg256#15,>mul_x9=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x9=%ymm14,>mul_x9=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   mul_x10 aligned= mem256[input_0 + 704]
# asm 1: vmovapd   704(<input_0=int64#1),>mul_x10=reg256#15
# asm 2: vmovapd   704(<input_0=%rdi),>mul_x10=%ymm14
vmovapd   704(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mul_y0
# asm 1: vmulpd <mul_x10=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x10=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 32(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x10 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x10=reg256#15,>mul_x10=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x10=%ymm14,>mul_x10=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 64(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 96(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 128(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 160(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 192(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 224(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 256(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 288(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 320(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm14
vmulpd 352(%rdi),%ymm14,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   mul_x11 aligned= mem256[input_0 + 736]
# asm 1: vmovapd   736(<input_0=int64#1),>mul_x11=reg256#15
# asm 2: vmovapd   736(<input_0=%rdi),>mul_x11=%ymm14
vmovapd   736(%rdi),%ymm14

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

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 32]
# asm 1: vmulpd 32(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 32(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 32(%rdi),%ymm2,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 64]
# asm 1: vmulpd 64(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 64(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 64(%rdi),%ymm2,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 96]
# asm 1: vmulpd 96(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 96(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 96(%rdi),%ymm2,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 128]
# asm 1: vmulpd 128(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 128(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 128(%rdi),%ymm2,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 160]
# asm 1: vmulpd 160(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 160(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 160(%rdi),%ymm2,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 192]
# asm 1: vmulpd 192(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 192(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 192(%rdi),%ymm2,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 224]
# asm 1: vmulpd 224(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 224(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 224(%rdi),%ymm2,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 256]
# asm 1: vmulpd 256(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 256(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 256(%rdi),%ymm2,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 288]
# asm 1: vmulpd 288(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 288(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 288(%rdi),%ymm2,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 320]
# asm 1: vmulpd 320(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 320(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 320(%rdi),%ymm2,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 352]
# asm 1: vmulpd 352(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#3
# asm 2: vmulpd 352(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm2
vmulpd 352(%rdi),%ymm2,%ymm2

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

# qhasm: mem256[input_0 + 384] aligned= r0
# asm 1: vmovapd   <r0=reg256#1,384(<input_0=int64#1)
# asm 2: vmovapd   <r0=%ymm0,384(<input_0=%rdi)
vmovapd   %ymm0,384(%rdi)

# qhasm: mem256[input_0 + 416] aligned= r1
# asm 1: vmovapd   <r1=reg256#4,416(<input_0=int64#1)
# asm 2: vmovapd   <r1=%ymm3,416(<input_0=%rdi)
vmovapd   %ymm3,416(%rdi)

# qhasm: mem256[input_0 + 448] aligned= r2
# asm 1: vmovapd   <r2=reg256#6,448(<input_0=int64#1)
# asm 2: vmovapd   <r2=%ymm5,448(<input_0=%rdi)
vmovapd   %ymm5,448(%rdi)

# qhasm: mem256[input_0 + 480] aligned= r3
# asm 1: vmovapd   <r3=reg256#7,480(<input_0=int64#1)
# asm 2: vmovapd   <r3=%ymm6,480(<input_0=%rdi)
vmovapd   %ymm6,480(%rdi)

# qhasm: mem256[input_0 + 512] aligned= r4
# asm 1: vmovapd   <r4=reg256#8,512(<input_0=int64#1)
# asm 2: vmovapd   <r4=%ymm7,512(<input_0=%rdi)
vmovapd   %ymm7,512(%rdi)

# qhasm: mem256[input_0 + 544] aligned= r5
# asm 1: vmovapd   <r5=reg256#5,544(<input_0=int64#1)
# asm 2: vmovapd   <r5=%ymm4,544(<input_0=%rdi)
vmovapd   %ymm4,544(%rdi)

# qhasm: mem256[input_0 + 576] aligned= r6
# asm 1: vmovapd   <r6=reg256#10,576(<input_0=int64#1)
# asm 2: vmovapd   <r6=%ymm9,576(<input_0=%rdi)
vmovapd   %ymm9,576(%rdi)

# qhasm: mem256[input_0 + 608] aligned= r7
# asm 1: vmovapd   <r7=reg256#11,608(<input_0=int64#1)
# asm 2: vmovapd   <r7=%ymm10,608(<input_0=%rdi)
vmovapd   %ymm10,608(%rdi)

# qhasm: mem256[input_0 + 640] aligned= r8
# asm 1: vmovapd   <r8=reg256#12,640(<input_0=int64#1)
# asm 2: vmovapd   <r8=%ymm11,640(<input_0=%rdi)
vmovapd   %ymm11,640(%rdi)

# qhasm: mem256[input_0 + 672] aligned= r9
# asm 1: vmovapd   <r9=reg256#9,672(<input_0=int64#1)
# asm 2: vmovapd   <r9=%ymm8,672(<input_0=%rdi)
vmovapd   %ymm8,672(%rdi)

# qhasm: mem256[input_0 + 704] aligned= r10
# asm 1: vmovapd   <r10=reg256#3,704(<input_0=int64#1)
# asm 2: vmovapd   <r10=%ymm2,704(<input_0=%rdi)
vmovapd   %ymm2,704(%rdi)

# qhasm: mem256[input_0 + 736] aligned= r11
# asm 1: vmovapd   <r11=reg256#2,736(<input_0=int64#1)
# asm 2: vmovapd   <r11=%ymm1,736(<input_0=%rdi)
vmovapd   %ymm1,736(%rdi)

# qhasm:   mul_nineteen aligned= mem256[scale19]
# asm 1: vmovapd scale19,>mul_nineteen=reg256#1
# asm 2: vmovapd scale19,>mul_nineteen=%ymm0
vmovapd scale19,%ymm0

# qhasm:   mul_x0 aligned= mem256[input_0 + 768]
# asm 1: vmovapd   768(<input_0=int64#1),>mul_x0=reg256#2
# asm 2: vmovapd   768(<input_0=%rdi),>mul_x0=%ymm1
vmovapd   768(%rdi),%ymm1

# qhasm:   mul_y0 aligned= mem256[input_0 + 1152]
# asm 1: vmovapd   1152(<input_0=int64#1),>mul_y0=reg256#3
# asm 2: vmovapd   1152(<input_0=%rdi),>mul_y0=%ymm2
vmovapd   1152(%rdi),%ymm2

# qhasm:   4x r0 = approx mul_x0 * mul_y0
# asm 1: vmulpd <mul_x0=reg256#2,<mul_y0=reg256#3,>r0=reg256#4
# asm 2: vmulpd <mul_x0=%ymm1,<mul_y0=%ymm2,>r0=%ymm3
vmulpd %ymm1,%ymm2,%ymm3

# qhasm:   4x r1 = approx mul_x0 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x0=reg256#2,>r1=reg256#5
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x0=%ymm1,>r1=%ymm4
vmulpd 1184(%rdi),%ymm1,%ymm4

# qhasm:   4x r2 = approx mul_x0 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x0=reg256#2,>r2=reg256#6
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x0=%ymm1,>r2=%ymm5
vmulpd 1216(%rdi),%ymm1,%ymm5

# qhasm:   4x r3 = approx mul_x0 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x0=reg256#2,>r3=reg256#7
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x0=%ymm1,>r3=%ymm6
vmulpd 1248(%rdi),%ymm1,%ymm6

# qhasm:   4x r4 = approx mul_x0 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x0=reg256#2,>r4=reg256#8
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x0=%ymm1,>r4=%ymm7
vmulpd 1280(%rdi),%ymm1,%ymm7

# qhasm:   4x r5 = approx mul_x0 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x0=reg256#2,>r5=reg256#9
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x0=%ymm1,>r5=%ymm8
vmulpd 1312(%rdi),%ymm1,%ymm8

# qhasm:   4x r6 = approx mul_x0 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x0=reg256#2,>r6=reg256#10
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x0=%ymm1,>r6=%ymm9
vmulpd 1344(%rdi),%ymm1,%ymm9

# qhasm:   4x r7 = approx mul_x0 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x0=reg256#2,>r7=reg256#11
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x0=%ymm1,>r7=%ymm10
vmulpd 1376(%rdi),%ymm1,%ymm10

# qhasm:   4x r8 = approx mul_x0 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x0=reg256#2,>r8=reg256#12
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x0=%ymm1,>r8=%ymm11
vmulpd 1408(%rdi),%ymm1,%ymm11

# qhasm:   4x r9 = approx mul_x0 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x0=reg256#2,>r9=reg256#13
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x0=%ymm1,>r9=%ymm12
vmulpd 1440(%rdi),%ymm1,%ymm12

# qhasm:   4x r10 = approx mul_x0 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x0=reg256#2,>r10=reg256#14
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x0=%ymm1,>r10=%ymm13
vmulpd 1472(%rdi),%ymm1,%ymm13

# qhasm:   4x r11 = approx mul_x0 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x0=reg256#2,>r11=reg256#2
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x0=%ymm1,>r11=%ymm1
vmulpd 1504(%rdi),%ymm1,%ymm1

# qhasm:   mul_x1 aligned= mem256[input_0 + 800]
# asm 1: vmovapd   800(<input_0=int64#1),>mul_x1=reg256#15
# asm 2: vmovapd   800(<input_0=%rdi),>mul_x1=%ymm14
vmovapd   800(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mul_y0
# asm 1: vmulpd <mul_x1=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x1=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x1 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x1=reg256#15,>mul_x1=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x1=%ymm14,>mul_x1=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x1=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x1=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdi),%ymm14,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   mul_x2 aligned= mem256[input_0 + 832]
# asm 1: vmovapd   832(<input_0=int64#1),>mul_x2=reg256#15
# asm 2: vmovapd   832(<input_0=%rdi),>mul_x2=%ymm14
vmovapd   832(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mul_y0
# asm 1: vmulpd <mul_x2=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x2=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x2 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x2=reg256#15,>mul_x2=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x2=%ymm14,>mul_x2=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x2=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x2=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdi),%ymm14,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   mul_x3 aligned= mem256[input_0 + 864]
# asm 1: vmovapd   864(<input_0=int64#1),>mul_x3=reg256#15
# asm 2: vmovapd   864(<input_0=%rdi),>mul_x3=%ymm14
vmovapd   864(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mul_y0
# asm 1: vmulpd <mul_x3=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x3=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x3 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x3=reg256#15,>mul_x3=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x3=%ymm14,>mul_x3=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x3=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x3=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdi),%ymm14,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   mul_x4 aligned= mem256[input_0 + 896]
# asm 1: vmovapd   896(<input_0=int64#1),>mul_x4=reg256#15
# asm 2: vmovapd   896(<input_0=%rdi),>mul_x4=%ymm14
vmovapd   896(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mul_y0
# asm 1: vmulpd <mul_x4=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x4=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x4 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x4=reg256#15,>mul_x4=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x4=%ymm14,>mul_x4=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x4=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x4=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdi),%ymm14,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   mul_x5 aligned= mem256[input_0 + 928]
# asm 1: vmovapd   928(<input_0=int64#1),>mul_x5=reg256#15
# asm 2: vmovapd   928(<input_0=%rdi),>mul_x5=%ymm14
vmovapd   928(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mul_y0
# asm 1: vmulpd <mul_x5=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x5=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x5 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x5=reg256#15,>mul_x5=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x5=%ymm14,>mul_x5=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x5=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x5=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdi),%ymm14,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   mul_x6 aligned= mem256[input_0 + 960]
# asm 1: vmovapd   960(<input_0=int64#1),>mul_x6=reg256#15
# asm 2: vmovapd   960(<input_0=%rdi),>mul_x6=%ymm14
vmovapd   960(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mul_y0
# asm 1: vmulpd <mul_x6=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x6=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x6 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x6=reg256#15,>mul_x6=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x6=%ymm14,>mul_x6=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x6=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x6=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdi),%ymm14,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   mul_x7 aligned= mem256[input_0 + 992]
# asm 1: vmovapd   992(<input_0=int64#1),>mul_x7=reg256#15
# asm 2: vmovapd   992(<input_0=%rdi),>mul_x7=%ymm14
vmovapd   992(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mul_y0
# asm 1: vmulpd <mul_x7=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x7=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x7 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x7=reg256#15,>mul_x7=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x7=%ymm14,>mul_x7=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x7=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x7=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdi),%ymm14,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   mul_x8 aligned= mem256[input_0 + 1024]
# asm 1: vmovapd   1024(<input_0=int64#1),>mul_x8=reg256#15
# asm 2: vmovapd   1024(<input_0=%rdi),>mul_x8=%ymm14
vmovapd   1024(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mul_y0
# asm 1: vmulpd <mul_x8=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x8=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdi),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x8 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x8=reg256#15,>mul_x8=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x8=%ymm14,>mul_x8=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x8=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x8=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdi),%ymm14,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   mul_x9 aligned= mem256[input_0 + 1056]
# asm 1: vmovapd   1056(<input_0=int64#1),>mul_x9=reg256#15
# asm 2: vmovapd   1056(<input_0=%rdi),>mul_x9=%ymm14
vmovapd   1056(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mul_y0
# asm 1: vmulpd <mul_x9=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x9=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdi),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x9 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x9=reg256#15,>mul_x9=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x9=%ymm14,>mul_x9=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x9=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x9=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdi),%ymm14,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   mul_x10 aligned= mem256[input_0 + 1088]
# asm 1: vmovapd   1088(<input_0=int64#1),>mul_x10=reg256#15
# asm 2: vmovapd   1088(<input_0=%rdi),>mul_x10=%ymm14
vmovapd   1088(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mul_y0
# asm 1: vmulpd <mul_x10=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x10=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdi),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x10 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x10=reg256#15,>mul_x10=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x10=%ymm14,>mul_x10=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdi),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdi),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdi),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdi),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdi),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdi),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdi),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdi),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdi),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x10=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x10=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdi),%ymm14,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   mul_x11 aligned= mem256[input_0 + 1120]
# asm 1: vmovapd   1120(<input_0=int64#1),>mul_x11=reg256#15
# asm 2: vmovapd   1120(<input_0=%rdi),>mul_x11=%ymm14
vmovapd   1120(%rdi),%ymm14

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

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 1184]
# asm 1: vmulpd 1184(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1184(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1184(%rdi),%ymm2,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 1216]
# asm 1: vmulpd 1216(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1216(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1216(%rdi),%ymm2,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 1248]
# asm 1: vmulpd 1248(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1248(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1248(%rdi),%ymm2,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 1280]
# asm 1: vmulpd 1280(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1280(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1280(%rdi),%ymm2,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 1312]
# asm 1: vmulpd 1312(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1312(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1312(%rdi),%ymm2,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 1344]
# asm 1: vmulpd 1344(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1344(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1344(%rdi),%ymm2,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 1376]
# asm 1: vmulpd 1376(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1376(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1376(%rdi),%ymm2,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 1408]
# asm 1: vmulpd 1408(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1408(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1408(%rdi),%ymm2,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 1440]
# asm 1: vmulpd 1440(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1440(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1440(%rdi),%ymm2,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 1472]
# asm 1: vmulpd 1472(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1472(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1472(%rdi),%ymm2,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_0 + 1504]
# asm 1: vmulpd 1504(<input_0=int64#1),<mul_x11=reg256#3,>mul_t=reg256#3
# asm 2: vmulpd 1504(<input_0=%rdi),<mul_x11=%ymm2,>mul_t=%ymm2
vmulpd 1504(%rdi),%ymm2,%ymm2

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

# qhasm: 4x s0 = approx r0 - mem256[input_0 + 384]
# asm 1: vsubpd 384(<input_0=int64#1),<r0=reg256#1,>s0=reg256#13
# asm 2: vsubpd 384(<input_0=%rdi),<r0=%ymm0,>s0=%ymm12
vsubpd 384(%rdi),%ymm0,%ymm12

# qhasm: 4x s1 = approx r1 - mem256[input_0 + 416]
# asm 1: vsubpd 416(<input_0=int64#1),<r1=reg256#4,>s1=reg256#14
# asm 2: vsubpd 416(<input_0=%rdi),<r1=%ymm3,>s1=%ymm13
vsubpd 416(%rdi),%ymm3,%ymm13

# qhasm: 4x s2 = approx r2 - mem256[input_0 + 448]
# asm 1: vsubpd 448(<input_0=int64#1),<r2=reg256#6,>s2=reg256#15
# asm 2: vsubpd 448(<input_0=%rdi),<r2=%ymm5,>s2=%ymm14
vsubpd 448(%rdi),%ymm5,%ymm14

# qhasm: 4x s3 = approx r3 - mem256[input_0 + 480]
# asm 1: vsubpd 480(<input_0=int64#1),<r3=reg256#7,>s3=reg256#16
# asm 2: vsubpd 480(<input_0=%rdi),<r3=%ymm6,>s3=%ymm15
vsubpd 480(%rdi),%ymm6,%ymm15

# qhasm: mem256[input_0 + 0] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,0(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,0(<input_0=%rdi)
vmovapd   %ymm12,0(%rdi)

# qhasm: mem256[input_0 + 32] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,32(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,32(<input_0=%rdi)
vmovapd   %ymm13,32(%rdi)

# qhasm: mem256[input_0 + 64] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,64(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,64(<input_0=%rdi)
vmovapd   %ymm14,64(%rdi)

# qhasm: mem256[input_0 + 96] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,96(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,96(<input_0=%rdi)
vmovapd   %ymm15,96(%rdi)

# qhasm: 4x s0 = approx r4 - mem256[input_0 + 512]
# asm 1: vsubpd 512(<input_0=int64#1),<r4=reg256#8,>s0=reg256#13
# asm 2: vsubpd 512(<input_0=%rdi),<r4=%ymm7,>s0=%ymm12
vsubpd 512(%rdi),%ymm7,%ymm12

# qhasm: 4x s1 = approx r5 - mem256[input_0 + 544]
# asm 1: vsubpd 544(<input_0=int64#1),<r5=reg256#5,>s1=reg256#14
# asm 2: vsubpd 544(<input_0=%rdi),<r5=%ymm4,>s1=%ymm13
vsubpd 544(%rdi),%ymm4,%ymm13

# qhasm: 4x s2 = approx r6 - mem256[input_0 + 576]
# asm 1: vsubpd 576(<input_0=int64#1),<r6=reg256#10,>s2=reg256#15
# asm 2: vsubpd 576(<input_0=%rdi),<r6=%ymm9,>s2=%ymm14
vsubpd 576(%rdi),%ymm9,%ymm14

# qhasm: 4x s3 = approx r7 - mem256[input_0 + 608]
# asm 1: vsubpd 608(<input_0=int64#1),<r7=reg256#11,>s3=reg256#16
# asm 2: vsubpd 608(<input_0=%rdi),<r7=%ymm10,>s3=%ymm15
vsubpd 608(%rdi),%ymm10,%ymm15

# qhasm: mem256[input_0 + 128] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,128(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,128(<input_0=%rdi)
vmovapd   %ymm12,128(%rdi)

# qhasm: mem256[input_0 + 160] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,160(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,160(<input_0=%rdi)
vmovapd   %ymm13,160(%rdi)

# qhasm: mem256[input_0 + 192] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,192(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,192(<input_0=%rdi)
vmovapd   %ymm14,192(%rdi)

# qhasm: mem256[input_0 + 224] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,224(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,224(<input_0=%rdi)
vmovapd   %ymm15,224(%rdi)

# qhasm: 4x s0 = approx r8 - mem256[input_0 + 640]
# asm 1: vsubpd 640(<input_0=int64#1),<r8=reg256#12,>s0=reg256#13
# asm 2: vsubpd 640(<input_0=%rdi),<r8=%ymm11,>s0=%ymm12
vsubpd 640(%rdi),%ymm11,%ymm12

# qhasm: 4x s1 = approx r9 - mem256[input_0 + 672]
# asm 1: vsubpd 672(<input_0=int64#1),<r9=reg256#9,>s1=reg256#14
# asm 2: vsubpd 672(<input_0=%rdi),<r9=%ymm8,>s1=%ymm13
vsubpd 672(%rdi),%ymm8,%ymm13

# qhasm: 4x s2 = approx r10 - mem256[input_0 + 704]
# asm 1: vsubpd 704(<input_0=int64#1),<r10=reg256#3,>s2=reg256#15
# asm 2: vsubpd 704(<input_0=%rdi),<r10=%ymm2,>s2=%ymm14
vsubpd 704(%rdi),%ymm2,%ymm14

# qhasm: 4x s3 = approx r11 - mem256[input_0 + 736]
# asm 1: vsubpd 736(<input_0=int64#1),<r11=reg256#2,>s3=reg256#16
# asm 2: vsubpd 736(<input_0=%rdi),<r11=%ymm1,>s3=%ymm15
vsubpd 736(%rdi),%ymm1,%ymm15

# qhasm: mem256[input_0 + 256] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,256(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,256(<input_0=%rdi)
vmovapd   %ymm12,256(%rdi)

# qhasm: mem256[input_0 + 288] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,288(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,288(<input_0=%rdi)
vmovapd   %ymm13,288(%rdi)

# qhasm: mem256[input_0 + 320] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,320(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,320(<input_0=%rdi)
vmovapd   %ymm14,320(%rdi)

# qhasm: mem256[input_0 + 352] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,352(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,352(<input_0=%rdi)
vmovapd   %ymm15,352(%rdi)

# qhasm: 4x s0 = approx r0 + mem256[input_0 + 384]
# asm 1: vaddpd 384(<input_0=int64#1),<r0=reg256#1,>s0=reg256#1
# asm 2: vaddpd 384(<input_0=%rdi),<r0=%ymm0,>s0=%ymm0
vaddpd 384(%rdi),%ymm0,%ymm0

# qhasm: 4x s1 = approx r1 + mem256[input_0 + 416]
# asm 1: vaddpd 416(<input_0=int64#1),<r1=reg256#4,>s1=reg256#4
# asm 2: vaddpd 416(<input_0=%rdi),<r1=%ymm3,>s1=%ymm3
vaddpd 416(%rdi),%ymm3,%ymm3

# qhasm: 4x s2 = approx r2 + mem256[input_0 + 448]
# asm 1: vaddpd 448(<input_0=int64#1),<r2=reg256#6,>s2=reg256#6
# asm 2: vaddpd 448(<input_0=%rdi),<r2=%ymm5,>s2=%ymm5
vaddpd 448(%rdi),%ymm5,%ymm5

# qhasm: 4x s3 = approx r3 + mem256[input_0 + 480]
# asm 1: vaddpd 480(<input_0=int64#1),<r3=reg256#7,>s3=reg256#7
# asm 2: vaddpd 480(<input_0=%rdi),<r3=%ymm6,>s3=%ymm6
vaddpd 480(%rdi),%ymm6,%ymm6

# qhasm: mem256[input_0 + 384] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,384(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,384(<input_0=%rdi)
vmovapd   %ymm0,384(%rdi)

# qhasm: mem256[input_0 + 416] aligned= s1
# asm 1: vmovapd   <s1=reg256#4,416(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm3,416(<input_0=%rdi)
vmovapd   %ymm3,416(%rdi)

# qhasm: mem256[input_0 + 448] aligned= s2
# asm 1: vmovapd   <s2=reg256#6,448(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm5,448(<input_0=%rdi)
vmovapd   %ymm5,448(%rdi)

# qhasm: mem256[input_0 + 480] aligned= s3
# asm 1: vmovapd   <s3=reg256#7,480(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm6,480(<input_0=%rdi)
vmovapd   %ymm6,480(%rdi)

# qhasm: 4x s0 = approx r4 + mem256[input_0 + 512]
# asm 1: vaddpd 512(<input_0=int64#1),<r4=reg256#8,>s0=reg256#1
# asm 2: vaddpd 512(<input_0=%rdi),<r4=%ymm7,>s0=%ymm0
vaddpd 512(%rdi),%ymm7,%ymm0

# qhasm: 4x s1 = approx r5 + mem256[input_0 + 544]
# asm 1: vaddpd 544(<input_0=int64#1),<r5=reg256#5,>s1=reg256#4
# asm 2: vaddpd 544(<input_0=%rdi),<r5=%ymm4,>s1=%ymm3
vaddpd 544(%rdi),%ymm4,%ymm3

# qhasm: 4x s2 = approx r6 + mem256[input_0 + 576]
# asm 1: vaddpd 576(<input_0=int64#1),<r6=reg256#10,>s2=reg256#5
# asm 2: vaddpd 576(<input_0=%rdi),<r6=%ymm9,>s2=%ymm4
vaddpd 576(%rdi),%ymm9,%ymm4

# qhasm: 4x s3 = approx r7 + mem256[input_0 + 608]
# asm 1: vaddpd 608(<input_0=int64#1),<r7=reg256#11,>s3=reg256#6
# asm 2: vaddpd 608(<input_0=%rdi),<r7=%ymm10,>s3=%ymm5
vaddpd 608(%rdi),%ymm10,%ymm5

# qhasm: mem256[input_0 + 512] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,512(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,512(<input_0=%rdi)
vmovapd   %ymm0,512(%rdi)

# qhasm: mem256[input_0 + 544] aligned= s1
# asm 1: vmovapd   <s1=reg256#4,544(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm3,544(<input_0=%rdi)
vmovapd   %ymm3,544(%rdi)

# qhasm: mem256[input_0 + 576] aligned= s2
# asm 1: vmovapd   <s2=reg256#5,576(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm4,576(<input_0=%rdi)
vmovapd   %ymm4,576(%rdi)

# qhasm: mem256[input_0 + 608] aligned= s3
# asm 1: vmovapd   <s3=reg256#6,608(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm5,608(<input_0=%rdi)
vmovapd   %ymm5,608(%rdi)

# qhasm: 4x s0 = approx r8 + mem256[input_0 + 640]
# asm 1: vaddpd 640(<input_0=int64#1),<r8=reg256#12,>s0=reg256#1
# asm 2: vaddpd 640(<input_0=%rdi),<r8=%ymm11,>s0=%ymm0
vaddpd 640(%rdi),%ymm11,%ymm0

# qhasm: 4x s1 = approx r9 + mem256[input_0 + 672]
# asm 1: vaddpd 672(<input_0=int64#1),<r9=reg256#9,>s1=reg256#4
# asm 2: vaddpd 672(<input_0=%rdi),<r9=%ymm8,>s1=%ymm3
vaddpd 672(%rdi),%ymm8,%ymm3

# qhasm: 4x s2 = approx r10 + mem256[input_0 + 704]
# asm 1: vaddpd 704(<input_0=int64#1),<r10=reg256#3,>s2=reg256#3
# asm 2: vaddpd 704(<input_0=%rdi),<r10=%ymm2,>s2=%ymm2
vaddpd 704(%rdi),%ymm2,%ymm2

# qhasm: 4x s3 = approx r11 + mem256[input_0 + 736]
# asm 1: vaddpd 736(<input_0=int64#1),<r11=reg256#2,>s3=reg256#2
# asm 2: vaddpd 736(<input_0=%rdi),<r11=%ymm1,>s3=%ymm1
vaddpd 736(%rdi),%ymm1,%ymm1

# qhasm: mem256[input_0 + 640] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,640(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,640(<input_0=%rdi)
vmovapd   %ymm0,640(%rdi)

# qhasm: mem256[input_0 + 672] aligned= s1
# asm 1: vmovapd   <s1=reg256#4,672(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm3,672(<input_0=%rdi)
vmovapd   %ymm3,672(%rdi)

# qhasm: mem256[input_0 + 704] aligned= s2
# asm 1: vmovapd   <s2=reg256#3,704(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm2,704(<input_0=%rdi)
vmovapd   %ymm2,704(%rdi)

# qhasm: mem256[input_0 + 736] aligned= s3
# asm 1: vmovapd   <s3=reg256#2,736(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm1,736(<input_0=%rdi)
vmovapd   %ymm1,736(%rdi)

# qhasm:   mul_nineteen aligned= mem256[scale19]
# asm 1: vmovapd scale19,>mul_nineteen=reg256#1
# asm 2: vmovapd scale19,>mul_nineteen=%ymm0
vmovapd scale19,%ymm0

# qhasm:   mul_x0 aligned= mem256[input_1 + 1152]
# asm 1: vmovapd   1152(<input_1=int64#2),>mul_x0=reg256#2
# asm 2: vmovapd   1152(<input_1=%rsi),>mul_x0=%ymm1
vmovapd   1152(%rsi),%ymm1

# qhasm:   mul_y0 aligned= mem256[input_2 + 1152]
# asm 1: vmovapd   1152(<input_2=int64#3),>mul_y0=reg256#3
# asm 2: vmovapd   1152(<input_2=%rdx),>mul_y0=%ymm2
vmovapd   1152(%rdx),%ymm2

# qhasm:   4x r0 = approx mul_x0 * mul_y0
# asm 1: vmulpd <mul_x0=reg256#2,<mul_y0=reg256#3,>r0=reg256#4
# asm 2: vmulpd <mul_x0=%ymm1,<mul_y0=%ymm2,>r0=%ymm3
vmulpd %ymm1,%ymm2,%ymm3

# qhasm:   4x r1 = approx mul_x0 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x0=reg256#2,>r1=reg256#5
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x0=%ymm1,>r1=%ymm4
vmulpd 1184(%rdx),%ymm1,%ymm4

# qhasm:   4x r2 = approx mul_x0 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x0=reg256#2,>r2=reg256#6
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x0=%ymm1,>r2=%ymm5
vmulpd 1216(%rdx),%ymm1,%ymm5

# qhasm:   4x r3 = approx mul_x0 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x0=reg256#2,>r3=reg256#7
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x0=%ymm1,>r3=%ymm6
vmulpd 1248(%rdx),%ymm1,%ymm6

# qhasm:   4x r4 = approx mul_x0 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x0=reg256#2,>r4=reg256#8
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x0=%ymm1,>r4=%ymm7
vmulpd 1280(%rdx),%ymm1,%ymm7

# qhasm:   4x r5 = approx mul_x0 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x0=reg256#2,>r5=reg256#9
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x0=%ymm1,>r5=%ymm8
vmulpd 1312(%rdx),%ymm1,%ymm8

# qhasm:   4x r6 = approx mul_x0 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x0=reg256#2,>r6=reg256#10
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x0=%ymm1,>r6=%ymm9
vmulpd 1344(%rdx),%ymm1,%ymm9

# qhasm:   4x r7 = approx mul_x0 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x0=reg256#2,>r7=reg256#11
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x0=%ymm1,>r7=%ymm10
vmulpd 1376(%rdx),%ymm1,%ymm10

# qhasm:   4x r8 = approx mul_x0 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x0=reg256#2,>r8=reg256#12
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x0=%ymm1,>r8=%ymm11
vmulpd 1408(%rdx),%ymm1,%ymm11

# qhasm:   4x r9 = approx mul_x0 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x0=reg256#2,>r9=reg256#13
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x0=%ymm1,>r9=%ymm12
vmulpd 1440(%rdx),%ymm1,%ymm12

# qhasm:   4x r10 = approx mul_x0 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x0=reg256#2,>r10=reg256#14
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x0=%ymm1,>r10=%ymm13
vmulpd 1472(%rdx),%ymm1,%ymm13

# qhasm:   4x r11 = approx mul_x0 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x0=reg256#2,>r11=reg256#2
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x0=%ymm1,>r11=%ymm1
vmulpd 1504(%rdx),%ymm1,%ymm1

# qhasm:   mul_x1 aligned= mem256[input_1 + 1184]
# asm 1: vmovapd   1184(<input_1=int64#2),>mul_x1=reg256#15
# asm 2: vmovapd   1184(<input_1=%rsi),>mul_x1=%ymm14
vmovapd   1184(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mul_y0
# asm 1: vmulpd <mul_x1=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x1=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x1 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x1=reg256#15,>mul_x1=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x1=%ymm14,>mul_x1=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdx),%ymm14,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   mul_x2 aligned= mem256[input_1 + 1216]
# asm 1: vmovapd   1216(<input_1=int64#2),>mul_x2=reg256#15
# asm 2: vmovapd   1216(<input_1=%rsi),>mul_x2=%ymm14
vmovapd   1216(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mul_y0
# asm 1: vmulpd <mul_x2=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x2=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x2 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x2=reg256#15,>mul_x2=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x2=%ymm14,>mul_x2=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdx),%ymm14,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   mul_x3 aligned= mem256[input_1 + 1248]
# asm 1: vmovapd   1248(<input_1=int64#2),>mul_x3=reg256#15
# asm 2: vmovapd   1248(<input_1=%rsi),>mul_x3=%ymm14
vmovapd   1248(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mul_y0
# asm 1: vmulpd <mul_x3=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x3=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x3 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x3=reg256#15,>mul_x3=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x3=%ymm14,>mul_x3=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdx),%ymm14,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   mul_x4 aligned= mem256[input_1 + 1280]
# asm 1: vmovapd   1280(<input_1=int64#2),>mul_x4=reg256#15
# asm 2: vmovapd   1280(<input_1=%rsi),>mul_x4=%ymm14
vmovapd   1280(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mul_y0
# asm 1: vmulpd <mul_x4=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x4=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x4 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x4=reg256#15,>mul_x4=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x4=%ymm14,>mul_x4=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdx),%ymm14,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   mul_x5 aligned= mem256[input_1 + 1312]
# asm 1: vmovapd   1312(<input_1=int64#2),>mul_x5=reg256#15
# asm 2: vmovapd   1312(<input_1=%rsi),>mul_x5=%ymm14
vmovapd   1312(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mul_y0
# asm 1: vmulpd <mul_x5=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x5=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x5 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x5=reg256#15,>mul_x5=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x5=%ymm14,>mul_x5=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdx),%ymm14,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   mul_x6 aligned= mem256[input_1 + 1344]
# asm 1: vmovapd   1344(<input_1=int64#2),>mul_x6=reg256#15
# asm 2: vmovapd   1344(<input_1=%rsi),>mul_x6=%ymm14
vmovapd   1344(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mul_y0
# asm 1: vmulpd <mul_x6=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x6=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x6 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x6=reg256#15,>mul_x6=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x6=%ymm14,>mul_x6=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdx),%ymm14,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   mul_x7 aligned= mem256[input_1 + 1376]
# asm 1: vmovapd   1376(<input_1=int64#2),>mul_x7=reg256#15
# asm 2: vmovapd   1376(<input_1=%rsi),>mul_x7=%ymm14
vmovapd   1376(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mul_y0
# asm 1: vmulpd <mul_x7=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x7=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x7 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x7=reg256#15,>mul_x7=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x7=%ymm14,>mul_x7=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdx),%ymm14,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   mul_x8 aligned= mem256[input_1 + 1408]
# asm 1: vmovapd   1408(<input_1=int64#2),>mul_x8=reg256#15
# asm 2: vmovapd   1408(<input_1=%rsi),>mul_x8=%ymm14
vmovapd   1408(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mul_y0
# asm 1: vmulpd <mul_x8=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x8=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x8 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x8=reg256#15,>mul_x8=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x8=%ymm14,>mul_x8=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdx),%ymm14,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   mul_x9 aligned= mem256[input_1 + 1440]
# asm 1: vmovapd   1440(<input_1=int64#2),>mul_x9=reg256#15
# asm 2: vmovapd   1440(<input_1=%rsi),>mul_x9=%ymm14
vmovapd   1440(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mul_y0
# asm 1: vmulpd <mul_x9=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x9=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x9 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x9=reg256#15,>mul_x9=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x9=%ymm14,>mul_x9=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdx),%ymm14,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   mul_x10 aligned= mem256[input_1 + 1472]
# asm 1: vmovapd   1472(<input_1=int64#2),>mul_x10=reg256#15
# asm 2: vmovapd   1472(<input_1=%rsi),>mul_x10=%ymm14
vmovapd   1472(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mul_y0
# asm 1: vmulpd <mul_x10=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x10=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1184(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x10 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x10=reg256#15,>mul_x10=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x10=%ymm14,>mul_x10=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1216(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1248(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1280(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1312(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1344(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1376(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1408(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1440(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1472(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm14
vmulpd 1504(%rdx),%ymm14,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   mul_x11 aligned= mem256[input_1 + 1504]
# asm 1: vmovapd   1504(<input_1=int64#2),>mul_x11=reg256#15
# asm 2: vmovapd   1504(<input_1=%rsi),>mul_x11=%ymm14
vmovapd   1504(%rsi),%ymm14

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

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1184]
# asm 1: vmulpd 1184(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1184(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1184(%rdx),%ymm2,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1216]
# asm 1: vmulpd 1216(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1216(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1216(%rdx),%ymm2,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1248]
# asm 1: vmulpd 1248(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1248(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1248(%rdx),%ymm2,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1280]
# asm 1: vmulpd 1280(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1280(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1280(%rdx),%ymm2,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1312]
# asm 1: vmulpd 1312(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1312(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1312(%rdx),%ymm2,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1344]
# asm 1: vmulpd 1344(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1344(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1344(%rdx),%ymm2,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1376]
# asm 1: vmulpd 1376(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1376(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1376(%rdx),%ymm2,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1408]
# asm 1: vmulpd 1408(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1408(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1408(%rdx),%ymm2,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1440]
# asm 1: vmulpd 1440(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1440(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1440(%rdx),%ymm2,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1472]
# asm 1: vmulpd 1472(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1472(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1472(%rdx),%ymm2,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1504]
# asm 1: vmulpd 1504(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#3
# asm 2: vmulpd 1504(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm2
vmulpd 1504(%rdx),%ymm2,%ymm2

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

# qhasm: mem256[input_0 + 768] aligned= r0
# asm 1: vmovapd   <r0=reg256#1,768(<input_0=int64#1)
# asm 2: vmovapd   <r0=%ymm0,768(<input_0=%rdi)
vmovapd   %ymm0,768(%rdi)

# qhasm: mem256[input_0 + 800] aligned= r1
# asm 1: vmovapd   <r1=reg256#4,800(<input_0=int64#1)
# asm 2: vmovapd   <r1=%ymm3,800(<input_0=%rdi)
vmovapd   %ymm3,800(%rdi)

# qhasm: mem256[input_0 + 832] aligned= r2
# asm 1: vmovapd   <r2=reg256#6,832(<input_0=int64#1)
# asm 2: vmovapd   <r2=%ymm5,832(<input_0=%rdi)
vmovapd   %ymm5,832(%rdi)

# qhasm: mem256[input_0 + 864] aligned= r3
# asm 1: vmovapd   <r3=reg256#7,864(<input_0=int64#1)
# asm 2: vmovapd   <r3=%ymm6,864(<input_0=%rdi)
vmovapd   %ymm6,864(%rdi)

# qhasm: mem256[input_0 + 896] aligned= r4
# asm 1: vmovapd   <r4=reg256#8,896(<input_0=int64#1)
# asm 2: vmovapd   <r4=%ymm7,896(<input_0=%rdi)
vmovapd   %ymm7,896(%rdi)

# qhasm: mem256[input_0 + 928] aligned= r5
# asm 1: vmovapd   <r5=reg256#5,928(<input_0=int64#1)
# asm 2: vmovapd   <r5=%ymm4,928(<input_0=%rdi)
vmovapd   %ymm4,928(%rdi)

# qhasm: mem256[input_0 + 960] aligned= r6
# asm 1: vmovapd   <r6=reg256#10,960(<input_0=int64#1)
# asm 2: vmovapd   <r6=%ymm9,960(<input_0=%rdi)
vmovapd   %ymm9,960(%rdi)

# qhasm: mem256[input_0 + 992] aligned= r7
# asm 1: vmovapd   <r7=reg256#11,992(<input_0=int64#1)
# asm 2: vmovapd   <r7=%ymm10,992(<input_0=%rdi)
vmovapd   %ymm10,992(%rdi)

# qhasm: mem256[input_0 + 1024] aligned= r8
# asm 1: vmovapd   <r8=reg256#12,1024(<input_0=int64#1)
# asm 2: vmovapd   <r8=%ymm11,1024(<input_0=%rdi)
vmovapd   %ymm11,1024(%rdi)

# qhasm: mem256[input_0 + 1056] aligned= r9
# asm 1: vmovapd   <r9=reg256#9,1056(<input_0=int64#1)
# asm 2: vmovapd   <r9=%ymm8,1056(<input_0=%rdi)
vmovapd   %ymm8,1056(%rdi)

# qhasm: mem256[input_0 + 1088] aligned= r10
# asm 1: vmovapd   <r10=reg256#3,1088(<input_0=int64#1)
# asm 2: vmovapd   <r10=%ymm2,1088(<input_0=%rdi)
vmovapd   %ymm2,1088(%rdi)

# qhasm: mem256[input_0 + 1120] aligned= r11
# asm 1: vmovapd   <r11=reg256#2,1120(<input_0=int64#1)
# asm 2: vmovapd   <r11=%ymm1,1120(<input_0=%rdi)
vmovapd   %ymm1,1120(%rdi)

# qhasm:   mul_nineteen aligned= mem256[scale19]
# asm 1: vmovapd scale19,>mul_nineteen=reg256#1
# asm 2: vmovapd scale19,>mul_nineteen=%ymm0
vmovapd scale19,%ymm0

# qhasm:   mul_x0 aligned= mem256[input_0 + 768]
# asm 1: vmovapd   768(<input_0=int64#1),>mul_x0=reg256#2
# asm 2: vmovapd   768(<input_0=%rdi),>mul_x0=%ymm1
vmovapd   768(%rdi),%ymm1

# qhasm:   mul_y0 aligned= mem256[input_3 + 0]
# asm 1: vmovapd   0(<input_3=int64#4),>mul_y0=reg256#3
# asm 2: vmovapd   0(<input_3=%rcx),>mul_y0=%ymm2
vmovapd   0(%rcx),%ymm2

# qhasm:   4x r0 = approx mul_x0 * mul_y0
# asm 1: vmulpd <mul_x0=reg256#2,<mul_y0=reg256#3,>r0=reg256#4
# asm 2: vmulpd <mul_x0=%ymm1,<mul_y0=%ymm2,>r0=%ymm3
vmulpd %ymm1,%ymm2,%ymm3

# qhasm:   4x r1 = approx mul_x0 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x0=reg256#2,>r1=reg256#5
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x0=%ymm1,>r1=%ymm4
vmulpd 32(%rcx),%ymm1,%ymm4

# qhasm:   4x r2 = approx mul_x0 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x0=reg256#2,>r2=reg256#6
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x0=%ymm1,>r2=%ymm5
vmulpd 64(%rcx),%ymm1,%ymm5

# qhasm:   4x r3 = approx mul_x0 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x0=reg256#2,>r3=reg256#7
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x0=%ymm1,>r3=%ymm6
vmulpd 96(%rcx),%ymm1,%ymm6

# qhasm:   4x r4 = approx mul_x0 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x0=reg256#2,>r4=reg256#8
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x0=%ymm1,>r4=%ymm7
vmulpd 128(%rcx),%ymm1,%ymm7

# qhasm:   4x r5 = approx mul_x0 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x0=reg256#2,>r5=reg256#9
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x0=%ymm1,>r5=%ymm8
vmulpd 160(%rcx),%ymm1,%ymm8

# qhasm:   4x r6 = approx mul_x0 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x0=reg256#2,>r6=reg256#10
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x0=%ymm1,>r6=%ymm9
vmulpd 192(%rcx),%ymm1,%ymm9

# qhasm:   4x r7 = approx mul_x0 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x0=reg256#2,>r7=reg256#11
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x0=%ymm1,>r7=%ymm10
vmulpd 224(%rcx),%ymm1,%ymm10

# qhasm:   4x r8 = approx mul_x0 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x0=reg256#2,>r8=reg256#12
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x0=%ymm1,>r8=%ymm11
vmulpd 256(%rcx),%ymm1,%ymm11

# qhasm:   4x r9 = approx mul_x0 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x0=reg256#2,>r9=reg256#13
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x0=%ymm1,>r9=%ymm12
vmulpd 288(%rcx),%ymm1,%ymm12

# qhasm:   4x r10 = approx mul_x0 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x0=reg256#2,>r10=reg256#14
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x0=%ymm1,>r10=%ymm13
vmulpd 320(%rcx),%ymm1,%ymm13

# qhasm:   4x r11 = approx mul_x0 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x0=reg256#2,>r11=reg256#2
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x0=%ymm1,>r11=%ymm1
vmulpd 352(%rcx),%ymm1,%ymm1

# qhasm:   mul_x1 aligned= mem256[input_0 + 800]
# asm 1: vmovapd   800(<input_0=int64#1),>mul_x1=reg256#15
# asm 2: vmovapd   800(<input_0=%rdi),>mul_x1=%ymm14
vmovapd   800(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mul_y0
# asm 1: vmulpd <mul_x1=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x1=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 32(%rcx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 64(%rcx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 96(%rcx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 128(%rcx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 160(%rcx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 192(%rcx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 224(%rcx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 256(%rcx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 288(%rcx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 320(%rcx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x1 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x1=reg256#15,>mul_x1=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x1=%ymm14,>mul_x1=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x1=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x1=%ymm14,>mul_t=%ymm14
vmulpd 352(%rcx),%ymm14,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   mul_x2 aligned= mem256[input_0 + 832]
# asm 1: vmovapd   832(<input_0=int64#1),>mul_x2=reg256#15
# asm 2: vmovapd   832(<input_0=%rdi),>mul_x2=%ymm14
vmovapd   832(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mul_y0
# asm 1: vmulpd <mul_x2=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x2=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 32(%rcx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 64(%rcx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 96(%rcx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 128(%rcx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 160(%rcx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 192(%rcx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 224(%rcx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 256(%rcx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 288(%rcx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x2 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x2=reg256#15,>mul_x2=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x2=%ymm14,>mul_x2=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 320(%rcx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x2=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x2=%ymm14,>mul_t=%ymm14
vmulpd 352(%rcx),%ymm14,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   mul_x3 aligned= mem256[input_0 + 864]
# asm 1: vmovapd   864(<input_0=int64#1),>mul_x3=reg256#15
# asm 2: vmovapd   864(<input_0=%rdi),>mul_x3=%ymm14
vmovapd   864(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mul_y0
# asm 1: vmulpd <mul_x3=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x3=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 32(%rcx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 64(%rcx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 96(%rcx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 128(%rcx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 160(%rcx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 192(%rcx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 224(%rcx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 256(%rcx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x3 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x3=reg256#15,>mul_x3=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x3=%ymm14,>mul_x3=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 288(%rcx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 320(%rcx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x3=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x3=%ymm14,>mul_t=%ymm14
vmulpd 352(%rcx),%ymm14,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   mul_x4 aligned= mem256[input_0 + 896]
# asm 1: vmovapd   896(<input_0=int64#1),>mul_x4=reg256#15
# asm 2: vmovapd   896(<input_0=%rdi),>mul_x4=%ymm14
vmovapd   896(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mul_y0
# asm 1: vmulpd <mul_x4=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x4=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 32(%rcx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 64(%rcx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 96(%rcx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 128(%rcx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 160(%rcx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 192(%rcx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 224(%rcx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x4 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x4=reg256#15,>mul_x4=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x4=%ymm14,>mul_x4=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 256(%rcx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 288(%rcx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 320(%rcx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x4=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x4=%ymm14,>mul_t=%ymm14
vmulpd 352(%rcx),%ymm14,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   mul_x5 aligned= mem256[input_0 + 928]
# asm 1: vmovapd   928(<input_0=int64#1),>mul_x5=reg256#15
# asm 2: vmovapd   928(<input_0=%rdi),>mul_x5=%ymm14
vmovapd   928(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mul_y0
# asm 1: vmulpd <mul_x5=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x5=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 32(%rcx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 64(%rcx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 96(%rcx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 128(%rcx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 160(%rcx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 192(%rcx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x5 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x5=reg256#15,>mul_x5=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x5=%ymm14,>mul_x5=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 224(%rcx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 256(%rcx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 288(%rcx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 320(%rcx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x5=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x5=%ymm14,>mul_t=%ymm14
vmulpd 352(%rcx),%ymm14,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   mul_x6 aligned= mem256[input_0 + 960]
# asm 1: vmovapd   960(<input_0=int64#1),>mul_x6=reg256#15
# asm 2: vmovapd   960(<input_0=%rdi),>mul_x6=%ymm14
vmovapd   960(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mul_y0
# asm 1: vmulpd <mul_x6=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x6=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 32(%rcx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 64(%rcx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 96(%rcx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 128(%rcx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 160(%rcx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x6 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x6=reg256#15,>mul_x6=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x6=%ymm14,>mul_x6=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 192(%rcx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 224(%rcx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 256(%rcx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 288(%rcx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 320(%rcx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x6=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x6=%ymm14,>mul_t=%ymm14
vmulpd 352(%rcx),%ymm14,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   mul_x7 aligned= mem256[input_0 + 992]
# asm 1: vmovapd   992(<input_0=int64#1),>mul_x7=reg256#15
# asm 2: vmovapd   992(<input_0=%rdi),>mul_x7=%ymm14
vmovapd   992(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mul_y0
# asm 1: vmulpd <mul_x7=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x7=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 32(%rcx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 64(%rcx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 96(%rcx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 128(%rcx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x7 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x7=reg256#15,>mul_x7=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x7=%ymm14,>mul_x7=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 160(%rcx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 192(%rcx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 224(%rcx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 256(%rcx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 288(%rcx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 320(%rcx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x7=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x7=%ymm14,>mul_t=%ymm14
vmulpd 352(%rcx),%ymm14,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   mul_x8 aligned= mem256[input_0 + 1024]
# asm 1: vmovapd   1024(<input_0=int64#1),>mul_x8=reg256#15
# asm 2: vmovapd   1024(<input_0=%rdi),>mul_x8=%ymm14
vmovapd   1024(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mul_y0
# asm 1: vmulpd <mul_x8=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x8=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 32(%rcx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 64(%rcx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 96(%rcx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x8 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x8=reg256#15,>mul_x8=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x8=%ymm14,>mul_x8=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 128(%rcx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 160(%rcx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 192(%rcx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 224(%rcx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 256(%rcx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 288(%rcx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 320(%rcx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x8=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x8=%ymm14,>mul_t=%ymm14
vmulpd 352(%rcx),%ymm14,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   mul_x9 aligned= mem256[input_0 + 1056]
# asm 1: vmovapd   1056(<input_0=int64#1),>mul_x9=reg256#15
# asm 2: vmovapd   1056(<input_0=%rdi),>mul_x9=%ymm14
vmovapd   1056(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mul_y0
# asm 1: vmulpd <mul_x9=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x9=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 32(%rcx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 64(%rcx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x9 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x9=reg256#15,>mul_x9=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x9=%ymm14,>mul_x9=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 96(%rcx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 128(%rcx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 160(%rcx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 192(%rcx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 224(%rcx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 256(%rcx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 288(%rcx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 320(%rcx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x9=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x9=%ymm14,>mul_t=%ymm14
vmulpd 352(%rcx),%ymm14,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   mul_x10 aligned= mem256[input_0 + 1088]
# asm 1: vmovapd   1088(<input_0=int64#1),>mul_x10=reg256#15
# asm 2: vmovapd   1088(<input_0=%rdi),>mul_x10=%ymm14
vmovapd   1088(%rdi),%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mul_y0
# asm 1: vmulpd <mul_x10=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x10=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 32(%rcx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x10 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x10=reg256#15,>mul_x10=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x10=%ymm14,>mul_x10=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 64(%rcx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 96(%rcx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 128(%rcx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 160(%rcx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 192(%rcx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 224(%rcx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 256(%rcx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 288(%rcx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 320(%rcx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x10=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x10=%ymm14,>mul_t=%ymm14
vmulpd 352(%rcx),%ymm14,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   mul_x11 aligned= mem256[input_0 + 1120]
# asm 1: vmovapd   1120(<input_0=int64#1),>mul_x11=reg256#15
# asm 2: vmovapd   1120(<input_0=%rdi),>mul_x11=%ymm14
vmovapd   1120(%rdi),%ymm14

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

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_3 + 32]
# asm 1: vmulpd 32(<input_3=int64#4),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 32(<input_3=%rcx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 32(%rcx),%ymm2,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_3 + 64]
# asm 1: vmulpd 64(<input_3=int64#4),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 64(<input_3=%rcx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 64(%rcx),%ymm2,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_3 + 96]
# asm 1: vmulpd 96(<input_3=int64#4),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 96(<input_3=%rcx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 96(%rcx),%ymm2,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_3 + 128]
# asm 1: vmulpd 128(<input_3=int64#4),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 128(<input_3=%rcx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 128(%rcx),%ymm2,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_3 + 160]
# asm 1: vmulpd 160(<input_3=int64#4),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 160(<input_3=%rcx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 160(%rcx),%ymm2,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_3 + 192]
# asm 1: vmulpd 192(<input_3=int64#4),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 192(<input_3=%rcx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 192(%rcx),%ymm2,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_3 + 224]
# asm 1: vmulpd 224(<input_3=int64#4),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 224(<input_3=%rcx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 224(%rcx),%ymm2,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_3 + 256]
# asm 1: vmulpd 256(<input_3=int64#4),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 256(<input_3=%rcx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 256(%rcx),%ymm2,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_3 + 288]
# asm 1: vmulpd 288(<input_3=int64#4),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 288(<input_3=%rcx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 288(%rcx),%ymm2,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_3 + 320]
# asm 1: vmulpd 320(<input_3=int64#4),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 320(<input_3=%rcx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 320(%rcx),%ymm2,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_3 + 352]
# asm 1: vmulpd 352(<input_3=int64#4),<mul_x11=reg256#3,>mul_t=reg256#3
# asm 2: vmulpd 352(<input_3=%rcx),<mul_x11=%ymm2,>mul_t=%ymm2
vmulpd 352(%rcx),%ymm2,%ymm2

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

# qhasm: mem256[input_0 + 768] aligned= r0
# asm 1: vmovapd   <r0=reg256#1,768(<input_0=int64#1)
# asm 2: vmovapd   <r0=%ymm0,768(<input_0=%rdi)
vmovapd   %ymm0,768(%rdi)

# qhasm: mem256[input_0 + 800] aligned= r1
# asm 1: vmovapd   <r1=reg256#4,800(<input_0=int64#1)
# asm 2: vmovapd   <r1=%ymm3,800(<input_0=%rdi)
vmovapd   %ymm3,800(%rdi)

# qhasm: mem256[input_0 + 832] aligned= r2
# asm 1: vmovapd   <r2=reg256#6,832(<input_0=int64#1)
# asm 2: vmovapd   <r2=%ymm5,832(<input_0=%rdi)
vmovapd   %ymm5,832(%rdi)

# qhasm: mem256[input_0 + 864] aligned= r3
# asm 1: vmovapd   <r3=reg256#7,864(<input_0=int64#1)
# asm 2: vmovapd   <r3=%ymm6,864(<input_0=%rdi)
vmovapd   %ymm6,864(%rdi)

# qhasm: mem256[input_0 + 896] aligned= r4
# asm 1: vmovapd   <r4=reg256#8,896(<input_0=int64#1)
# asm 2: vmovapd   <r4=%ymm7,896(<input_0=%rdi)
vmovapd   %ymm7,896(%rdi)

# qhasm: mem256[input_0 + 928] aligned= r5
# asm 1: vmovapd   <r5=reg256#5,928(<input_0=int64#1)
# asm 2: vmovapd   <r5=%ymm4,928(<input_0=%rdi)
vmovapd   %ymm4,928(%rdi)

# qhasm: mem256[input_0 + 960] aligned= r6
# asm 1: vmovapd   <r6=reg256#10,960(<input_0=int64#1)
# asm 2: vmovapd   <r6=%ymm9,960(<input_0=%rdi)
vmovapd   %ymm9,960(%rdi)

# qhasm: mem256[input_0 + 992] aligned= r7
# asm 1: vmovapd   <r7=reg256#11,992(<input_0=int64#1)
# asm 2: vmovapd   <r7=%ymm10,992(<input_0=%rdi)
vmovapd   %ymm10,992(%rdi)

# qhasm: mem256[input_0 + 1024] aligned= r8
# asm 1: vmovapd   <r8=reg256#12,1024(<input_0=int64#1)
# asm 2: vmovapd   <r8=%ymm11,1024(<input_0=%rdi)
vmovapd   %ymm11,1024(%rdi)

# qhasm: mem256[input_0 + 1056] aligned= r9
# asm 1: vmovapd   <r9=reg256#9,1056(<input_0=int64#1)
# asm 2: vmovapd   <r9=%ymm8,1056(<input_0=%rdi)
vmovapd   %ymm8,1056(%rdi)

# qhasm: mem256[input_0 + 1088] aligned= r10
# asm 1: vmovapd   <r10=reg256#3,1088(<input_0=int64#1)
# asm 2: vmovapd   <r10=%ymm2,1088(<input_0=%rdi)
vmovapd   %ymm2,1088(%rdi)

# qhasm: mem256[input_0 + 1120] aligned= r11
# asm 1: vmovapd   <r11=reg256#2,1120(<input_0=int64#1)
# asm 2: vmovapd   <r11=%ymm1,1120(<input_0=%rdi)
vmovapd   %ymm1,1120(%rdi)

# qhasm:   mul_nineteen aligned= mem256[scale19]
# asm 1: vmovapd scale19,>mul_nineteen=reg256#1
# asm 2: vmovapd scale19,>mul_nineteen=%ymm0
vmovapd scale19,%ymm0

# qhasm:   mul_x0 aligned= mem256[input_1 + 768]
# asm 1: vmovapd   768(<input_1=int64#2),>mul_x0=reg256#2
# asm 2: vmovapd   768(<input_1=%rsi),>mul_x0=%ymm1
vmovapd   768(%rsi),%ymm1

# qhasm:   mul_y0 aligned= mem256[input_2 + 768]
# asm 1: vmovapd   768(<input_2=int64#3),>mul_y0=reg256#3
# asm 2: vmovapd   768(<input_2=%rdx),>mul_y0=%ymm2
vmovapd   768(%rdx),%ymm2

# qhasm:   4x r0 = approx mul_x0 * mul_y0
# asm 1: vmulpd <mul_x0=reg256#2,<mul_y0=reg256#3,>r0=reg256#4
# asm 2: vmulpd <mul_x0=%ymm1,<mul_y0=%ymm2,>r0=%ymm3
vmulpd %ymm1,%ymm2,%ymm3

# qhasm:   4x r1 = approx mul_x0 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x0=reg256#2,>r1=reg256#5
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x0=%ymm1,>r1=%ymm4
vmulpd 800(%rdx),%ymm1,%ymm4

# qhasm:   4x r2 = approx mul_x0 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x0=reg256#2,>r2=reg256#6
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x0=%ymm1,>r2=%ymm5
vmulpd 832(%rdx),%ymm1,%ymm5

# qhasm:   4x r3 = approx mul_x0 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x0=reg256#2,>r3=reg256#7
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x0=%ymm1,>r3=%ymm6
vmulpd 864(%rdx),%ymm1,%ymm6

# qhasm:   4x r4 = approx mul_x0 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x0=reg256#2,>r4=reg256#8
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x0=%ymm1,>r4=%ymm7
vmulpd 896(%rdx),%ymm1,%ymm7

# qhasm:   4x r5 = approx mul_x0 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x0=reg256#2,>r5=reg256#9
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x0=%ymm1,>r5=%ymm8
vmulpd 928(%rdx),%ymm1,%ymm8

# qhasm:   4x r6 = approx mul_x0 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x0=reg256#2,>r6=reg256#10
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x0=%ymm1,>r6=%ymm9
vmulpd 960(%rdx),%ymm1,%ymm9

# qhasm:   4x r7 = approx mul_x0 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x0=reg256#2,>r7=reg256#11
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x0=%ymm1,>r7=%ymm10
vmulpd 992(%rdx),%ymm1,%ymm10

# qhasm:   4x r8 = approx mul_x0 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x0=reg256#2,>r8=reg256#12
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x0=%ymm1,>r8=%ymm11
vmulpd 1024(%rdx),%ymm1,%ymm11

# qhasm:   4x r9 = approx mul_x0 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x0=reg256#2,>r9=reg256#13
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x0=%ymm1,>r9=%ymm12
vmulpd 1056(%rdx),%ymm1,%ymm12

# qhasm:   4x r10 = approx mul_x0 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x0=reg256#2,>r10=reg256#14
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x0=%ymm1,>r10=%ymm13
vmulpd 1088(%rdx),%ymm1,%ymm13

# qhasm:   4x r11 = approx mul_x0 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x0=reg256#2,>r11=reg256#2
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x0=%ymm1,>r11=%ymm1
vmulpd 1120(%rdx),%ymm1,%ymm1

# qhasm:   mul_x1 aligned= mem256[input_1 + 800]
# asm 1: vmovapd   800(<input_1=int64#2),>mul_x1=reg256#15
# asm 2: vmovapd   800(<input_1=%rsi),>mul_x1=%ymm14
vmovapd   800(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mul_y0
# asm 1: vmulpd <mul_x1=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x1=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 800(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 832(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 864(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 896(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 928(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 960(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 992(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1024(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1056(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm15
vmulpd 1088(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x1 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x1=reg256#15,>mul_x1=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x1=%ymm14,>mul_x1=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x1 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x1=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x1=%ymm14,>mul_t=%ymm14
vmulpd 1120(%rdx),%ymm14,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   mul_x2 aligned= mem256[input_1 + 832]
# asm 1: vmovapd   832(<input_1=int64#2),>mul_x2=reg256#15
# asm 2: vmovapd   832(<input_1=%rsi),>mul_x2=%ymm14
vmovapd   832(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mul_y0
# asm 1: vmulpd <mul_x2=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x2=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 800(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 832(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 864(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 896(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 928(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 960(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 992(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1024(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1056(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x2 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x2=reg256#15,>mul_x2=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x2=%ymm14,>mul_x2=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm15
vmulpd 1088(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x2 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x2=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x2=%ymm14,>mul_t=%ymm14
vmulpd 1120(%rdx),%ymm14,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   mul_x3 aligned= mem256[input_1 + 864]
# asm 1: vmovapd   864(<input_1=int64#2),>mul_x3=reg256#15
# asm 2: vmovapd   864(<input_1=%rsi),>mul_x3=%ymm14
vmovapd   864(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mul_y0
# asm 1: vmulpd <mul_x3=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x3=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 800(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 832(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 864(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 896(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 928(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 960(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 992(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1024(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x3 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x3=reg256#15,>mul_x3=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x3=%ymm14,>mul_x3=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1056(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm15
vmulpd 1088(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x3 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x3=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x3=%ymm14,>mul_t=%ymm14
vmulpd 1120(%rdx),%ymm14,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   mul_x4 aligned= mem256[input_1 + 896]
# asm 1: vmovapd   896(<input_1=int64#2),>mul_x4=reg256#15
# asm 2: vmovapd   896(<input_1=%rsi),>mul_x4=%ymm14
vmovapd   896(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mul_y0
# asm 1: vmulpd <mul_x4=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x4=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 800(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 832(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 864(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 896(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 928(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 960(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 992(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x4 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x4=reg256#15,>mul_x4=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x4=%ymm14,>mul_x4=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1024(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1056(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm15
vmulpd 1088(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x4 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x4=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x4=%ymm14,>mul_t=%ymm14
vmulpd 1120(%rdx),%ymm14,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   mul_x5 aligned= mem256[input_1 + 928]
# asm 1: vmovapd   928(<input_1=int64#2),>mul_x5=reg256#15
# asm 2: vmovapd   928(<input_1=%rsi),>mul_x5=%ymm14
vmovapd   928(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mul_y0
# asm 1: vmulpd <mul_x5=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x5=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 800(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 832(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 864(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 896(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 928(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 960(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x5 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x5=reg256#15,>mul_x5=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x5=%ymm14,>mul_x5=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 992(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1024(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1056(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm15
vmulpd 1088(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x5 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x5=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x5=%ymm14,>mul_t=%ymm14
vmulpd 1120(%rdx),%ymm14,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   mul_x6 aligned= mem256[input_1 + 960]
# asm 1: vmovapd   960(<input_1=int64#2),>mul_x6=reg256#15
# asm 2: vmovapd   960(<input_1=%rsi),>mul_x6=%ymm14
vmovapd   960(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mul_y0
# asm 1: vmulpd <mul_x6=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x6=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 800(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 832(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 864(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 896(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 928(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x6 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x6=reg256#15,>mul_x6=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x6=%ymm14,>mul_x6=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 960(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 992(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1024(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1056(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm15
vmulpd 1088(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x6 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x6=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x6=%ymm14,>mul_t=%ymm14
vmulpd 1120(%rdx),%ymm14,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   mul_x7 aligned= mem256[input_1 + 992]
# asm 1: vmovapd   992(<input_1=int64#2),>mul_x7=reg256#15
# asm 2: vmovapd   992(<input_1=%rsi),>mul_x7=%ymm14
vmovapd   992(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mul_y0
# asm 1: vmulpd <mul_x7=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x7=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 800(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 832(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 864(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 896(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x7 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x7=reg256#15,>mul_x7=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x7=%ymm14,>mul_x7=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 928(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 960(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 992(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1024(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1056(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm15
vmulpd 1088(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x7 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x7=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x7=%ymm14,>mul_t=%ymm14
vmulpd 1120(%rdx),%ymm14,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   mul_x8 aligned= mem256[input_1 + 1024]
# asm 1: vmovapd   1024(<input_1=int64#2),>mul_x8=reg256#15
# asm 2: vmovapd   1024(<input_1=%rsi),>mul_x8=%ymm14
vmovapd   1024(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mul_y0
# asm 1: vmulpd <mul_x8=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x8=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 800(%rdx),%ymm14,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 832(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 864(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x8 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x8=reg256#15,>mul_x8=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x8=%ymm14,>mul_x8=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 896(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 928(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 960(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 992(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1024(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1056(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm15
vmulpd 1088(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x8 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x8=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x8=%ymm14,>mul_t=%ymm14
vmulpd 1120(%rdx),%ymm14,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   mul_x9 aligned= mem256[input_1 + 1056]
# asm 1: vmovapd   1056(<input_1=int64#2),>mul_x9=reg256#15
# asm 2: vmovapd   1056(<input_1=%rsi),>mul_x9=%ymm14
vmovapd   1056(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mul_y0
# asm 1: vmulpd <mul_x9=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x9=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm15,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm15,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 800(%rdx),%ymm14,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 832(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x9 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x9=reg256#15,>mul_x9=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x9=%ymm14,>mul_x9=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 864(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 896(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 928(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 960(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 992(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1024(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1056(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm15
vmulpd 1088(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x9 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x9=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x9=%ymm14,>mul_t=%ymm14
vmulpd 1120(%rdx),%ymm14,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   mul_x10 aligned= mem256[input_1 + 1088]
# asm 1: vmovapd   1088(<input_1=int64#2),>mul_x10=reg256#15
# asm 2: vmovapd   1088(<input_1=%rsi),>mul_x10=%ymm14
vmovapd   1088(%rsi),%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mul_y0
# asm 1: vmulpd <mul_x10=reg256#15,<mul_y0=reg256#3,>mul_t=reg256#16
# asm 2: vmulpd <mul_x10=%ymm14,<mul_y0=%ymm2,>mul_t=%ymm15
vmulpd %ymm14,%ymm2,%ymm15

# qhasm:   4x r10 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r10=reg256#14,>r10=reg256#14
# asm 2: vaddpd <mul_t=%ymm15,<r10=%ymm13,>r10=%ymm13
vaddpd %ymm15,%ymm13,%ymm13

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 800(%rdx),%ymm14,%ymm15

# qhasm:   4x r11 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <mul_t=%ymm15,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm15,%ymm1,%ymm1

# qhasm:   4x mul_x10 approx*= mul_nineteen
# asm 1: vmulpd <mul_nineteen=reg256#1,<mul_x10=reg256#15,>mul_x10=reg256#15
# asm 2: vmulpd <mul_nineteen=%ymm0,<mul_x10=%ymm14,>mul_x10=%ymm14
vmulpd %ymm0,%ymm14,%ymm14

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 832(%rdx),%ymm14,%ymm15

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm15,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm15,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 864(%rdx),%ymm14,%ymm15

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm15,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm15,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 896(%rdx),%ymm14,%ymm15

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm15,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm15,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 928(%rdx),%ymm14,%ymm15

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm15,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm15,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 960(%rdx),%ymm14,%ymm15

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm15,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm15,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 992(%rdx),%ymm14,%ymm15

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm15,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm15,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1024(%rdx),%ymm14,%ymm15

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm15,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm15,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1056(%rdx),%ymm14,%ymm15

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm15,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm15,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#16
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm15
vmulpd 1088(%rdx),%ymm14,%ymm15

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#16,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm15,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm15,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x10 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x10=reg256#15,>mul_t=reg256#15
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x10=%ymm14,>mul_t=%ymm14
vmulpd 1120(%rdx),%ymm14,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   mul_x11 aligned= mem256[input_1 + 1120]
# asm 1: vmovapd   1120(<input_1=int64#2),>mul_x11=reg256#15
# asm 2: vmovapd   1120(<input_1=%rsi),>mul_x11=%ymm14
vmovapd   1120(%rsi),%ymm14

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

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 800]
# asm 1: vmulpd 800(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 800(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 800(%rdx),%ymm2,%ymm14

# qhasm:   4x r0 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r0=reg256#4,>r0=reg256#4
# asm 2: vaddpd <mul_t=%ymm14,<r0=%ymm3,>r0=%ymm3
vaddpd %ymm14,%ymm3,%ymm3

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 832]
# asm 1: vmulpd 832(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 832(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 832(%rdx),%ymm2,%ymm14

# qhasm:   4x r1 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r1=reg256#5,>r1=reg256#5
# asm 2: vaddpd <mul_t=%ymm14,<r1=%ymm4,>r1=%ymm4
vaddpd %ymm14,%ymm4,%ymm4

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 864]
# asm 1: vmulpd 864(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 864(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 864(%rdx),%ymm2,%ymm14

# qhasm:   4x r2 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r2=reg256#6,>r2=reg256#6
# asm 2: vaddpd <mul_t=%ymm14,<r2=%ymm5,>r2=%ymm5
vaddpd %ymm14,%ymm5,%ymm5

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 896]
# asm 1: vmulpd 896(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 896(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 896(%rdx),%ymm2,%ymm14

# qhasm:   4x r3 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r3=reg256#7,>r3=reg256#7
# asm 2: vaddpd <mul_t=%ymm14,<r3=%ymm6,>r3=%ymm6
vaddpd %ymm14,%ymm6,%ymm6

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 928]
# asm 1: vmulpd 928(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 928(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 928(%rdx),%ymm2,%ymm14

# qhasm:   4x r4 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r4=reg256#8,>r4=reg256#8
# asm 2: vaddpd <mul_t=%ymm14,<r4=%ymm7,>r4=%ymm7
vaddpd %ymm14,%ymm7,%ymm7

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 960]
# asm 1: vmulpd 960(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 960(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 960(%rdx),%ymm2,%ymm14

# qhasm:   4x r5 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r5=reg256#9,>r5=reg256#9
# asm 2: vaddpd <mul_t=%ymm14,<r5=%ymm8,>r5=%ymm8
vaddpd %ymm14,%ymm8,%ymm8

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 992]
# asm 1: vmulpd 992(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 992(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 992(%rdx),%ymm2,%ymm14

# qhasm:   4x r6 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <mul_t=%ymm14,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm14,%ymm9,%ymm9

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1024]
# asm 1: vmulpd 1024(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1024(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1024(%rdx),%ymm2,%ymm14

# qhasm:   4x r7 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <mul_t=%ymm14,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm14,%ymm10,%ymm10

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1056]
# asm 1: vmulpd 1056(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1056(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1056(%rdx),%ymm2,%ymm14

# qhasm:   4x r8 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <mul_t=%ymm14,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm14,%ymm11,%ymm11

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1088]
# asm 1: vmulpd 1088(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#15
# asm 2: vmulpd 1088(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm14
vmulpd 1088(%rdx),%ymm2,%ymm14

# qhasm:   4x r9 approx+= mul_t
# asm 1: vaddpd <mul_t=reg256#15,<r9=reg256#13,>r9=reg256#13
# asm 2: vaddpd <mul_t=%ymm14,<r9=%ymm12,>r9=%ymm12
vaddpd %ymm14,%ymm12,%ymm12

# qhasm:   4x mul_t = approx mul_x11 * mem256[input_2 + 1120]
# asm 1: vmulpd 1120(<input_2=int64#3),<mul_x11=reg256#3,>mul_t=reg256#3
# asm 2: vmulpd 1120(<input_2=%rdx),<mul_x11=%ymm2,>mul_t=%ymm2
vmulpd 1120(%rdx),%ymm2,%ymm2

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
# asm 1: vaddpd <r6=reg256#10,<r6=reg256#10,>r6=reg256#10
# asm 2: vaddpd <r6=%ymm9,<r6=%ymm9,>r6=%ymm9
vaddpd %ymm9,%ymm9,%ymm9

# qhasm: 4x r7 approx+= r7
# asm 1: vaddpd <r7=reg256#11,<r7=reg256#11,>r7=reg256#11
# asm 2: vaddpd <r7=%ymm10,<r7=%ymm10,>r7=%ymm10
vaddpd %ymm10,%ymm10,%ymm10

# qhasm: 4x r8 approx+= r8
# asm 1: vaddpd <r8=reg256#12,<r8=reg256#12,>r8=reg256#12
# asm 2: vaddpd <r8=%ymm11,<r8=%ymm11,>r8=%ymm11
vaddpd %ymm11,%ymm11,%ymm11

# qhasm: 4x r9 approx+= r9
# asm 1: vaddpd <r9=reg256#9,<r9=reg256#9,>r9=reg256#9
# asm 2: vaddpd <r9=%ymm8,<r9=%ymm8,>r9=%ymm8
vaddpd %ymm8,%ymm8,%ymm8

# qhasm: 4x r10 approx+= r10
# asm 1: vaddpd <r10=reg256#3,<r10=reg256#3,>r10=reg256#3
# asm 2: vaddpd <r10=%ymm2,<r10=%ymm2,>r10=%ymm2
vaddpd %ymm2,%ymm2,%ymm2

# qhasm: 4x r11 approx+= r11
# asm 1: vaddpd <r11=reg256#2,<r11=reg256#2,>r11=reg256#2
# asm 2: vaddpd <r11=%ymm1,<r11=%ymm1,>r11=%ymm1
vaddpd %ymm1,%ymm1,%ymm1

# qhasm: 4x s0 = approx r0 - mem256[input_0 + 768]
# asm 1: vsubpd 768(<input_0=int64#1),<r0=reg256#1,>s0=reg256#13
# asm 2: vsubpd 768(<input_0=%rdi),<r0=%ymm0,>s0=%ymm12
vsubpd 768(%rdi),%ymm0,%ymm12

# qhasm: 4x s1 = approx r1 - mem256[input_0 + 800]
# asm 1: vsubpd 800(<input_0=int64#1),<r1=reg256#4,>s1=reg256#14
# asm 2: vsubpd 800(<input_0=%rdi),<r1=%ymm3,>s1=%ymm13
vsubpd 800(%rdi),%ymm3,%ymm13

# qhasm: 4x s2 = approx r2 - mem256[input_0 + 832]
# asm 1: vsubpd 832(<input_0=int64#1),<r2=reg256#6,>s2=reg256#15
# asm 2: vsubpd 832(<input_0=%rdi),<r2=%ymm5,>s2=%ymm14
vsubpd 832(%rdi),%ymm5,%ymm14

# qhasm: 4x s3 = approx r3 - mem256[input_0 + 864]
# asm 1: vsubpd 864(<input_0=int64#1),<r3=reg256#7,>s3=reg256#16
# asm 2: vsubpd 864(<input_0=%rdi),<r3=%ymm6,>s3=%ymm15
vsubpd 864(%rdi),%ymm6,%ymm15

# qhasm: mem256[input_0 + 1152] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,1152(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,1152(<input_0=%rdi)
vmovapd   %ymm12,1152(%rdi)

# qhasm: mem256[input_0 + 1184] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,1184(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,1184(<input_0=%rdi)
vmovapd   %ymm13,1184(%rdi)

# qhasm: mem256[input_0 + 1216] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,1216(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,1216(<input_0=%rdi)
vmovapd   %ymm14,1216(%rdi)

# qhasm: mem256[input_0 + 1248] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,1248(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,1248(<input_0=%rdi)
vmovapd   %ymm15,1248(%rdi)

# qhasm: 4x s0 = approx r4 - mem256[input_0 + 896]
# asm 1: vsubpd 896(<input_0=int64#1),<r4=reg256#8,>s0=reg256#13
# asm 2: vsubpd 896(<input_0=%rdi),<r4=%ymm7,>s0=%ymm12
vsubpd 896(%rdi),%ymm7,%ymm12

# qhasm: 4x s1 = approx r5 - mem256[input_0 + 928]
# asm 1: vsubpd 928(<input_0=int64#1),<r5=reg256#5,>s1=reg256#14
# asm 2: vsubpd 928(<input_0=%rdi),<r5=%ymm4,>s1=%ymm13
vsubpd 928(%rdi),%ymm4,%ymm13

# qhasm: 4x s2 = approx r6 - mem256[input_0 + 960]
# asm 1: vsubpd 960(<input_0=int64#1),<r6=reg256#10,>s2=reg256#15
# asm 2: vsubpd 960(<input_0=%rdi),<r6=%ymm9,>s2=%ymm14
vsubpd 960(%rdi),%ymm9,%ymm14

# qhasm: 4x s3 = approx r7 - mem256[input_0 + 992]
# asm 1: vsubpd 992(<input_0=int64#1),<r7=reg256#11,>s3=reg256#16
# asm 2: vsubpd 992(<input_0=%rdi),<r7=%ymm10,>s3=%ymm15
vsubpd 992(%rdi),%ymm10,%ymm15

# qhasm: mem256[input_0 + 1280] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,1280(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,1280(<input_0=%rdi)
vmovapd   %ymm12,1280(%rdi)

# qhasm: mem256[input_0 + 1312] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,1312(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,1312(<input_0=%rdi)
vmovapd   %ymm13,1312(%rdi)

# qhasm: mem256[input_0 + 1344] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,1344(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,1344(<input_0=%rdi)
vmovapd   %ymm14,1344(%rdi)

# qhasm: mem256[input_0 + 1376] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,1376(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,1376(<input_0=%rdi)
vmovapd   %ymm15,1376(%rdi)

# qhasm: 4x s0 = approx r8 - mem256[input_0 + 1024]
# asm 1: vsubpd 1024(<input_0=int64#1),<r8=reg256#12,>s0=reg256#13
# asm 2: vsubpd 1024(<input_0=%rdi),<r8=%ymm11,>s0=%ymm12
vsubpd 1024(%rdi),%ymm11,%ymm12

# qhasm: 4x s1 = approx r9 - mem256[input_0 + 1056]
# asm 1: vsubpd 1056(<input_0=int64#1),<r9=reg256#9,>s1=reg256#14
# asm 2: vsubpd 1056(<input_0=%rdi),<r9=%ymm8,>s1=%ymm13
vsubpd 1056(%rdi),%ymm8,%ymm13

# qhasm: 4x s2 = approx r10 - mem256[input_0 + 1088]
# asm 1: vsubpd 1088(<input_0=int64#1),<r10=reg256#3,>s2=reg256#15
# asm 2: vsubpd 1088(<input_0=%rdi),<r10=%ymm2,>s2=%ymm14
vsubpd 1088(%rdi),%ymm2,%ymm14

# qhasm: 4x s3 = approx r11 - mem256[input_0 + 1120]
# asm 1: vsubpd 1120(<input_0=int64#1),<r11=reg256#2,>s3=reg256#16
# asm 2: vsubpd 1120(<input_0=%rdi),<r11=%ymm1,>s3=%ymm15
vsubpd 1120(%rdi),%ymm1,%ymm15

# qhasm: mem256[input_0 + 1408] aligned= s0
# asm 1: vmovapd   <s0=reg256#13,1408(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm12,1408(<input_0=%rdi)
vmovapd   %ymm12,1408(%rdi)

# qhasm: mem256[input_0 + 1440] aligned= s1
# asm 1: vmovapd   <s1=reg256#14,1440(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm13,1440(<input_0=%rdi)
vmovapd   %ymm13,1440(%rdi)

# qhasm: mem256[input_0 + 1472] aligned= s2
# asm 1: vmovapd   <s2=reg256#15,1472(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm14,1472(<input_0=%rdi)
vmovapd   %ymm14,1472(%rdi)

# qhasm: mem256[input_0 + 1504] aligned= s3
# asm 1: vmovapd   <s3=reg256#16,1504(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm15,1504(<input_0=%rdi)
vmovapd   %ymm15,1504(%rdi)

# qhasm: 4x s0 = approx r0 + mem256[input_0 + 768]
# asm 1: vaddpd 768(<input_0=int64#1),<r0=reg256#1,>s0=reg256#1
# asm 2: vaddpd 768(<input_0=%rdi),<r0=%ymm0,>s0=%ymm0
vaddpd 768(%rdi),%ymm0,%ymm0

# qhasm: 4x s1 = approx r1 + mem256[input_0 + 800]
# asm 1: vaddpd 800(<input_0=int64#1),<r1=reg256#4,>s1=reg256#4
# asm 2: vaddpd 800(<input_0=%rdi),<r1=%ymm3,>s1=%ymm3
vaddpd 800(%rdi),%ymm3,%ymm3

# qhasm: 4x s2 = approx r2 + mem256[input_0 + 832]
# asm 1: vaddpd 832(<input_0=int64#1),<r2=reg256#6,>s2=reg256#6
# asm 2: vaddpd 832(<input_0=%rdi),<r2=%ymm5,>s2=%ymm5
vaddpd 832(%rdi),%ymm5,%ymm5

# qhasm: 4x s3 = approx r3 + mem256[input_0 + 864]
# asm 1: vaddpd 864(<input_0=int64#1),<r3=reg256#7,>s3=reg256#7
# asm 2: vaddpd 864(<input_0=%rdi),<r3=%ymm6,>s3=%ymm6
vaddpd 864(%rdi),%ymm6,%ymm6

# qhasm: mem256[input_0 + 768] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,768(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,768(<input_0=%rdi)
vmovapd   %ymm0,768(%rdi)

# qhasm: mem256[input_0 + 800] aligned= s1
# asm 1: vmovapd   <s1=reg256#4,800(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm3,800(<input_0=%rdi)
vmovapd   %ymm3,800(%rdi)

# qhasm: mem256[input_0 + 832] aligned= s2
# asm 1: vmovapd   <s2=reg256#6,832(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm5,832(<input_0=%rdi)
vmovapd   %ymm5,832(%rdi)

# qhasm: mem256[input_0 + 864] aligned= s3
# asm 1: vmovapd   <s3=reg256#7,864(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm6,864(<input_0=%rdi)
vmovapd   %ymm6,864(%rdi)

# qhasm: 4x s0 = approx r4 + mem256[input_0 + 896]
# asm 1: vaddpd 896(<input_0=int64#1),<r4=reg256#8,>s0=reg256#1
# asm 2: vaddpd 896(<input_0=%rdi),<r4=%ymm7,>s0=%ymm0
vaddpd 896(%rdi),%ymm7,%ymm0

# qhasm: 4x s1 = approx r5 + mem256[input_0 + 928]
# asm 1: vaddpd 928(<input_0=int64#1),<r5=reg256#5,>s1=reg256#4
# asm 2: vaddpd 928(<input_0=%rdi),<r5=%ymm4,>s1=%ymm3
vaddpd 928(%rdi),%ymm4,%ymm3

# qhasm: 4x s2 = approx r6 + mem256[input_0 + 960]
# asm 1: vaddpd 960(<input_0=int64#1),<r6=reg256#10,>s2=reg256#5
# asm 2: vaddpd 960(<input_0=%rdi),<r6=%ymm9,>s2=%ymm4
vaddpd 960(%rdi),%ymm9,%ymm4

# qhasm: 4x s3 = approx r7 + mem256[input_0 + 992]
# asm 1: vaddpd 992(<input_0=int64#1),<r7=reg256#11,>s3=reg256#6
# asm 2: vaddpd 992(<input_0=%rdi),<r7=%ymm10,>s3=%ymm5
vaddpd 992(%rdi),%ymm10,%ymm5

# qhasm: mem256[input_0 + 896] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,896(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,896(<input_0=%rdi)
vmovapd   %ymm0,896(%rdi)

# qhasm: mem256[input_0 + 928] aligned= s1
# asm 1: vmovapd   <s1=reg256#4,928(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm3,928(<input_0=%rdi)
vmovapd   %ymm3,928(%rdi)

# qhasm: mem256[input_0 + 960] aligned= s2
# asm 1: vmovapd   <s2=reg256#5,960(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm4,960(<input_0=%rdi)
vmovapd   %ymm4,960(%rdi)

# qhasm: mem256[input_0 + 992] aligned= s3
# asm 1: vmovapd   <s3=reg256#6,992(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm5,992(<input_0=%rdi)
vmovapd   %ymm5,992(%rdi)

# qhasm: 4x s0 = approx r8 + mem256[input_0 + 1024]
# asm 1: vaddpd 1024(<input_0=int64#1),<r8=reg256#12,>s0=reg256#1
# asm 2: vaddpd 1024(<input_0=%rdi),<r8=%ymm11,>s0=%ymm0
vaddpd 1024(%rdi),%ymm11,%ymm0

# qhasm: 4x s1 = approx r9 + mem256[input_0 + 1056]
# asm 1: vaddpd 1056(<input_0=int64#1),<r9=reg256#9,>s1=reg256#4
# asm 2: vaddpd 1056(<input_0=%rdi),<r9=%ymm8,>s1=%ymm3
vaddpd 1056(%rdi),%ymm8,%ymm3

# qhasm: 4x s2 = approx r10 + mem256[input_0 + 1088]
# asm 1: vaddpd 1088(<input_0=int64#1),<r10=reg256#3,>s2=reg256#3
# asm 2: vaddpd 1088(<input_0=%rdi),<r10=%ymm2,>s2=%ymm2
vaddpd 1088(%rdi),%ymm2,%ymm2

# qhasm: 4x s3 = approx r11 + mem256[input_0 + 1120]
# asm 1: vaddpd 1120(<input_0=int64#1),<r11=reg256#2,>s3=reg256#2
# asm 2: vaddpd 1120(<input_0=%rdi),<r11=%ymm1,>s3=%ymm1
vaddpd 1120(%rdi),%ymm1,%ymm1

# qhasm: mem256[input_0 + 1024] aligned= s0
# asm 1: vmovapd   <s0=reg256#1,1024(<input_0=int64#1)
# asm 2: vmovapd   <s0=%ymm0,1024(<input_0=%rdi)
vmovapd   %ymm0,1024(%rdi)

# qhasm: mem256[input_0 + 1056] aligned= s1
# asm 1: vmovapd   <s1=reg256#4,1056(<input_0=int64#1)
# asm 2: vmovapd   <s1=%ymm3,1056(<input_0=%rdi)
vmovapd   %ymm3,1056(%rdi)

# qhasm: mem256[input_0 + 1088] aligned= s2
# asm 1: vmovapd   <s2=reg256#3,1088(<input_0=int64#1)
# asm 2: vmovapd   <s2=%ymm2,1088(<input_0=%rdi)
vmovapd   %ymm2,1088(%rdi)

# qhasm: mem256[input_0 + 1120] aligned= s3
# asm 1: vmovapd   <s3=reg256#2,1120(<input_0=int64#1)
# asm 2: vmovapd   <s3=%ymm1,1120(<input_0=%rdi)
vmovapd   %ymm1,1120(%rdi)

# qhasm: return
add %r11,%rsp
ret
