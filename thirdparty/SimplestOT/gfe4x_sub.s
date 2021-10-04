
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

# qhasm: reg256 x0

# qhasm: reg256 x1

# qhasm: reg256 x2

# qhasm: reg256 x3

# qhasm: reg256 x4

# qhasm: reg256 x5

# qhasm: reg256 x6

# qhasm: reg256 x7

# qhasm: reg256 x8

# qhasm: reg256 x9

# qhasm: reg256 x10

# qhasm: reg256 x11

# qhasm: enter gfe4x_sub
.p2align 5
.global _gfe4x_sub
.global gfe4x_sub
_gfe4x_sub:
gfe4x_sub:
mov %rsp,%r11
and $31,%r11
add $0,%r11
sub %r11,%rsp

# qhasm: x0  = mem256[input_1 + 0]
# asm 1: vmovupd   0(<input_1=int64#2),>x0=reg256#1
# asm 2: vmovupd   0(<input_1=%rsi),>x0=%ymm0
vmovupd   0(%rsi),%ymm0

# qhasm: 4x x0 approx-= mem256[input_2 + 0]
# asm 1: vsubpd 0(<input_2=int64#3),<x0=reg256#1,>x0=reg256#1
# asm 2: vsubpd 0(<input_2=%rdx),<x0=%ymm0,>x0=%ymm0
vsubpd 0(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 0] = x0
# asm 1: vmovupd   <x0=reg256#1,0(<input_0=int64#1)
# asm 2: vmovupd   <x0=%ymm0,0(<input_0=%rdi)
vmovupd   %ymm0,0(%rdi)

# qhasm: x1  = mem256[input_1 + 32]
# asm 1: vmovupd   32(<input_1=int64#2),>x1=reg256#1
# asm 2: vmovupd   32(<input_1=%rsi),>x1=%ymm0
vmovupd   32(%rsi),%ymm0

# qhasm: 4x x1 approx-= mem256[input_2 + 32]
# asm 1: vsubpd 32(<input_2=int64#3),<x1=reg256#1,>x1=reg256#1
# asm 2: vsubpd 32(<input_2=%rdx),<x1=%ymm0,>x1=%ymm0
vsubpd 32(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 32] = x1
# asm 1: vmovupd   <x1=reg256#1,32(<input_0=int64#1)
# asm 2: vmovupd   <x1=%ymm0,32(<input_0=%rdi)
vmovupd   %ymm0,32(%rdi)

# qhasm: x2  = mem256[input_1 + 64]
# asm 1: vmovupd   64(<input_1=int64#2),>x2=reg256#1
# asm 2: vmovupd   64(<input_1=%rsi),>x2=%ymm0
vmovupd   64(%rsi),%ymm0

# qhasm: 4x x2 approx-= mem256[input_2 + 64]
# asm 1: vsubpd 64(<input_2=int64#3),<x2=reg256#1,>x2=reg256#1
# asm 2: vsubpd 64(<input_2=%rdx),<x2=%ymm0,>x2=%ymm0
vsubpd 64(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 64] = x2
# asm 1: vmovupd   <x2=reg256#1,64(<input_0=int64#1)
# asm 2: vmovupd   <x2=%ymm0,64(<input_0=%rdi)
vmovupd   %ymm0,64(%rdi)

# qhasm: x3  = mem256[input_1 + 96]
# asm 1: vmovupd   96(<input_1=int64#2),>x3=reg256#1
# asm 2: vmovupd   96(<input_1=%rsi),>x3=%ymm0
vmovupd   96(%rsi),%ymm0

# qhasm: 4x x3 approx-= mem256[input_2 + 96]
# asm 1: vsubpd 96(<input_2=int64#3),<x3=reg256#1,>x3=reg256#1
# asm 2: vsubpd 96(<input_2=%rdx),<x3=%ymm0,>x3=%ymm0
vsubpd 96(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 96] = x3
# asm 1: vmovupd   <x3=reg256#1,96(<input_0=int64#1)
# asm 2: vmovupd   <x3=%ymm0,96(<input_0=%rdi)
vmovupd   %ymm0,96(%rdi)

# qhasm: x4  = mem256[input_1 + 128]
# asm 1: vmovupd   128(<input_1=int64#2),>x4=reg256#1
# asm 2: vmovupd   128(<input_1=%rsi),>x4=%ymm0
vmovupd   128(%rsi),%ymm0

# qhasm: 4x x4 approx-= mem256[input_2 + 128]
# asm 1: vsubpd 128(<input_2=int64#3),<x4=reg256#1,>x4=reg256#1
# asm 2: vsubpd 128(<input_2=%rdx),<x4=%ymm0,>x4=%ymm0
vsubpd 128(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 128] = x4
# asm 1: vmovupd   <x4=reg256#1,128(<input_0=int64#1)
# asm 2: vmovupd   <x4=%ymm0,128(<input_0=%rdi)
vmovupd   %ymm0,128(%rdi)

# qhasm: x5  = mem256[input_1 + 160]
# asm 1: vmovupd   160(<input_1=int64#2),>x5=reg256#1
# asm 2: vmovupd   160(<input_1=%rsi),>x5=%ymm0
vmovupd   160(%rsi),%ymm0

# qhasm: 4x x5 approx-= mem256[input_2 + 160]
# asm 1: vsubpd 160(<input_2=int64#3),<x5=reg256#1,>x5=reg256#1
# asm 2: vsubpd 160(<input_2=%rdx),<x5=%ymm0,>x5=%ymm0
vsubpd 160(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 160] = x5
# asm 1: vmovupd   <x5=reg256#1,160(<input_0=int64#1)
# asm 2: vmovupd   <x5=%ymm0,160(<input_0=%rdi)
vmovupd   %ymm0,160(%rdi)

# qhasm: x6  = mem256[input_1 + 192]
# asm 1: vmovupd   192(<input_1=int64#2),>x6=reg256#1
# asm 2: vmovupd   192(<input_1=%rsi),>x6=%ymm0
vmovupd   192(%rsi),%ymm0

# qhasm: 4x x6 approx-= mem256[input_2 + 192]
# asm 1: vsubpd 192(<input_2=int64#3),<x6=reg256#1,>x6=reg256#1
# asm 2: vsubpd 192(<input_2=%rdx),<x6=%ymm0,>x6=%ymm0
vsubpd 192(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 192] = x6
# asm 1: vmovupd   <x6=reg256#1,192(<input_0=int64#1)
# asm 2: vmovupd   <x6=%ymm0,192(<input_0=%rdi)
vmovupd   %ymm0,192(%rdi)

# qhasm: x7  = mem256[input_1 + 224]
# asm 1: vmovupd   224(<input_1=int64#2),>x7=reg256#1
# asm 2: vmovupd   224(<input_1=%rsi),>x7=%ymm0
vmovupd   224(%rsi),%ymm0

# qhasm: 4x x7 approx-= mem256[input_2 + 224]
# asm 1: vsubpd 224(<input_2=int64#3),<x7=reg256#1,>x7=reg256#1
# asm 2: vsubpd 224(<input_2=%rdx),<x7=%ymm0,>x7=%ymm0
vsubpd 224(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 224] = x7
# asm 1: vmovupd   <x7=reg256#1,224(<input_0=int64#1)
# asm 2: vmovupd   <x7=%ymm0,224(<input_0=%rdi)
vmovupd   %ymm0,224(%rdi)

# qhasm: x8  = mem256[input_1 + 256]
# asm 1: vmovupd   256(<input_1=int64#2),>x8=reg256#1
# asm 2: vmovupd   256(<input_1=%rsi),>x8=%ymm0
vmovupd   256(%rsi),%ymm0

# qhasm: 4x x8 approx-= mem256[input_2 + 256]
# asm 1: vsubpd 256(<input_2=int64#3),<x8=reg256#1,>x8=reg256#1
# asm 2: vsubpd 256(<input_2=%rdx),<x8=%ymm0,>x8=%ymm0
vsubpd 256(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 256] = x8
# asm 1: vmovupd   <x8=reg256#1,256(<input_0=int64#1)
# asm 2: vmovupd   <x8=%ymm0,256(<input_0=%rdi)
vmovupd   %ymm0,256(%rdi)

# qhasm: x9  = mem256[input_1 + 288]
# asm 1: vmovupd   288(<input_1=int64#2),>x9=reg256#1
# asm 2: vmovupd   288(<input_1=%rsi),>x9=%ymm0
vmovupd   288(%rsi),%ymm0

# qhasm: 4x x9 approx-= mem256[input_2 + 288]
# asm 1: vsubpd 288(<input_2=int64#3),<x9=reg256#1,>x9=reg256#1
# asm 2: vsubpd 288(<input_2=%rdx),<x9=%ymm0,>x9=%ymm0
vsubpd 288(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 288] = x9
# asm 1: vmovupd   <x9=reg256#1,288(<input_0=int64#1)
# asm 2: vmovupd   <x9=%ymm0,288(<input_0=%rdi)
vmovupd   %ymm0,288(%rdi)

# qhasm: x10  = mem256[input_1 + 320]
# asm 1: vmovupd   320(<input_1=int64#2),>x10=reg256#1
# asm 2: vmovupd   320(<input_1=%rsi),>x10=%ymm0
vmovupd   320(%rsi),%ymm0

# qhasm: 4x x10 approx-= mem256[input_2 + 320]
# asm 1: vsubpd 320(<input_2=int64#3),<x10=reg256#1,>x10=reg256#1
# asm 2: vsubpd 320(<input_2=%rdx),<x10=%ymm0,>x10=%ymm0
vsubpd 320(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 320] = x10
# asm 1: vmovupd   <x10=reg256#1,320(<input_0=int64#1)
# asm 2: vmovupd   <x10=%ymm0,320(<input_0=%rdi)
vmovupd   %ymm0,320(%rdi)

# qhasm: x11  = mem256[input_1 + 352]
# asm 1: vmovupd   352(<input_1=int64#2),>x11=reg256#1
# asm 2: vmovupd   352(<input_1=%rsi),>x11=%ymm0
vmovupd   352(%rsi),%ymm0

# qhasm: 4x x11 approx-= mem256[input_2 + 352]
# asm 1: vsubpd 352(<input_2=int64#3),<x11=reg256#1,>x11=reg256#1
# asm 2: vsubpd 352(<input_2=%rdx),<x11=%ymm0,>x11=%ymm0
vsubpd 352(%rdx),%ymm0,%ymm0

# qhasm: mem256[input_0 + 352] = x11
# asm 1: vmovupd   <x11=reg256#1,352(<input_0=int64#1)
# asm 2: vmovupd   <x11=%ymm0,352(<input_0=%rdi)
vmovupd   %ymm0,352(%rdi)

# qhasm: return
add %r11,%rsp
ret
