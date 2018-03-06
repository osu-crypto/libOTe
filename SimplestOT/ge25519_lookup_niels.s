
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

# qhasm: int64 tp

# qhasm: int64 pos

# qhasm: int64 b

# qhasm: int64 basep

# qhasm: int64 mask

# qhasm: int64 u

# qhasm: int64 tysubx0

# qhasm: int64 tysubx1

# qhasm: int64 tysubx2

# qhasm: int64 tysubx3

# qhasm: int64 tysubx4

# qhasm: int64 txaddy0

# qhasm: int64 txaddy1

# qhasm: int64 txaddy2

# qhasm: int64 txaddy3

# qhasm: int64 txaddy4

# qhasm: int64 tt2d0

# qhasm: int64 tt2d1

# qhasm: int64 tt2d2

# qhasm: int64 tt2d3

# qhasm: int64 tt2d4

# qhasm: int64 tt0

# qhasm: int64 tt1

# qhasm: int64 tt2

# qhasm: int64 tt3

# qhasm: int64 tt4

# qhasm: int64 t

# qhasm: stack64 tp_stack

# qhasm: stack64 r11_stack

# qhasm: stack64 r12_stack

# qhasm: stack64 r13_stack

# qhasm: stack64 r14_stack

# qhasm: stack64 r15_stack

# qhasm: stack64 rbx_stack

# qhasm: stack64 rbp_stack

# qhasm: enter ge25519_lookup_niels_asm
.p2align 5
.global _ge25519_lookup_niels_asm
.global ge25519_lookup_niels_asm
_ge25519_lookup_niels_asm:
ge25519_lookup_niels_asm:
mov %rsp,%r11
and $31,%r11
add $64,%r11
sub %r11,%rsp

# qhasm: r11_stack = caller_r11
# asm 1: movq <caller_r11=int64#9,>r11_stack=stack64#1
# asm 2: movq <caller_r11=%r11,>r11_stack=0(%rsp)
movq %r11,0(%rsp)

# qhasm: r12_stack = caller_r12
# asm 1: movq <caller_r12=int64#10,>r12_stack=stack64#2
# asm 2: movq <caller_r12=%r12,>r12_stack=8(%rsp)
movq %r12,8(%rsp)

# qhasm: r13_stack = caller_r13
# asm 1: movq <caller_r13=int64#11,>r13_stack=stack64#3
# asm 2: movq <caller_r13=%r13,>r13_stack=16(%rsp)
movq %r13,16(%rsp)

# qhasm: r14_stack = caller_r14
# asm 1: movq <caller_r14=int64#12,>r14_stack=stack64#4
# asm 2: movq <caller_r14=%r14,>r14_stack=24(%rsp)
movq %r14,24(%rsp)

# qhasm: r15_stack = caller_r15
# asm 1: movq <caller_r15=int64#13,>r15_stack=stack64#5
# asm 2: movq <caller_r15=%r15,>r15_stack=32(%rsp)
movq %r15,32(%rsp)

# qhasm: rbx_stack = caller_rbx
# asm 1: movq <caller_rbx=int64#14,>rbx_stack=stack64#6
# asm 2: movq <caller_rbx=%rbx,>rbx_stack=40(%rsp)
movq %rbx,40(%rsp)

# qhasm: rbp_stack = caller_rbp
# asm 1: movq <caller_rbp=int64#15,>rbp_stack=stack64#7
# asm 2: movq <caller_rbp=%rbp,>rbp_stack=48(%rsp)
movq %rbp,48(%rsp)

# qhasm: tp = input_0
# asm 1: mov  <input_0=int64#1,>tp=int64#1
# asm 2: mov  <input_0=%rdi,>tp=%rdi
mov  %rdi,%rdi

# qhasm: b = *( int8  *) (input_2 + 0)
# asm 1: movsbq 0(<input_2=int64#3),>b=int64#3
# asm 2: movsbq 0(<input_2=%rdx),>b=%rdx
movsbq 0(%rdx),%rdx

# qhasm: basep = input_1
# asm 1: mov  <input_1=int64#2,>basep=int64#2
# asm 2: mov  <input_1=%rsi,>basep=%rsi
mov  %rsi,%rsi

# qhasm: tp_stack = tp
# asm 1: movq <tp=int64#1,>tp_stack=stack64#8
# asm 2: movq <tp=%rdi,>tp_stack=56(%rsp)
movq %rdi,56(%rsp)

# qhasm: mask = b
# asm 1: mov  <b=int64#3,>mask=int64#1
# asm 2: mov  <b=%rdx,>mask=%rdi
mov  %rdx,%rdi

# qhasm: (int64) mask >>= 7
# asm 1: sar  $7,<mask=int64#1
# asm 2: sar  $7,<mask=%rdi
sar  $7,%rdi

# qhasm: u = b
# asm 1: mov  <b=int64#3,>u=int64#4
# asm 2: mov  <b=%rdx,>u=%rcx
mov  %rdx,%rcx

# qhasm: u += mask
# asm 1: add  <mask=int64#1,<u=int64#4
# asm 2: add  <mask=%rdi,<u=%rcx
add  %rdi,%rcx

# qhasm: u ^= mask
# asm 1: xor  <mask=int64#1,<u=int64#4
# asm 2: xor  <mask=%rdi,<u=%rcx
xor  %rdi,%rcx

# qhasm: tysubx0 = 1
# asm 1: mov  $1,>tysubx0=int64#1
# asm 2: mov  $1,>tysubx0=%rdi
mov  $1,%rdi

# qhasm: tysubx1 = 0
# asm 1: mov  $0,>tysubx1=int64#5
# asm 2: mov  $0,>tysubx1=%r8
mov  $0,%r8

# qhasm: tysubx2 = 0
# asm 1: mov  $0,>tysubx2=int64#6
# asm 2: mov  $0,>tysubx2=%r9
mov  $0,%r9

# qhasm: tysubx3 = 0
# asm 1: mov  $0,>tysubx3=int64#7
# asm 2: mov  $0,>tysubx3=%rax
mov  $0,%rax

# qhasm: tysubx4 = 0
# asm 1: mov  $0,>tysubx4=int64#8
# asm 2: mov  $0,>tysubx4=%r10
mov  $0,%r10

# qhasm: txaddy0 = 1
# asm 1: mov  $1,>txaddy0=int64#9
# asm 2: mov  $1,>txaddy0=%r11
mov  $1,%r11

# qhasm: txaddy1 = 0
# asm 1: mov  $0,>txaddy1=int64#10
# asm 2: mov  $0,>txaddy1=%r12
mov  $0,%r12

# qhasm: txaddy2 = 0
# asm 1: mov  $0,>txaddy2=int64#11
# asm 2: mov  $0,>txaddy2=%r13
mov  $0,%r13

# qhasm: txaddy3 = 0
# asm 1: mov  $0,>txaddy3=int64#12
# asm 2: mov  $0,>txaddy3=%r14
mov  $0,%r14

# qhasm: txaddy4 = 0
# asm 1: mov  $0,>txaddy4=int64#13
# asm 2: mov  $0,>txaddy4=%r15
mov  $0,%r15

# qhasm: =? u - 1
# asm 1: cmp  $1,<u=int64#4
# asm 2: cmp  $1,<u=%rcx
cmp  $1,%rcx

# qhasm: t = *(uint64 *)(basep + 0)
# asm 1: movq   0(<basep=int64#2),>t=int64#14
# asm 2: movq   0(<basep=%rsi),>t=%rbx
movq   0(%rsi),%rbx

# qhasm: tysubx0 = t if =
# asm 1: cmove <t=int64#14,<tysubx0=int64#1
# asm 2: cmove <t=%rbx,<tysubx0=%rdi
cmove %rbx,%rdi

# qhasm: t = *(uint64 *)(basep + 8)
# asm 1: movq   8(<basep=int64#2),>t=int64#14
# asm 2: movq   8(<basep=%rsi),>t=%rbx
movq   8(%rsi),%rbx

# qhasm: tysubx1 = t if =
# asm 1: cmove <t=int64#14,<tysubx1=int64#5
# asm 2: cmove <t=%rbx,<tysubx1=%r8
cmove %rbx,%r8

# qhasm: t = *(uint64 *)(basep + 16)
# asm 1: movq   16(<basep=int64#2),>t=int64#14
# asm 2: movq   16(<basep=%rsi),>t=%rbx
movq   16(%rsi),%rbx

# qhasm: tysubx2 = t if =
# asm 1: cmove <t=int64#14,<tysubx2=int64#6
# asm 2: cmove <t=%rbx,<tysubx2=%r9
cmove %rbx,%r9

# qhasm: t = *(uint64 *)(basep + 24)
# asm 1: movq   24(<basep=int64#2),>t=int64#14
# asm 2: movq   24(<basep=%rsi),>t=%rbx
movq   24(%rsi),%rbx

# qhasm: tysubx3 = t if =
# asm 1: cmove <t=int64#14,<tysubx3=int64#7
# asm 2: cmove <t=%rbx,<tysubx3=%rax
cmove %rbx,%rax

# qhasm: t = *(uint64 *)(basep + 32)
# asm 1: movq   32(<basep=int64#2),>t=int64#14
# asm 2: movq   32(<basep=%rsi),>t=%rbx
movq   32(%rsi),%rbx

# qhasm: tysubx4 = t if =
# asm 1: cmove <t=int64#14,<tysubx4=int64#8
# asm 2: cmove <t=%rbx,<tysubx4=%r10
cmove %rbx,%r10

# qhasm: t = *(uint64 *)(basep + 40)
# asm 1: movq   40(<basep=int64#2),>t=int64#14
# asm 2: movq   40(<basep=%rsi),>t=%rbx
movq   40(%rsi),%rbx

# qhasm: txaddy0 = t if =
# asm 1: cmove <t=int64#14,<txaddy0=int64#9
# asm 2: cmove <t=%rbx,<txaddy0=%r11
cmove %rbx,%r11

# qhasm: t = *(uint64 *)(basep + 48)
# asm 1: movq   48(<basep=int64#2),>t=int64#14
# asm 2: movq   48(<basep=%rsi),>t=%rbx
movq   48(%rsi),%rbx

# qhasm: txaddy1 = t if =
# asm 1: cmove <t=int64#14,<txaddy1=int64#10
# asm 2: cmove <t=%rbx,<txaddy1=%r12
cmove %rbx,%r12

# qhasm: t = *(uint64 *)(basep + 56)
# asm 1: movq   56(<basep=int64#2),>t=int64#14
# asm 2: movq   56(<basep=%rsi),>t=%rbx
movq   56(%rsi),%rbx

# qhasm: txaddy2 = t if =
# asm 1: cmove <t=int64#14,<txaddy2=int64#11
# asm 2: cmove <t=%rbx,<txaddy2=%r13
cmove %rbx,%r13

# qhasm: t = *(uint64 *)(basep + 64)
# asm 1: movq   64(<basep=int64#2),>t=int64#14
# asm 2: movq   64(<basep=%rsi),>t=%rbx
movq   64(%rsi),%rbx

# qhasm: txaddy3 = t if =
# asm 1: cmove <t=int64#14,<txaddy3=int64#12
# asm 2: cmove <t=%rbx,<txaddy3=%r14
cmove %rbx,%r14

# qhasm: t = *(uint64 *)(basep + 72)
# asm 1: movq   72(<basep=int64#2),>t=int64#14
# asm 2: movq   72(<basep=%rsi),>t=%rbx
movq   72(%rsi),%rbx

# qhasm: txaddy4 = t if =
# asm 1: cmove <t=int64#14,<txaddy4=int64#13
# asm 2: cmove <t=%rbx,<txaddy4=%r15
cmove %rbx,%r15

# qhasm: =? u - 2
# asm 1: cmp  $2,<u=int64#4
# asm 2: cmp  $2,<u=%rcx
cmp  $2,%rcx

# qhasm: t = *(uint64 *)(basep + 120)
# asm 1: movq   120(<basep=int64#2),>t=int64#14
# asm 2: movq   120(<basep=%rsi),>t=%rbx
movq   120(%rsi),%rbx

# qhasm: tysubx0 = t if =
# asm 1: cmove <t=int64#14,<tysubx0=int64#1
# asm 2: cmove <t=%rbx,<tysubx0=%rdi
cmove %rbx,%rdi

# qhasm: t = *(uint64 *)(basep + 128)
# asm 1: movq   128(<basep=int64#2),>t=int64#14
# asm 2: movq   128(<basep=%rsi),>t=%rbx
movq   128(%rsi),%rbx

# qhasm: tysubx1 = t if =
# asm 1: cmove <t=int64#14,<tysubx1=int64#5
# asm 2: cmove <t=%rbx,<tysubx1=%r8
cmove %rbx,%r8

# qhasm: t = *(uint64 *)(basep + 136)
# asm 1: movq   136(<basep=int64#2),>t=int64#14
# asm 2: movq   136(<basep=%rsi),>t=%rbx
movq   136(%rsi),%rbx

# qhasm: tysubx2 = t if =
# asm 1: cmove <t=int64#14,<tysubx2=int64#6
# asm 2: cmove <t=%rbx,<tysubx2=%r9
cmove %rbx,%r9

# qhasm: t = *(uint64 *)(basep + 144)
# asm 1: movq   144(<basep=int64#2),>t=int64#14
# asm 2: movq   144(<basep=%rsi),>t=%rbx
movq   144(%rsi),%rbx

# qhasm: tysubx3 = t if =
# asm 1: cmove <t=int64#14,<tysubx3=int64#7
# asm 2: cmove <t=%rbx,<tysubx3=%rax
cmove %rbx,%rax

# qhasm: t = *(uint64 *)(basep + 152)
# asm 1: movq   152(<basep=int64#2),>t=int64#14
# asm 2: movq   152(<basep=%rsi),>t=%rbx
movq   152(%rsi),%rbx

# qhasm: tysubx4 = t if =
# asm 1: cmove <t=int64#14,<tysubx4=int64#8
# asm 2: cmove <t=%rbx,<tysubx4=%r10
cmove %rbx,%r10

# qhasm: t = *(uint64 *)(basep + 160)
# asm 1: movq   160(<basep=int64#2),>t=int64#14
# asm 2: movq   160(<basep=%rsi),>t=%rbx
movq   160(%rsi),%rbx

# qhasm: txaddy0 = t if =
# asm 1: cmove <t=int64#14,<txaddy0=int64#9
# asm 2: cmove <t=%rbx,<txaddy0=%r11
cmove %rbx,%r11

# qhasm: t = *(uint64 *)(basep + 168)
# asm 1: movq   168(<basep=int64#2),>t=int64#14
# asm 2: movq   168(<basep=%rsi),>t=%rbx
movq   168(%rsi),%rbx

# qhasm: txaddy1 = t if =
# asm 1: cmove <t=int64#14,<txaddy1=int64#10
# asm 2: cmove <t=%rbx,<txaddy1=%r12
cmove %rbx,%r12

# qhasm: t = *(uint64 *)(basep + 176)
# asm 1: movq   176(<basep=int64#2),>t=int64#14
# asm 2: movq   176(<basep=%rsi),>t=%rbx
movq   176(%rsi),%rbx

# qhasm: txaddy2 = t if =
# asm 1: cmove <t=int64#14,<txaddy2=int64#11
# asm 2: cmove <t=%rbx,<txaddy2=%r13
cmove %rbx,%r13

# qhasm: t = *(uint64 *)(basep + 184)
# asm 1: movq   184(<basep=int64#2),>t=int64#14
# asm 2: movq   184(<basep=%rsi),>t=%rbx
movq   184(%rsi),%rbx

# qhasm: txaddy3 = t if =
# asm 1: cmove <t=int64#14,<txaddy3=int64#12
# asm 2: cmove <t=%rbx,<txaddy3=%r14
cmove %rbx,%r14

# qhasm: t = *(uint64 *)(basep + 192)
# asm 1: movq   192(<basep=int64#2),>t=int64#14
# asm 2: movq   192(<basep=%rsi),>t=%rbx
movq   192(%rsi),%rbx

# qhasm: txaddy4 = t if =
# asm 1: cmove <t=int64#14,<txaddy4=int64#13
# asm 2: cmove <t=%rbx,<txaddy4=%r15
cmove %rbx,%r15

# qhasm: =? u - 3
# asm 1: cmp  $3,<u=int64#4
# asm 2: cmp  $3,<u=%rcx
cmp  $3,%rcx

# qhasm: t = *(uint64 *)(basep + 240)
# asm 1: movq   240(<basep=int64#2),>t=int64#14
# asm 2: movq   240(<basep=%rsi),>t=%rbx
movq   240(%rsi),%rbx

# qhasm: tysubx0 = t if =
# asm 1: cmove <t=int64#14,<tysubx0=int64#1
# asm 2: cmove <t=%rbx,<tysubx0=%rdi
cmove %rbx,%rdi

# qhasm: t = *(uint64 *)(basep + 248)
# asm 1: movq   248(<basep=int64#2),>t=int64#14
# asm 2: movq   248(<basep=%rsi),>t=%rbx
movq   248(%rsi),%rbx

# qhasm: tysubx1 = t if =
# asm 1: cmove <t=int64#14,<tysubx1=int64#5
# asm 2: cmove <t=%rbx,<tysubx1=%r8
cmove %rbx,%r8

# qhasm: t = *(uint64 *)(basep + 256)
# asm 1: movq   256(<basep=int64#2),>t=int64#14
# asm 2: movq   256(<basep=%rsi),>t=%rbx
movq   256(%rsi),%rbx

# qhasm: tysubx2 = t if =
# asm 1: cmove <t=int64#14,<tysubx2=int64#6
# asm 2: cmove <t=%rbx,<tysubx2=%r9
cmove %rbx,%r9

# qhasm: t = *(uint64 *)(basep + 264)
# asm 1: movq   264(<basep=int64#2),>t=int64#14
# asm 2: movq   264(<basep=%rsi),>t=%rbx
movq   264(%rsi),%rbx

# qhasm: tysubx3 = t if =
# asm 1: cmove <t=int64#14,<tysubx3=int64#7
# asm 2: cmove <t=%rbx,<tysubx3=%rax
cmove %rbx,%rax

# qhasm: t = *(uint64 *)(basep + 272)
# asm 1: movq   272(<basep=int64#2),>t=int64#14
# asm 2: movq   272(<basep=%rsi),>t=%rbx
movq   272(%rsi),%rbx

# qhasm: tysubx4 = t if =
# asm 1: cmove <t=int64#14,<tysubx4=int64#8
# asm 2: cmove <t=%rbx,<tysubx4=%r10
cmove %rbx,%r10

# qhasm: t = *(uint64 *)(basep + 280)
# asm 1: movq   280(<basep=int64#2),>t=int64#14
# asm 2: movq   280(<basep=%rsi),>t=%rbx
movq   280(%rsi),%rbx

# qhasm: txaddy0 = t if =
# asm 1: cmove <t=int64#14,<txaddy0=int64#9
# asm 2: cmove <t=%rbx,<txaddy0=%r11
cmove %rbx,%r11

# qhasm: t = *(uint64 *)(basep + 288)
# asm 1: movq   288(<basep=int64#2),>t=int64#14
# asm 2: movq   288(<basep=%rsi),>t=%rbx
movq   288(%rsi),%rbx

# qhasm: txaddy1 = t if =
# asm 1: cmove <t=int64#14,<txaddy1=int64#10
# asm 2: cmove <t=%rbx,<txaddy1=%r12
cmove %rbx,%r12

# qhasm: t = *(uint64 *)(basep + 296)
# asm 1: movq   296(<basep=int64#2),>t=int64#14
# asm 2: movq   296(<basep=%rsi),>t=%rbx
movq   296(%rsi),%rbx

# qhasm: txaddy2 = t if =
# asm 1: cmove <t=int64#14,<txaddy2=int64#11
# asm 2: cmove <t=%rbx,<txaddy2=%r13
cmove %rbx,%r13

# qhasm: t = *(uint64 *)(basep + 304)
# asm 1: movq   304(<basep=int64#2),>t=int64#14
# asm 2: movq   304(<basep=%rsi),>t=%rbx
movq   304(%rsi),%rbx

# qhasm: txaddy3 = t if =
# asm 1: cmove <t=int64#14,<txaddy3=int64#12
# asm 2: cmove <t=%rbx,<txaddy3=%r14
cmove %rbx,%r14

# qhasm: t = *(uint64 *)(basep + 312)
# asm 1: movq   312(<basep=int64#2),>t=int64#14
# asm 2: movq   312(<basep=%rsi),>t=%rbx
movq   312(%rsi),%rbx

# qhasm: txaddy4 = t if =
# asm 1: cmove <t=int64#14,<txaddy4=int64#13
# asm 2: cmove <t=%rbx,<txaddy4=%r15
cmove %rbx,%r15

# qhasm: =? u - 4
# asm 1: cmp  $4,<u=int64#4
# asm 2: cmp  $4,<u=%rcx
cmp  $4,%rcx

# qhasm: t = *(uint64 *)(basep + 360)
# asm 1: movq   360(<basep=int64#2),>t=int64#14
# asm 2: movq   360(<basep=%rsi),>t=%rbx
movq   360(%rsi),%rbx

# qhasm: tysubx0 = t if =
# asm 1: cmove <t=int64#14,<tysubx0=int64#1
# asm 2: cmove <t=%rbx,<tysubx0=%rdi
cmove %rbx,%rdi

# qhasm: t = *(uint64 *)(basep + 368)
# asm 1: movq   368(<basep=int64#2),>t=int64#14
# asm 2: movq   368(<basep=%rsi),>t=%rbx
movq   368(%rsi),%rbx

# qhasm: tysubx1 = t if =
# asm 1: cmove <t=int64#14,<tysubx1=int64#5
# asm 2: cmove <t=%rbx,<tysubx1=%r8
cmove %rbx,%r8

# qhasm: t = *(uint64 *)(basep + 376)
# asm 1: movq   376(<basep=int64#2),>t=int64#14
# asm 2: movq   376(<basep=%rsi),>t=%rbx
movq   376(%rsi),%rbx

# qhasm: tysubx2 = t if =
# asm 1: cmove <t=int64#14,<tysubx2=int64#6
# asm 2: cmove <t=%rbx,<tysubx2=%r9
cmove %rbx,%r9

# qhasm: t = *(uint64 *)(basep + 384)
# asm 1: movq   384(<basep=int64#2),>t=int64#14
# asm 2: movq   384(<basep=%rsi),>t=%rbx
movq   384(%rsi),%rbx

# qhasm: tysubx3 = t if =
# asm 1: cmove <t=int64#14,<tysubx3=int64#7
# asm 2: cmove <t=%rbx,<tysubx3=%rax
cmove %rbx,%rax

# qhasm: t = *(uint64 *)(basep + 392)
# asm 1: movq   392(<basep=int64#2),>t=int64#14
# asm 2: movq   392(<basep=%rsi),>t=%rbx
movq   392(%rsi),%rbx

# qhasm: tysubx4 = t if =
# asm 1: cmove <t=int64#14,<tysubx4=int64#8
# asm 2: cmove <t=%rbx,<tysubx4=%r10
cmove %rbx,%r10

# qhasm: t = *(uint64 *)(basep + 400)
# asm 1: movq   400(<basep=int64#2),>t=int64#14
# asm 2: movq   400(<basep=%rsi),>t=%rbx
movq   400(%rsi),%rbx

# qhasm: txaddy0 = t if =
# asm 1: cmove <t=int64#14,<txaddy0=int64#9
# asm 2: cmove <t=%rbx,<txaddy0=%r11
cmove %rbx,%r11

# qhasm: t = *(uint64 *)(basep + 408)
# asm 1: movq   408(<basep=int64#2),>t=int64#14
# asm 2: movq   408(<basep=%rsi),>t=%rbx
movq   408(%rsi),%rbx

# qhasm: txaddy1 = t if =
# asm 1: cmove <t=int64#14,<txaddy1=int64#10
# asm 2: cmove <t=%rbx,<txaddy1=%r12
cmove %rbx,%r12

# qhasm: t = *(uint64 *)(basep + 416)
# asm 1: movq   416(<basep=int64#2),>t=int64#14
# asm 2: movq   416(<basep=%rsi),>t=%rbx
movq   416(%rsi),%rbx

# qhasm: txaddy2 = t if =
# asm 1: cmove <t=int64#14,<txaddy2=int64#11
# asm 2: cmove <t=%rbx,<txaddy2=%r13
cmove %rbx,%r13

# qhasm: t = *(uint64 *)(basep + 424)
# asm 1: movq   424(<basep=int64#2),>t=int64#14
# asm 2: movq   424(<basep=%rsi),>t=%rbx
movq   424(%rsi),%rbx

# qhasm: txaddy3 = t if =
# asm 1: cmove <t=int64#14,<txaddy3=int64#12
# asm 2: cmove <t=%rbx,<txaddy3=%r14
cmove %rbx,%r14

# qhasm: t = *(uint64 *)(basep + 432)
# asm 1: movq   432(<basep=int64#2),>t=int64#14
# asm 2: movq   432(<basep=%rsi),>t=%rbx
movq   432(%rsi),%rbx

# qhasm: txaddy4 = t if =
# asm 1: cmove <t=int64#14,<txaddy4=int64#13
# asm 2: cmove <t=%rbx,<txaddy4=%r15
cmove %rbx,%r15

# qhasm: =? u - 5
# asm 1: cmp  $5,<u=int64#4
# asm 2: cmp  $5,<u=%rcx
cmp  $5,%rcx

# qhasm: t = *(uint64 *)(basep + 480)
# asm 1: movq   480(<basep=int64#2),>t=int64#14
# asm 2: movq   480(<basep=%rsi),>t=%rbx
movq   480(%rsi),%rbx

# qhasm: tysubx0 = t if =
# asm 1: cmove <t=int64#14,<tysubx0=int64#1
# asm 2: cmove <t=%rbx,<tysubx0=%rdi
cmove %rbx,%rdi

# qhasm: t = *(uint64 *)(basep + 488)
# asm 1: movq   488(<basep=int64#2),>t=int64#14
# asm 2: movq   488(<basep=%rsi),>t=%rbx
movq   488(%rsi),%rbx

# qhasm: tysubx1 = t if =
# asm 1: cmove <t=int64#14,<tysubx1=int64#5
# asm 2: cmove <t=%rbx,<tysubx1=%r8
cmove %rbx,%r8

# qhasm: t = *(uint64 *)(basep + 496)
# asm 1: movq   496(<basep=int64#2),>t=int64#14
# asm 2: movq   496(<basep=%rsi),>t=%rbx
movq   496(%rsi),%rbx

# qhasm: tysubx2 = t if =
# asm 1: cmove <t=int64#14,<tysubx2=int64#6
# asm 2: cmove <t=%rbx,<tysubx2=%r9
cmove %rbx,%r9

# qhasm: t = *(uint64 *)(basep + 504)
# asm 1: movq   504(<basep=int64#2),>t=int64#14
# asm 2: movq   504(<basep=%rsi),>t=%rbx
movq   504(%rsi),%rbx

# qhasm: tysubx3 = t if =
# asm 1: cmove <t=int64#14,<tysubx3=int64#7
# asm 2: cmove <t=%rbx,<tysubx3=%rax
cmove %rbx,%rax

# qhasm: t = *(uint64 *)(basep + 512)
# asm 1: movq   512(<basep=int64#2),>t=int64#14
# asm 2: movq   512(<basep=%rsi),>t=%rbx
movq   512(%rsi),%rbx

# qhasm: tysubx4 = t if =
# asm 1: cmove <t=int64#14,<tysubx4=int64#8
# asm 2: cmove <t=%rbx,<tysubx4=%r10
cmove %rbx,%r10

# qhasm: t = *(uint64 *)(basep + 520)
# asm 1: movq   520(<basep=int64#2),>t=int64#14
# asm 2: movq   520(<basep=%rsi),>t=%rbx
movq   520(%rsi),%rbx

# qhasm: txaddy0 = t if =
# asm 1: cmove <t=int64#14,<txaddy0=int64#9
# asm 2: cmove <t=%rbx,<txaddy0=%r11
cmove %rbx,%r11

# qhasm: t = *(uint64 *)(basep + 528)
# asm 1: movq   528(<basep=int64#2),>t=int64#14
# asm 2: movq   528(<basep=%rsi),>t=%rbx
movq   528(%rsi),%rbx

# qhasm: txaddy1 = t if =
# asm 1: cmove <t=int64#14,<txaddy1=int64#10
# asm 2: cmove <t=%rbx,<txaddy1=%r12
cmove %rbx,%r12

# qhasm: t = *(uint64 *)(basep + 536)
# asm 1: movq   536(<basep=int64#2),>t=int64#14
# asm 2: movq   536(<basep=%rsi),>t=%rbx
movq   536(%rsi),%rbx

# qhasm: txaddy2 = t if =
# asm 1: cmove <t=int64#14,<txaddy2=int64#11
# asm 2: cmove <t=%rbx,<txaddy2=%r13
cmove %rbx,%r13

# qhasm: t = *(uint64 *)(basep + 544)
# asm 1: movq   544(<basep=int64#2),>t=int64#14
# asm 2: movq   544(<basep=%rsi),>t=%rbx
movq   544(%rsi),%rbx

# qhasm: txaddy3 = t if =
# asm 1: cmove <t=int64#14,<txaddy3=int64#12
# asm 2: cmove <t=%rbx,<txaddy3=%r14
cmove %rbx,%r14

# qhasm: t = *(uint64 *)(basep + 552)
# asm 1: movq   552(<basep=int64#2),>t=int64#14
# asm 2: movq   552(<basep=%rsi),>t=%rbx
movq   552(%rsi),%rbx

# qhasm: txaddy4 = t if =
# asm 1: cmove <t=int64#14,<txaddy4=int64#13
# asm 2: cmove <t=%rbx,<txaddy4=%r15
cmove %rbx,%r15

# qhasm: =? u - 6
# asm 1: cmp  $6,<u=int64#4
# asm 2: cmp  $6,<u=%rcx
cmp  $6,%rcx

# qhasm: t = *(uint64 *)(basep + 600)
# asm 1: movq   600(<basep=int64#2),>t=int64#14
# asm 2: movq   600(<basep=%rsi),>t=%rbx
movq   600(%rsi),%rbx

# qhasm: tysubx0 = t if =
# asm 1: cmove <t=int64#14,<tysubx0=int64#1
# asm 2: cmove <t=%rbx,<tysubx0=%rdi
cmove %rbx,%rdi

# qhasm: t = *(uint64 *)(basep + 608)
# asm 1: movq   608(<basep=int64#2),>t=int64#14
# asm 2: movq   608(<basep=%rsi),>t=%rbx
movq   608(%rsi),%rbx

# qhasm: tysubx1 = t if =
# asm 1: cmove <t=int64#14,<tysubx1=int64#5
# asm 2: cmove <t=%rbx,<tysubx1=%r8
cmove %rbx,%r8

# qhasm: t = *(uint64 *)(basep + 616)
# asm 1: movq   616(<basep=int64#2),>t=int64#14
# asm 2: movq   616(<basep=%rsi),>t=%rbx
movq   616(%rsi),%rbx

# qhasm: tysubx2 = t if =
# asm 1: cmove <t=int64#14,<tysubx2=int64#6
# asm 2: cmove <t=%rbx,<tysubx2=%r9
cmove %rbx,%r9

# qhasm: t = *(uint64 *)(basep + 624)
# asm 1: movq   624(<basep=int64#2),>t=int64#14
# asm 2: movq   624(<basep=%rsi),>t=%rbx
movq   624(%rsi),%rbx

# qhasm: tysubx3 = t if =
# asm 1: cmove <t=int64#14,<tysubx3=int64#7
# asm 2: cmove <t=%rbx,<tysubx3=%rax
cmove %rbx,%rax

# qhasm: t = *(uint64 *)(basep + 632)
# asm 1: movq   632(<basep=int64#2),>t=int64#14
# asm 2: movq   632(<basep=%rsi),>t=%rbx
movq   632(%rsi),%rbx

# qhasm: tysubx4 = t if =
# asm 1: cmove <t=int64#14,<tysubx4=int64#8
# asm 2: cmove <t=%rbx,<tysubx4=%r10
cmove %rbx,%r10

# qhasm: t = *(uint64 *)(basep + 640)
# asm 1: movq   640(<basep=int64#2),>t=int64#14
# asm 2: movq   640(<basep=%rsi),>t=%rbx
movq   640(%rsi),%rbx

# qhasm: txaddy0 = t if =
# asm 1: cmove <t=int64#14,<txaddy0=int64#9
# asm 2: cmove <t=%rbx,<txaddy0=%r11
cmove %rbx,%r11

# qhasm: t = *(uint64 *)(basep + 648)
# asm 1: movq   648(<basep=int64#2),>t=int64#14
# asm 2: movq   648(<basep=%rsi),>t=%rbx
movq   648(%rsi),%rbx

# qhasm: txaddy1 = t if =
# asm 1: cmove <t=int64#14,<txaddy1=int64#10
# asm 2: cmove <t=%rbx,<txaddy1=%r12
cmove %rbx,%r12

# qhasm: t = *(uint64 *)(basep + 656)
# asm 1: movq   656(<basep=int64#2),>t=int64#14
# asm 2: movq   656(<basep=%rsi),>t=%rbx
movq   656(%rsi),%rbx

# qhasm: txaddy2 = t if =
# asm 1: cmove <t=int64#14,<txaddy2=int64#11
# asm 2: cmove <t=%rbx,<txaddy2=%r13
cmove %rbx,%r13

# qhasm: t = *(uint64 *)(basep + 664)
# asm 1: movq   664(<basep=int64#2),>t=int64#14
# asm 2: movq   664(<basep=%rsi),>t=%rbx
movq   664(%rsi),%rbx

# qhasm: txaddy3 = t if =
# asm 1: cmove <t=int64#14,<txaddy3=int64#12
# asm 2: cmove <t=%rbx,<txaddy3=%r14
cmove %rbx,%r14

# qhasm: t = *(uint64 *)(basep + 672)
# asm 1: movq   672(<basep=int64#2),>t=int64#14
# asm 2: movq   672(<basep=%rsi),>t=%rbx
movq   672(%rsi),%rbx

# qhasm: txaddy4 = t if =
# asm 1: cmove <t=int64#14,<txaddy4=int64#13
# asm 2: cmove <t=%rbx,<txaddy4=%r15
cmove %rbx,%r15

# qhasm: =? u - 7
# asm 1: cmp  $7,<u=int64#4
# asm 2: cmp  $7,<u=%rcx
cmp  $7,%rcx

# qhasm: t = *(uint64 *)(basep + 720)
# asm 1: movq   720(<basep=int64#2),>t=int64#14
# asm 2: movq   720(<basep=%rsi),>t=%rbx
movq   720(%rsi),%rbx

# qhasm: tysubx0 = t if =
# asm 1: cmove <t=int64#14,<tysubx0=int64#1
# asm 2: cmove <t=%rbx,<tysubx0=%rdi
cmove %rbx,%rdi

# qhasm: t = *(uint64 *)(basep + 728)
# asm 1: movq   728(<basep=int64#2),>t=int64#14
# asm 2: movq   728(<basep=%rsi),>t=%rbx
movq   728(%rsi),%rbx

# qhasm: tysubx1 = t if =
# asm 1: cmove <t=int64#14,<tysubx1=int64#5
# asm 2: cmove <t=%rbx,<tysubx1=%r8
cmove %rbx,%r8

# qhasm: t = *(uint64 *)(basep + 736)
# asm 1: movq   736(<basep=int64#2),>t=int64#14
# asm 2: movq   736(<basep=%rsi),>t=%rbx
movq   736(%rsi),%rbx

# qhasm: tysubx2 = t if =
# asm 1: cmove <t=int64#14,<tysubx2=int64#6
# asm 2: cmove <t=%rbx,<tysubx2=%r9
cmove %rbx,%r9

# qhasm: t = *(uint64 *)(basep + 744)
# asm 1: movq   744(<basep=int64#2),>t=int64#14
# asm 2: movq   744(<basep=%rsi),>t=%rbx
movq   744(%rsi),%rbx

# qhasm: tysubx3 = t if =
# asm 1: cmove <t=int64#14,<tysubx3=int64#7
# asm 2: cmove <t=%rbx,<tysubx3=%rax
cmove %rbx,%rax

# qhasm: t = *(uint64 *)(basep + 752)
# asm 1: movq   752(<basep=int64#2),>t=int64#14
# asm 2: movq   752(<basep=%rsi),>t=%rbx
movq   752(%rsi),%rbx

# qhasm: tysubx4 = t if =
# asm 1: cmove <t=int64#14,<tysubx4=int64#8
# asm 2: cmove <t=%rbx,<tysubx4=%r10
cmove %rbx,%r10

# qhasm: t = *(uint64 *)(basep + 760)
# asm 1: movq   760(<basep=int64#2),>t=int64#14
# asm 2: movq   760(<basep=%rsi),>t=%rbx
movq   760(%rsi),%rbx

# qhasm: txaddy0 = t if =
# asm 1: cmove <t=int64#14,<txaddy0=int64#9
# asm 2: cmove <t=%rbx,<txaddy0=%r11
cmove %rbx,%r11

# qhasm: t = *(uint64 *)(basep + 768)
# asm 1: movq   768(<basep=int64#2),>t=int64#14
# asm 2: movq   768(<basep=%rsi),>t=%rbx
movq   768(%rsi),%rbx

# qhasm: txaddy1 = t if =
# asm 1: cmove <t=int64#14,<txaddy1=int64#10
# asm 2: cmove <t=%rbx,<txaddy1=%r12
cmove %rbx,%r12

# qhasm: t = *(uint64 *)(basep + 776)
# asm 1: movq   776(<basep=int64#2),>t=int64#14
# asm 2: movq   776(<basep=%rsi),>t=%rbx
movq   776(%rsi),%rbx

# qhasm: txaddy2 = t if =
# asm 1: cmove <t=int64#14,<txaddy2=int64#11
# asm 2: cmove <t=%rbx,<txaddy2=%r13
cmove %rbx,%r13

# qhasm: t = *(uint64 *)(basep + 784)
# asm 1: movq   784(<basep=int64#2),>t=int64#14
# asm 2: movq   784(<basep=%rsi),>t=%rbx
movq   784(%rsi),%rbx

# qhasm: txaddy3 = t if =
# asm 1: cmove <t=int64#14,<txaddy3=int64#12
# asm 2: cmove <t=%rbx,<txaddy3=%r14
cmove %rbx,%r14

# qhasm: t = *(uint64 *)(basep + 792)
# asm 1: movq   792(<basep=int64#2),>t=int64#14
# asm 2: movq   792(<basep=%rsi),>t=%rbx
movq   792(%rsi),%rbx

# qhasm: txaddy4 = t if =
# asm 1: cmove <t=int64#14,<txaddy4=int64#13
# asm 2: cmove <t=%rbx,<txaddy4=%r15
cmove %rbx,%r15

# qhasm: =? u - 8
# asm 1: cmp  $8,<u=int64#4
# asm 2: cmp  $8,<u=%rcx
cmp  $8,%rcx

# qhasm: t = *(uint64 *)(basep + 840)
# asm 1: movq   840(<basep=int64#2),>t=int64#14
# asm 2: movq   840(<basep=%rsi),>t=%rbx
movq   840(%rsi),%rbx

# qhasm: tysubx0 = t if =
# asm 1: cmove <t=int64#14,<tysubx0=int64#1
# asm 2: cmove <t=%rbx,<tysubx0=%rdi
cmove %rbx,%rdi

# qhasm: t = *(uint64 *)(basep + 848)
# asm 1: movq   848(<basep=int64#2),>t=int64#14
# asm 2: movq   848(<basep=%rsi),>t=%rbx
movq   848(%rsi),%rbx

# qhasm: tysubx1 = t if =
# asm 1: cmove <t=int64#14,<tysubx1=int64#5
# asm 2: cmove <t=%rbx,<tysubx1=%r8
cmove %rbx,%r8

# qhasm: t = *(uint64 *)(basep + 856)
# asm 1: movq   856(<basep=int64#2),>t=int64#14
# asm 2: movq   856(<basep=%rsi),>t=%rbx
movq   856(%rsi),%rbx

# qhasm: tysubx2 = t if =
# asm 1: cmove <t=int64#14,<tysubx2=int64#6
# asm 2: cmove <t=%rbx,<tysubx2=%r9
cmove %rbx,%r9

# qhasm: t = *(uint64 *)(basep + 864)
# asm 1: movq   864(<basep=int64#2),>t=int64#14
# asm 2: movq   864(<basep=%rsi),>t=%rbx
movq   864(%rsi),%rbx

# qhasm: tysubx3 = t if =
# asm 1: cmove <t=int64#14,<tysubx3=int64#7
# asm 2: cmove <t=%rbx,<tysubx3=%rax
cmove %rbx,%rax

# qhasm: t = *(uint64 *)(basep + 872)
# asm 1: movq   872(<basep=int64#2),>t=int64#14
# asm 2: movq   872(<basep=%rsi),>t=%rbx
movq   872(%rsi),%rbx

# qhasm: tysubx4 = t if =
# asm 1: cmove <t=int64#14,<tysubx4=int64#8
# asm 2: cmove <t=%rbx,<tysubx4=%r10
cmove %rbx,%r10

# qhasm: t = *(uint64 *)(basep + 880)
# asm 1: movq   880(<basep=int64#2),>t=int64#14
# asm 2: movq   880(<basep=%rsi),>t=%rbx
movq   880(%rsi),%rbx

# qhasm: txaddy0 = t if =
# asm 1: cmove <t=int64#14,<txaddy0=int64#9
# asm 2: cmove <t=%rbx,<txaddy0=%r11
cmove %rbx,%r11

# qhasm: t = *(uint64 *)(basep + 888)
# asm 1: movq   888(<basep=int64#2),>t=int64#14
# asm 2: movq   888(<basep=%rsi),>t=%rbx
movq   888(%rsi),%rbx

# qhasm: txaddy1 = t if =
# asm 1: cmove <t=int64#14,<txaddy1=int64#10
# asm 2: cmove <t=%rbx,<txaddy1=%r12
cmove %rbx,%r12

# qhasm: t = *(uint64 *)(basep + 896)
# asm 1: movq   896(<basep=int64#2),>t=int64#14
# asm 2: movq   896(<basep=%rsi),>t=%rbx
movq   896(%rsi),%rbx

# qhasm: txaddy2 = t if =
# asm 1: cmove <t=int64#14,<txaddy2=int64#11
# asm 2: cmove <t=%rbx,<txaddy2=%r13
cmove %rbx,%r13

# qhasm: t = *(uint64 *)(basep + 904)
# asm 1: movq   904(<basep=int64#2),>t=int64#14
# asm 2: movq   904(<basep=%rsi),>t=%rbx
movq   904(%rsi),%rbx

# qhasm: txaddy3 = t if =
# asm 1: cmove <t=int64#14,<txaddy3=int64#12
# asm 2: cmove <t=%rbx,<txaddy3=%r14
cmove %rbx,%r14

# qhasm: t = *(uint64 *)(basep + 912)
# asm 1: movq   912(<basep=int64#2),>t=int64#14
# asm 2: movq   912(<basep=%rsi),>t=%rbx
movq   912(%rsi),%rbx

# qhasm: txaddy4 = t if =
# asm 1: cmove <t=int64#14,<txaddy4=int64#13
# asm 2: cmove <t=%rbx,<txaddy4=%r15
cmove %rbx,%r15

# qhasm: signed<? b - 0
# asm 1: cmp  $0,<b=int64#3
# asm 2: cmp  $0,<b=%rdx
cmp  $0,%rdx

# qhasm: t = tysubx0
# asm 1: mov  <tysubx0=int64#1,>t=int64#14
# asm 2: mov  <tysubx0=%rdi,>t=%rbx
mov  %rdi,%rbx

# qhasm: tysubx0 = txaddy0 if signed<
# asm 1: cmovl <txaddy0=int64#9,<tysubx0=int64#1
# asm 2: cmovl <txaddy0=%r11,<tysubx0=%rdi
cmovl %r11,%rdi

# qhasm: txaddy0 = t if signed<
# asm 1: cmovl <t=int64#14,<txaddy0=int64#9
# asm 2: cmovl <t=%rbx,<txaddy0=%r11
cmovl %rbx,%r11

# qhasm: t = tysubx1
# asm 1: mov  <tysubx1=int64#5,>t=int64#14
# asm 2: mov  <tysubx1=%r8,>t=%rbx
mov  %r8,%rbx

# qhasm: tysubx1 = txaddy1 if signed<
# asm 1: cmovl <txaddy1=int64#10,<tysubx1=int64#5
# asm 2: cmovl <txaddy1=%r12,<tysubx1=%r8
cmovl %r12,%r8

# qhasm: txaddy1 = t if signed<
# asm 1: cmovl <t=int64#14,<txaddy1=int64#10
# asm 2: cmovl <t=%rbx,<txaddy1=%r12
cmovl %rbx,%r12

# qhasm: t = tysubx2
# asm 1: mov  <tysubx2=int64#6,>t=int64#14
# asm 2: mov  <tysubx2=%r9,>t=%rbx
mov  %r9,%rbx

# qhasm: tysubx2 = txaddy2 if signed<
# asm 1: cmovl <txaddy2=int64#11,<tysubx2=int64#6
# asm 2: cmovl <txaddy2=%r13,<tysubx2=%r9
cmovl %r13,%r9

# qhasm: txaddy2 = t if signed<
# asm 1: cmovl <t=int64#14,<txaddy2=int64#11
# asm 2: cmovl <t=%rbx,<txaddy2=%r13
cmovl %rbx,%r13

# qhasm: t = tysubx3
# asm 1: mov  <tysubx3=int64#7,>t=int64#14
# asm 2: mov  <tysubx3=%rax,>t=%rbx
mov  %rax,%rbx

# qhasm: tysubx3 = txaddy3 if signed<
# asm 1: cmovl <txaddy3=int64#12,<tysubx3=int64#7
# asm 2: cmovl <txaddy3=%r14,<tysubx3=%rax
cmovl %r14,%rax

# qhasm: txaddy3 = t if signed<
# asm 1: cmovl <t=int64#14,<txaddy3=int64#12
# asm 2: cmovl <t=%rbx,<txaddy3=%r14
cmovl %rbx,%r14

# qhasm: t = tysubx4
# asm 1: mov  <tysubx4=int64#8,>t=int64#14
# asm 2: mov  <tysubx4=%r10,>t=%rbx
mov  %r10,%rbx

# qhasm: tysubx4 = txaddy4 if signed<
# asm 1: cmovl <txaddy4=int64#13,<tysubx4=int64#8
# asm 2: cmovl <txaddy4=%r15,<tysubx4=%r10
cmovl %r15,%r10

# qhasm: txaddy4 = t if signed<
# asm 1: cmovl <t=int64#14,<txaddy4=int64#13
# asm 2: cmovl <t=%rbx,<txaddy4=%r15
cmovl %rbx,%r15

# qhasm: tp = tp_stack
# asm 1: movq <tp_stack=stack64#8,>tp=int64#14
# asm 2: movq <tp_stack=56(%rsp),>tp=%rbx
movq 56(%rsp),%rbx

# qhasm: *(uint64 *)(tp + 0) = tysubx0
# asm 1: movq   <tysubx0=int64#1,0(<tp=int64#14)
# asm 2: movq   <tysubx0=%rdi,0(<tp=%rbx)
movq   %rdi,0(%rbx)

# qhasm: *(uint64 *)(tp + 8) = tysubx1
# asm 1: movq   <tysubx1=int64#5,8(<tp=int64#14)
# asm 2: movq   <tysubx1=%r8,8(<tp=%rbx)
movq   %r8,8(%rbx)

# qhasm: *(uint64 *)(tp + 16) = tysubx2
# asm 1: movq   <tysubx2=int64#6,16(<tp=int64#14)
# asm 2: movq   <tysubx2=%r9,16(<tp=%rbx)
movq   %r9,16(%rbx)

# qhasm: *(uint64 *)(tp + 24) = tysubx3
# asm 1: movq   <tysubx3=int64#7,24(<tp=int64#14)
# asm 2: movq   <tysubx3=%rax,24(<tp=%rbx)
movq   %rax,24(%rbx)

# qhasm: *(uint64 *)(tp + 32) = tysubx4
# asm 1: movq   <tysubx4=int64#8,32(<tp=int64#14)
# asm 2: movq   <tysubx4=%r10,32(<tp=%rbx)
movq   %r10,32(%rbx)

# qhasm: *(uint64 *)(tp + 40) = txaddy0
# asm 1: movq   <txaddy0=int64#9,40(<tp=int64#14)
# asm 2: movq   <txaddy0=%r11,40(<tp=%rbx)
movq   %r11,40(%rbx)

# qhasm: *(uint64 *)(tp + 48) = txaddy1
# asm 1: movq   <txaddy1=int64#10,48(<tp=int64#14)
# asm 2: movq   <txaddy1=%r12,48(<tp=%rbx)
movq   %r12,48(%rbx)

# qhasm: *(uint64 *)(tp + 56) = txaddy2
# asm 1: movq   <txaddy2=int64#11,56(<tp=int64#14)
# asm 2: movq   <txaddy2=%r13,56(<tp=%rbx)
movq   %r13,56(%rbx)

# qhasm: *(uint64 *)(tp + 64) = txaddy3
# asm 1: movq   <txaddy3=int64#12,64(<tp=int64#14)
# asm 2: movq   <txaddy3=%r14,64(<tp=%rbx)
movq   %r14,64(%rbx)

# qhasm: *(uint64 *)(tp + 72) = txaddy4
# asm 1: movq   <txaddy4=int64#13,72(<tp=int64#14)
# asm 2: movq   <txaddy4=%r15,72(<tp=%rbx)
movq   %r15,72(%rbx)

# qhasm: tt2d0 = 0
# asm 1: mov  $0,>tt2d0=int64#1
# asm 2: mov  $0,>tt2d0=%rdi
mov  $0,%rdi

# qhasm: tt2d1 = 0
# asm 1: mov  $0,>tt2d1=int64#5
# asm 2: mov  $0,>tt2d1=%r8
mov  $0,%r8

# qhasm: tt2d2 = 0
# asm 1: mov  $0,>tt2d2=int64#6
# asm 2: mov  $0,>tt2d2=%r9
mov  $0,%r9

# qhasm: tt2d3 = 0
# asm 1: mov  $0,>tt2d3=int64#7
# asm 2: mov  $0,>tt2d3=%rax
mov  $0,%rax

# qhasm: tt2d4 = 0
# asm 1: mov  $0,>tt2d4=int64#8
# asm 2: mov  $0,>tt2d4=%r10
mov  $0,%r10

# qhasm: =? u - 1
# asm 1: cmp  $1,<u=int64#4
# asm 2: cmp  $1,<u=%rcx
cmp  $1,%rcx

# qhasm: t = *(uint64 *)(basep + 80)
# asm 1: movq   80(<basep=int64#2),>t=int64#9
# asm 2: movq   80(<basep=%rsi),>t=%r11
movq   80(%rsi),%r11

# qhasm: tt2d0 = t if =
# asm 1: cmove <t=int64#9,<tt2d0=int64#1
# asm 2: cmove <t=%r11,<tt2d0=%rdi
cmove %r11,%rdi

# qhasm: t = *(uint64 *)(basep + 88)
# asm 1: movq   88(<basep=int64#2),>t=int64#9
# asm 2: movq   88(<basep=%rsi),>t=%r11
movq   88(%rsi),%r11

# qhasm: tt2d1 = t if =
# asm 1: cmove <t=int64#9,<tt2d1=int64#5
# asm 2: cmove <t=%r11,<tt2d1=%r8
cmove %r11,%r8

# qhasm: t = *(uint64 *)(basep + 96)
# asm 1: movq   96(<basep=int64#2),>t=int64#9
# asm 2: movq   96(<basep=%rsi),>t=%r11
movq   96(%rsi),%r11

# qhasm: tt2d2 = t if =
# asm 1: cmove <t=int64#9,<tt2d2=int64#6
# asm 2: cmove <t=%r11,<tt2d2=%r9
cmove %r11,%r9

# qhasm: t = *(uint64 *)(basep + 104)
# asm 1: movq   104(<basep=int64#2),>t=int64#9
# asm 2: movq   104(<basep=%rsi),>t=%r11
movq   104(%rsi),%r11

# qhasm: tt2d3 = t if =
# asm 1: cmove <t=int64#9,<tt2d3=int64#7
# asm 2: cmove <t=%r11,<tt2d3=%rax
cmove %r11,%rax

# qhasm: t = *(uint64 *)(basep + 112)
# asm 1: movq   112(<basep=int64#2),>t=int64#9
# asm 2: movq   112(<basep=%rsi),>t=%r11
movq   112(%rsi),%r11

# qhasm: tt2d4 = t if =
# asm 1: cmove <t=int64#9,<tt2d4=int64#8
# asm 2: cmove <t=%r11,<tt2d4=%r10
cmove %r11,%r10

# qhasm: =? u - 2
# asm 1: cmp  $2,<u=int64#4
# asm 2: cmp  $2,<u=%rcx
cmp  $2,%rcx

# qhasm: t = *(uint64 *)(basep + 200)
# asm 1: movq   200(<basep=int64#2),>t=int64#9
# asm 2: movq   200(<basep=%rsi),>t=%r11
movq   200(%rsi),%r11

# qhasm: tt2d0 = t if =
# asm 1: cmove <t=int64#9,<tt2d0=int64#1
# asm 2: cmove <t=%r11,<tt2d0=%rdi
cmove %r11,%rdi

# qhasm: t = *(uint64 *)(basep + 208)
# asm 1: movq   208(<basep=int64#2),>t=int64#9
# asm 2: movq   208(<basep=%rsi),>t=%r11
movq   208(%rsi),%r11

# qhasm: tt2d1 = t if =
# asm 1: cmove <t=int64#9,<tt2d1=int64#5
# asm 2: cmove <t=%r11,<tt2d1=%r8
cmove %r11,%r8

# qhasm: t = *(uint64 *)(basep + 216)
# asm 1: movq   216(<basep=int64#2),>t=int64#9
# asm 2: movq   216(<basep=%rsi),>t=%r11
movq   216(%rsi),%r11

# qhasm: tt2d2 = t if =
# asm 1: cmove <t=int64#9,<tt2d2=int64#6
# asm 2: cmove <t=%r11,<tt2d2=%r9
cmove %r11,%r9

# qhasm: t = *(uint64 *)(basep + 224)
# asm 1: movq   224(<basep=int64#2),>t=int64#9
# asm 2: movq   224(<basep=%rsi),>t=%r11
movq   224(%rsi),%r11

# qhasm: tt2d3 = t if =
# asm 1: cmove <t=int64#9,<tt2d3=int64#7
# asm 2: cmove <t=%r11,<tt2d3=%rax
cmove %r11,%rax

# qhasm: t = *(uint64 *)(basep + 232)
# asm 1: movq   232(<basep=int64#2),>t=int64#9
# asm 2: movq   232(<basep=%rsi),>t=%r11
movq   232(%rsi),%r11

# qhasm: tt2d4 = t if =
# asm 1: cmove <t=int64#9,<tt2d4=int64#8
# asm 2: cmove <t=%r11,<tt2d4=%r10
cmove %r11,%r10

# qhasm: =? u - 3
# asm 1: cmp  $3,<u=int64#4
# asm 2: cmp  $3,<u=%rcx
cmp  $3,%rcx

# qhasm: t = *(uint64 *)(basep + 320)
# asm 1: movq   320(<basep=int64#2),>t=int64#9
# asm 2: movq   320(<basep=%rsi),>t=%r11
movq   320(%rsi),%r11

# qhasm: tt2d0 = t if =
# asm 1: cmove <t=int64#9,<tt2d0=int64#1
# asm 2: cmove <t=%r11,<tt2d0=%rdi
cmove %r11,%rdi

# qhasm: t = *(uint64 *)(basep + 328)
# asm 1: movq   328(<basep=int64#2),>t=int64#9
# asm 2: movq   328(<basep=%rsi),>t=%r11
movq   328(%rsi),%r11

# qhasm: tt2d1 = t if =
# asm 1: cmove <t=int64#9,<tt2d1=int64#5
# asm 2: cmove <t=%r11,<tt2d1=%r8
cmove %r11,%r8

# qhasm: t = *(uint64 *)(basep + 336)
# asm 1: movq   336(<basep=int64#2),>t=int64#9
# asm 2: movq   336(<basep=%rsi),>t=%r11
movq   336(%rsi),%r11

# qhasm: tt2d2 = t if =
# asm 1: cmove <t=int64#9,<tt2d2=int64#6
# asm 2: cmove <t=%r11,<tt2d2=%r9
cmove %r11,%r9

# qhasm: t = *(uint64 *)(basep + 344)
# asm 1: movq   344(<basep=int64#2),>t=int64#9
# asm 2: movq   344(<basep=%rsi),>t=%r11
movq   344(%rsi),%r11

# qhasm: tt2d3 = t if =
# asm 1: cmove <t=int64#9,<tt2d3=int64#7
# asm 2: cmove <t=%r11,<tt2d3=%rax
cmove %r11,%rax

# qhasm: t = *(uint64 *)(basep + 352)
# asm 1: movq   352(<basep=int64#2),>t=int64#9
# asm 2: movq   352(<basep=%rsi),>t=%r11
movq   352(%rsi),%r11

# qhasm: tt2d4 = t if =
# asm 1: cmove <t=int64#9,<tt2d4=int64#8
# asm 2: cmove <t=%r11,<tt2d4=%r10
cmove %r11,%r10

# qhasm: =? u - 4
# asm 1: cmp  $4,<u=int64#4
# asm 2: cmp  $4,<u=%rcx
cmp  $4,%rcx

# qhasm: t = *(uint64 *)(basep + 440)
# asm 1: movq   440(<basep=int64#2),>t=int64#9
# asm 2: movq   440(<basep=%rsi),>t=%r11
movq   440(%rsi),%r11

# qhasm: tt2d0 = t if =
# asm 1: cmove <t=int64#9,<tt2d0=int64#1
# asm 2: cmove <t=%r11,<tt2d0=%rdi
cmove %r11,%rdi

# qhasm: t = *(uint64 *)(basep + 448)
# asm 1: movq   448(<basep=int64#2),>t=int64#9
# asm 2: movq   448(<basep=%rsi),>t=%r11
movq   448(%rsi),%r11

# qhasm: tt2d1 = t if =
# asm 1: cmove <t=int64#9,<tt2d1=int64#5
# asm 2: cmove <t=%r11,<tt2d1=%r8
cmove %r11,%r8

# qhasm: t = *(uint64 *)(basep + 456)
# asm 1: movq   456(<basep=int64#2),>t=int64#9
# asm 2: movq   456(<basep=%rsi),>t=%r11
movq   456(%rsi),%r11

# qhasm: tt2d2 = t if =
# asm 1: cmove <t=int64#9,<tt2d2=int64#6
# asm 2: cmove <t=%r11,<tt2d2=%r9
cmove %r11,%r9

# qhasm: t = *(uint64 *)(basep + 464)
# asm 1: movq   464(<basep=int64#2),>t=int64#9
# asm 2: movq   464(<basep=%rsi),>t=%r11
movq   464(%rsi),%r11

# qhasm: tt2d3 = t if =
# asm 1: cmove <t=int64#9,<tt2d3=int64#7
# asm 2: cmove <t=%r11,<tt2d3=%rax
cmove %r11,%rax

# qhasm: t = *(uint64 *)(basep + 472)
# asm 1: movq   472(<basep=int64#2),>t=int64#9
# asm 2: movq   472(<basep=%rsi),>t=%r11
movq   472(%rsi),%r11

# qhasm: tt2d4 = t if =
# asm 1: cmove <t=int64#9,<tt2d4=int64#8
# asm 2: cmove <t=%r11,<tt2d4=%r10
cmove %r11,%r10

# qhasm: =? u - 5
# asm 1: cmp  $5,<u=int64#4
# asm 2: cmp  $5,<u=%rcx
cmp  $5,%rcx

# qhasm: t = *(uint64 *)(basep + 560)
# asm 1: movq   560(<basep=int64#2),>t=int64#9
# asm 2: movq   560(<basep=%rsi),>t=%r11
movq   560(%rsi),%r11

# qhasm: tt2d0 = t if =
# asm 1: cmove <t=int64#9,<tt2d0=int64#1
# asm 2: cmove <t=%r11,<tt2d0=%rdi
cmove %r11,%rdi

# qhasm: t = *(uint64 *)(basep + 568)
# asm 1: movq   568(<basep=int64#2),>t=int64#9
# asm 2: movq   568(<basep=%rsi),>t=%r11
movq   568(%rsi),%r11

# qhasm: tt2d1 = t if =
# asm 1: cmove <t=int64#9,<tt2d1=int64#5
# asm 2: cmove <t=%r11,<tt2d1=%r8
cmove %r11,%r8

# qhasm: t = *(uint64 *)(basep + 576)
# asm 1: movq   576(<basep=int64#2),>t=int64#9
# asm 2: movq   576(<basep=%rsi),>t=%r11
movq   576(%rsi),%r11

# qhasm: tt2d2 = t if =
# asm 1: cmove <t=int64#9,<tt2d2=int64#6
# asm 2: cmove <t=%r11,<tt2d2=%r9
cmove %r11,%r9

# qhasm: t = *(uint64 *)(basep + 584)
# asm 1: movq   584(<basep=int64#2),>t=int64#9
# asm 2: movq   584(<basep=%rsi),>t=%r11
movq   584(%rsi),%r11

# qhasm: tt2d3 = t if =
# asm 1: cmove <t=int64#9,<tt2d3=int64#7
# asm 2: cmove <t=%r11,<tt2d3=%rax
cmove %r11,%rax

# qhasm: t = *(uint64 *)(basep + 592)
# asm 1: movq   592(<basep=int64#2),>t=int64#9
# asm 2: movq   592(<basep=%rsi),>t=%r11
movq   592(%rsi),%r11

# qhasm: tt2d4 = t if =
# asm 1: cmove <t=int64#9,<tt2d4=int64#8
# asm 2: cmove <t=%r11,<tt2d4=%r10
cmove %r11,%r10

# qhasm: =? u - 6
# asm 1: cmp  $6,<u=int64#4
# asm 2: cmp  $6,<u=%rcx
cmp  $6,%rcx

# qhasm: t = *(uint64 *)(basep + 680)
# asm 1: movq   680(<basep=int64#2),>t=int64#9
# asm 2: movq   680(<basep=%rsi),>t=%r11
movq   680(%rsi),%r11

# qhasm: tt2d0 = t if =
# asm 1: cmove <t=int64#9,<tt2d0=int64#1
# asm 2: cmove <t=%r11,<tt2d0=%rdi
cmove %r11,%rdi

# qhasm: t = *(uint64 *)(basep + 688)
# asm 1: movq   688(<basep=int64#2),>t=int64#9
# asm 2: movq   688(<basep=%rsi),>t=%r11
movq   688(%rsi),%r11

# qhasm: tt2d1 = t if =
# asm 1: cmove <t=int64#9,<tt2d1=int64#5
# asm 2: cmove <t=%r11,<tt2d1=%r8
cmove %r11,%r8

# qhasm: t = *(uint64 *)(basep + 696)
# asm 1: movq   696(<basep=int64#2),>t=int64#9
# asm 2: movq   696(<basep=%rsi),>t=%r11
movq   696(%rsi),%r11

# qhasm: tt2d2 = t if =
# asm 1: cmove <t=int64#9,<tt2d2=int64#6
# asm 2: cmove <t=%r11,<tt2d2=%r9
cmove %r11,%r9

# qhasm: t = *(uint64 *)(basep + 704)
# asm 1: movq   704(<basep=int64#2),>t=int64#9
# asm 2: movq   704(<basep=%rsi),>t=%r11
movq   704(%rsi),%r11

# qhasm: tt2d3 = t if =
# asm 1: cmove <t=int64#9,<tt2d3=int64#7
# asm 2: cmove <t=%r11,<tt2d3=%rax
cmove %r11,%rax

# qhasm: t = *(uint64 *)(basep + 712)
# asm 1: movq   712(<basep=int64#2),>t=int64#9
# asm 2: movq   712(<basep=%rsi),>t=%r11
movq   712(%rsi),%r11

# qhasm: tt2d4 = t if =
# asm 1: cmove <t=int64#9,<tt2d4=int64#8
# asm 2: cmove <t=%r11,<tt2d4=%r10
cmove %r11,%r10

# qhasm: =? u - 7
# asm 1: cmp  $7,<u=int64#4
# asm 2: cmp  $7,<u=%rcx
cmp  $7,%rcx

# qhasm: t = *(uint64 *)(basep + 800)
# asm 1: movq   800(<basep=int64#2),>t=int64#9
# asm 2: movq   800(<basep=%rsi),>t=%r11
movq   800(%rsi),%r11

# qhasm: tt2d0 = t if =
# asm 1: cmove <t=int64#9,<tt2d0=int64#1
# asm 2: cmove <t=%r11,<tt2d0=%rdi
cmove %r11,%rdi

# qhasm: t = *(uint64 *)(basep + 808)
# asm 1: movq   808(<basep=int64#2),>t=int64#9
# asm 2: movq   808(<basep=%rsi),>t=%r11
movq   808(%rsi),%r11

# qhasm: tt2d1 = t if =
# asm 1: cmove <t=int64#9,<tt2d1=int64#5
# asm 2: cmove <t=%r11,<tt2d1=%r8
cmove %r11,%r8

# qhasm: t = *(uint64 *)(basep + 816)
# asm 1: movq   816(<basep=int64#2),>t=int64#9
# asm 2: movq   816(<basep=%rsi),>t=%r11
movq   816(%rsi),%r11

# qhasm: tt2d2 = t if =
# asm 1: cmove <t=int64#9,<tt2d2=int64#6
# asm 2: cmove <t=%r11,<tt2d2=%r9
cmove %r11,%r9

# qhasm: t = *(uint64 *)(basep + 824)
# asm 1: movq   824(<basep=int64#2),>t=int64#9
# asm 2: movq   824(<basep=%rsi),>t=%r11
movq   824(%rsi),%r11

# qhasm: tt2d3 = t if =
# asm 1: cmove <t=int64#9,<tt2d3=int64#7
# asm 2: cmove <t=%r11,<tt2d3=%rax
cmove %r11,%rax

# qhasm: t = *(uint64 *)(basep + 832)
# asm 1: movq   832(<basep=int64#2),>t=int64#9
# asm 2: movq   832(<basep=%rsi),>t=%r11
movq   832(%rsi),%r11

# qhasm: tt2d4 = t if =
# asm 1: cmove <t=int64#9,<tt2d4=int64#8
# asm 2: cmove <t=%r11,<tt2d4=%r10
cmove %r11,%r10

# qhasm: =? u - 8
# asm 1: cmp  $8,<u=int64#4
# asm 2: cmp  $8,<u=%rcx
cmp  $8,%rcx

# qhasm: t = *(uint64 *)(basep + 920)
# asm 1: movq   920(<basep=int64#2),>t=int64#4
# asm 2: movq   920(<basep=%rsi),>t=%rcx
movq   920(%rsi),%rcx

# qhasm: tt2d0 = t if =
# asm 1: cmove <t=int64#4,<tt2d0=int64#1
# asm 2: cmove <t=%rcx,<tt2d0=%rdi
cmove %rcx,%rdi

# qhasm: t = *(uint64 *)(basep + 928)
# asm 1: movq   928(<basep=int64#2),>t=int64#4
# asm 2: movq   928(<basep=%rsi),>t=%rcx
movq   928(%rsi),%rcx

# qhasm: tt2d1 = t if =
# asm 1: cmove <t=int64#4,<tt2d1=int64#5
# asm 2: cmove <t=%rcx,<tt2d1=%r8
cmove %rcx,%r8

# qhasm: t = *(uint64 *)(basep + 936)
# asm 1: movq   936(<basep=int64#2),>t=int64#4
# asm 2: movq   936(<basep=%rsi),>t=%rcx
movq   936(%rsi),%rcx

# qhasm: tt2d2 = t if =
# asm 1: cmove <t=int64#4,<tt2d2=int64#6
# asm 2: cmove <t=%rcx,<tt2d2=%r9
cmove %rcx,%r9

# qhasm: t = *(uint64 *)(basep + 944)
# asm 1: movq   944(<basep=int64#2),>t=int64#4
# asm 2: movq   944(<basep=%rsi),>t=%rcx
movq   944(%rsi),%rcx

# qhasm: tt2d3 = t if =
# asm 1: cmove <t=int64#4,<tt2d3=int64#7
# asm 2: cmove <t=%rcx,<tt2d3=%rax
cmove %rcx,%rax

# qhasm: t = *(uint64 *)(basep + 952)
# asm 1: movq   952(<basep=int64#2),>t=int64#2
# asm 2: movq   952(<basep=%rsi),>t=%rsi
movq   952(%rsi),%rsi

# qhasm: tt2d4 = t if =
# asm 1: cmove <t=int64#2,<tt2d4=int64#8
# asm 2: cmove <t=%rsi,<tt2d4=%r10
cmove %rsi,%r10

# qhasm: tt0 = *(uint64 *)&CONST_2P0
# asm 1: movq CONST_2P0,>tt0=int64#2
# asm 2: movq CONST_2P0,>tt0=%rsi
movq CONST_2P0,%rsi

# qhasm: tt1 = *(uint64 *)&CONST_2P1234
# asm 1: movq CONST_2P1234,>tt1=int64#4
# asm 2: movq CONST_2P1234,>tt1=%rcx
movq CONST_2P1234,%rcx

# qhasm: tt2 = *(uint64 *)&CONST_2P1234
# asm 1: movq CONST_2P1234,>tt2=int64#9
# asm 2: movq CONST_2P1234,>tt2=%r11
movq CONST_2P1234,%r11

# qhasm: tt3 = *(uint64 *)&CONST_2P1234
# asm 1: movq CONST_2P1234,>tt3=int64#10
# asm 2: movq CONST_2P1234,>tt3=%r12
movq CONST_2P1234,%r12

# qhasm: tt4 = *(uint64 *)&CONST_2P1234
# asm 1: movq CONST_2P1234,>tt4=int64#11
# asm 2: movq CONST_2P1234,>tt4=%r13
movq CONST_2P1234,%r13

# qhasm: tt0 -= tt2d0
# asm 1: sub  <tt2d0=int64#1,<tt0=int64#2
# asm 2: sub  <tt2d0=%rdi,<tt0=%rsi
sub  %rdi,%rsi

# qhasm: tt1 -= tt2d1
# asm 1: sub  <tt2d1=int64#5,<tt1=int64#4
# asm 2: sub  <tt2d1=%r8,<tt1=%rcx
sub  %r8,%rcx

# qhasm: tt2 -= tt2d2
# asm 1: sub  <tt2d2=int64#6,<tt2=int64#9
# asm 2: sub  <tt2d2=%r9,<tt2=%r11
sub  %r9,%r11

# qhasm: tt3 -= tt2d3
# asm 1: sub  <tt2d3=int64#7,<tt3=int64#10
# asm 2: sub  <tt2d3=%rax,<tt3=%r12
sub  %rax,%r12

# qhasm: tt4 -= tt2d4
# asm 1: sub  <tt2d4=int64#8,<tt4=int64#11
# asm 2: sub  <tt2d4=%r10,<tt4=%r13
sub  %r10,%r13

# qhasm: signed<? b - 0
# asm 1: cmp  $0,<b=int64#3
# asm 2: cmp  $0,<b=%rdx
cmp  $0,%rdx

# qhasm: tt2d0 = tt0 if signed<
# asm 1: cmovl <tt0=int64#2,<tt2d0=int64#1
# asm 2: cmovl <tt0=%rsi,<tt2d0=%rdi
cmovl %rsi,%rdi

# qhasm: tt2d1 = tt1 if signed<
# asm 1: cmovl <tt1=int64#4,<tt2d1=int64#5
# asm 2: cmovl <tt1=%rcx,<tt2d1=%r8
cmovl %rcx,%r8

# qhasm: tt2d2 = tt2 if signed<
# asm 1: cmovl <tt2=int64#9,<tt2d2=int64#6
# asm 2: cmovl <tt2=%r11,<tt2d2=%r9
cmovl %r11,%r9

# qhasm: tt2d3 = tt3 if signed<
# asm 1: cmovl <tt3=int64#10,<tt2d3=int64#7
# asm 2: cmovl <tt3=%r12,<tt2d3=%rax
cmovl %r12,%rax

# qhasm: tt2d4 = tt4 if signed<
# asm 1: cmovl <tt4=int64#11,<tt2d4=int64#8
# asm 2: cmovl <tt4=%r13,<tt2d4=%r10
cmovl %r13,%r10

# qhasm: *(uint64 *)(tp + 80) = tt2d0
# asm 1: movq   <tt2d0=int64#1,80(<tp=int64#14)
# asm 2: movq   <tt2d0=%rdi,80(<tp=%rbx)
movq   %rdi,80(%rbx)

# qhasm: *(uint64 *)(tp + 88) = tt2d1
# asm 1: movq   <tt2d1=int64#5,88(<tp=int64#14)
# asm 2: movq   <tt2d1=%r8,88(<tp=%rbx)
movq   %r8,88(%rbx)

# qhasm: *(uint64 *)(tp + 96) = tt2d2
# asm 1: movq   <tt2d2=int64#6,96(<tp=int64#14)
# asm 2: movq   <tt2d2=%r9,96(<tp=%rbx)
movq   %r9,96(%rbx)

# qhasm: *(uint64 *)(tp + 104) = tt2d3
# asm 1: movq   <tt2d3=int64#7,104(<tp=int64#14)
# asm 2: movq   <tt2d3=%rax,104(<tp=%rbx)
movq   %rax,104(%rbx)

# qhasm: *(uint64 *)(tp + 112) = tt2d4
# asm 1: movq   <tt2d4=int64#8,112(<tp=int64#14)
# asm 2: movq   <tt2d4=%r10,112(<tp=%rbx)
movq   %r10,112(%rbx)

# qhasm: caller_r11 = r11_stack
# asm 1: movq <r11_stack=stack64#1,>caller_r11=int64#9
# asm 2: movq <r11_stack=0(%rsp),>caller_r11=%r11
movq 0(%rsp),%r11

# qhasm: caller_r12 = r12_stack
# asm 1: movq <r12_stack=stack64#2,>caller_r12=int64#10
# asm 2: movq <r12_stack=8(%rsp),>caller_r12=%r12
movq 8(%rsp),%r12

# qhasm: caller_r13 = r13_stack
# asm 1: movq <r13_stack=stack64#3,>caller_r13=int64#11
# asm 2: movq <r13_stack=16(%rsp),>caller_r13=%r13
movq 16(%rsp),%r13

# qhasm: caller_r14 = r14_stack
# asm 1: movq <r14_stack=stack64#4,>caller_r14=int64#12
# asm 2: movq <r14_stack=24(%rsp),>caller_r14=%r14
movq 24(%rsp),%r14

# qhasm: caller_r15 = r15_stack
# asm 1: movq <r15_stack=stack64#5,>caller_r15=int64#13
# asm 2: movq <r15_stack=32(%rsp),>caller_r15=%r15
movq 32(%rsp),%r15

# qhasm: caller_rbx = rbx_stack
# asm 1: movq <rbx_stack=stack64#6,>caller_rbx=int64#14
# asm 2: movq <rbx_stack=40(%rsp),>caller_rbx=%rbx
movq 40(%rsp),%rbx

# qhasm: caller_rbp = rbp_stack
# asm 1: movq <rbp_stack=stack64#7,>caller_rbp=int64#15
# asm 2: movq <rbp_stack=48(%rsp),>caller_rbp=%rbp
movq 48(%rsp),%rbp

# qhasm: return 
add %r11,%rsp
ret
