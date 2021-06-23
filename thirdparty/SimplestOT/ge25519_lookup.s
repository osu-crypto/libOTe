
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

# qhasm: int64 s0

# qhasm: int64 s1

# qhasm: int64 s2

# qhasm: int64 s3

# qhasm: int64 s4

# qhasm: int64 r0

# qhasm: int64 r1

# qhasm: int64 r2

# qhasm: int64 r3

# qhasm: int64 r4

# qhasm: int64 x0

# qhasm: int64 x1

# qhasm: int64 x2

# qhasm: int64 x3

# qhasm: int64 x4

# qhasm: int64 y0

# qhasm: int64 y1

# qhasm: int64 y2

# qhasm: int64 y3

# qhasm: int64 y4

# qhasm: int64 z0

# qhasm: int64 z1

# qhasm: int64 z2

# qhasm: int64 z3

# qhasm: int64 z4

# qhasm: int64 t0

# qhasm: int64 t1

# qhasm: int64 t2

# qhasm: int64 t3

# qhasm: int64 t4

# qhasm: int64 b

# qhasm: int64 t

# qhasm: int64 u

# qhasm: int64 mask

# qhasm: stack64 r11_stack

# qhasm: stack64 r12_stack

# qhasm: stack64 r13_stack

# qhasm: stack64 r14_stack

# qhasm: stack64 r15_stack

# qhasm: stack64 rbx_stack

# qhasm: stack64 rbp_stack

# qhasm: enter ge25519_lookup_asm
.p2align 5
.global _ge25519_lookup_asm
.global ge25519_lookup_asm
_ge25519_lookup_asm:
ge25519_lookup_asm:
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

# qhasm: b = *( int8  *) (input_2 + 0)
# asm 1: movsbq 0(<input_2=int64#3),>b=int64#3
# asm 2: movsbq 0(<input_2=%rdx),>b=%rdx
movsbq 0(%rdx),%rdx

# qhasm: mask = b
# asm 1: mov  <b=int64#3,>mask=int64#4
# asm 2: mov  <b=%rdx,>mask=%rcx
mov  %rdx,%rcx

# qhasm: (int64) mask >>= 7
# asm 1: sar  $7,<mask=int64#4
# asm 2: sar  $7,<mask=%rcx
sar  $7,%rcx

# qhasm: u = b
# asm 1: mov  <b=int64#3,>u=int64#5
# asm 2: mov  <b=%rdx,>u=%r8
mov  %rdx,%r8

# qhasm: u += mask
# asm 1: add  <mask=int64#4,<u=int64#5
# asm 2: add  <mask=%rcx,<u=%r8
add  %rcx,%r8

# qhasm: u ^= mask
# asm 1: xor  <mask=int64#4,<u=int64#5
# asm 2: xor  <mask=%rcx,<u=%r8
xor  %rcx,%r8

# qhasm: x0 = 0
# asm 1: mov  $0,>x0=int64#4
# asm 2: mov  $0,>x0=%rcx
mov  $0,%rcx

# qhasm: x1 = 0
# asm 1: mov  $0,>x1=int64#6
# asm 2: mov  $0,>x1=%r9
mov  $0,%r9

# qhasm: x2 = 0
# asm 1: mov  $0,>x2=int64#7
# asm 2: mov  $0,>x2=%rax
mov  $0,%rax

# qhasm: x3 = 0
# asm 1: mov  $0,>x3=int64#8
# asm 2: mov  $0,>x3=%r10
mov  $0,%r10

# qhasm: x4 = 0
# asm 1: mov  $0,>x4=int64#9
# asm 2: mov  $0,>x4=%r11
mov  $0,%r11

# qhasm: y0 = 1
# asm 1: mov  $1,>y0=int64#10
# asm 2: mov  $1,>y0=%r12
mov  $1,%r12

# qhasm: y1 = 0
# asm 1: mov  $0,>y1=int64#11
# asm 2: mov  $0,>y1=%r13
mov  $0,%r13

# qhasm: y2 = 0
# asm 1: mov  $0,>y2=int64#12
# asm 2: mov  $0,>y2=%r14
mov  $0,%r14

# qhasm: y3 = 0
# asm 1: mov  $0,>y3=int64#13
# asm 2: mov  $0,>y3=%r15
mov  $0,%r15

# qhasm: y4 = 0
# asm 1: mov  $0,>y4=int64#14
# asm 2: mov  $0,>y4=%rbx
mov  $0,%rbx

# qhasm: =? u - 1
# asm 1: cmp  $1,<u=int64#5
# asm 2: cmp  $1,<u=%r8
cmp  $1,%r8

# qhasm: t = *(uint64 *) (input_1 + 0)
# asm 1: movq   0(<input_1=int64#2),>t=int64#15
# asm 2: movq   0(<input_1=%rsi),>t=%rbp
movq   0(%rsi),%rbp

# qhasm: x0 = t if =
# asm 1: cmove <t=int64#15,<x0=int64#4
# asm 2: cmove <t=%rbp,<x0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 8)
# asm 1: movq   8(<input_1=int64#2),>t=int64#15
# asm 2: movq   8(<input_1=%rsi),>t=%rbp
movq   8(%rsi),%rbp

# qhasm: x1 = t if =
# asm 1: cmove <t=int64#15,<x1=int64#6
# asm 2: cmove <t=%rbp,<x1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 16)
# asm 1: movq   16(<input_1=int64#2),>t=int64#15
# asm 2: movq   16(<input_1=%rsi),>t=%rbp
movq   16(%rsi),%rbp

# qhasm: x2 = t if =
# asm 1: cmove <t=int64#15,<x2=int64#7
# asm 2: cmove <t=%rbp,<x2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 24)
# asm 1: movq   24(<input_1=int64#2),>t=int64#15
# asm 2: movq   24(<input_1=%rsi),>t=%rbp
movq   24(%rsi),%rbp

# qhasm: x3 = t if =
# asm 1: cmove <t=int64#15,<x3=int64#8
# asm 2: cmove <t=%rbp,<x3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 32)
# asm 1: movq   32(<input_1=int64#2),>t=int64#15
# asm 2: movq   32(<input_1=%rsi),>t=%rbp
movq   32(%rsi),%rbp

# qhasm: x4 = t if =
# asm 1: cmove <t=int64#15,<x4=int64#9
# asm 2: cmove <t=%rbp,<x4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 40)
# asm 1: movq   40(<input_1=int64#2),>t=int64#15
# asm 2: movq   40(<input_1=%rsi),>t=%rbp
movq   40(%rsi),%rbp

# qhasm: y0 = t if =
# asm 1: cmove <t=int64#15,<y0=int64#10
# asm 2: cmove <t=%rbp,<y0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 48)
# asm 1: movq   48(<input_1=int64#2),>t=int64#15
# asm 2: movq   48(<input_1=%rsi),>t=%rbp
movq   48(%rsi),%rbp

# qhasm: y1 = t if =
# asm 1: cmove <t=int64#15,<y1=int64#11
# asm 2: cmove <t=%rbp,<y1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 56)
# asm 1: movq   56(<input_1=int64#2),>t=int64#15
# asm 2: movq   56(<input_1=%rsi),>t=%rbp
movq   56(%rsi),%rbp

# qhasm: y2 = t if =
# asm 1: cmove <t=int64#15,<y2=int64#12
# asm 2: cmove <t=%rbp,<y2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 64)
# asm 1: movq   64(<input_1=int64#2),>t=int64#15
# asm 2: movq   64(<input_1=%rsi),>t=%rbp
movq   64(%rsi),%rbp

# qhasm: y3 = t if =
# asm 1: cmove <t=int64#15,<y3=int64#13
# asm 2: cmove <t=%rbp,<y3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 72)
# asm 1: movq   72(<input_1=int64#2),>t=int64#15
# asm 2: movq   72(<input_1=%rsi),>t=%rbp
movq   72(%rsi),%rbp

# qhasm: y4 = t if =
# asm 1: cmove <t=int64#15,<y4=int64#14
# asm 2: cmove <t=%rbp,<y4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 2
# asm 1: cmp  $2,<u=int64#5
# asm 2: cmp  $2,<u=%r8
cmp  $2,%r8

# qhasm: t = *(uint64 *) (input_1 + 160)
# asm 1: movq   160(<input_1=int64#2),>t=int64#15
# asm 2: movq   160(<input_1=%rsi),>t=%rbp
movq   160(%rsi),%rbp

# qhasm: x0 = t if =
# asm 1: cmove <t=int64#15,<x0=int64#4
# asm 2: cmove <t=%rbp,<x0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 168)
# asm 1: movq   168(<input_1=int64#2),>t=int64#15
# asm 2: movq   168(<input_1=%rsi),>t=%rbp
movq   168(%rsi),%rbp

# qhasm: x1 = t if =
# asm 1: cmove <t=int64#15,<x1=int64#6
# asm 2: cmove <t=%rbp,<x1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 176)
# asm 1: movq   176(<input_1=int64#2),>t=int64#15
# asm 2: movq   176(<input_1=%rsi),>t=%rbp
movq   176(%rsi),%rbp

# qhasm: x2 = t if =
# asm 1: cmove <t=int64#15,<x2=int64#7
# asm 2: cmove <t=%rbp,<x2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 184)
# asm 1: movq   184(<input_1=int64#2),>t=int64#15
# asm 2: movq   184(<input_1=%rsi),>t=%rbp
movq   184(%rsi),%rbp

# qhasm: x3 = t if =
# asm 1: cmove <t=int64#15,<x3=int64#8
# asm 2: cmove <t=%rbp,<x3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 192)
# asm 1: movq   192(<input_1=int64#2),>t=int64#15
# asm 2: movq   192(<input_1=%rsi),>t=%rbp
movq   192(%rsi),%rbp

# qhasm: x4 = t if =
# asm 1: cmove <t=int64#15,<x4=int64#9
# asm 2: cmove <t=%rbp,<x4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 200)
# asm 1: movq   200(<input_1=int64#2),>t=int64#15
# asm 2: movq   200(<input_1=%rsi),>t=%rbp
movq   200(%rsi),%rbp

# qhasm: y0 = t if =
# asm 1: cmove <t=int64#15,<y0=int64#10
# asm 2: cmove <t=%rbp,<y0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 208)
# asm 1: movq   208(<input_1=int64#2),>t=int64#15
# asm 2: movq   208(<input_1=%rsi),>t=%rbp
movq   208(%rsi),%rbp

# qhasm: y1 = t if =
# asm 1: cmove <t=int64#15,<y1=int64#11
# asm 2: cmove <t=%rbp,<y1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 216)
# asm 1: movq   216(<input_1=int64#2),>t=int64#15
# asm 2: movq   216(<input_1=%rsi),>t=%rbp
movq   216(%rsi),%rbp

# qhasm: y2 = t if =
# asm 1: cmove <t=int64#15,<y2=int64#12
# asm 2: cmove <t=%rbp,<y2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 224)
# asm 1: movq   224(<input_1=int64#2),>t=int64#15
# asm 2: movq   224(<input_1=%rsi),>t=%rbp
movq   224(%rsi),%rbp

# qhasm: y3 = t if =
# asm 1: cmove <t=int64#15,<y3=int64#13
# asm 2: cmove <t=%rbp,<y3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 232)
# asm 1: movq   232(<input_1=int64#2),>t=int64#15
# asm 2: movq   232(<input_1=%rsi),>t=%rbp
movq   232(%rsi),%rbp

# qhasm: y4 = t if =
# asm 1: cmove <t=int64#15,<y4=int64#14
# asm 2: cmove <t=%rbp,<y4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 3
# asm 1: cmp  $3,<u=int64#5
# asm 2: cmp  $3,<u=%r8
cmp  $3,%r8

# qhasm: t = *(uint64 *) (input_1 + 320)
# asm 1: movq   320(<input_1=int64#2),>t=int64#15
# asm 2: movq   320(<input_1=%rsi),>t=%rbp
movq   320(%rsi),%rbp

# qhasm: x0 = t if =
# asm 1: cmove <t=int64#15,<x0=int64#4
# asm 2: cmove <t=%rbp,<x0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 328)
# asm 1: movq   328(<input_1=int64#2),>t=int64#15
# asm 2: movq   328(<input_1=%rsi),>t=%rbp
movq   328(%rsi),%rbp

# qhasm: x1 = t if =
# asm 1: cmove <t=int64#15,<x1=int64#6
# asm 2: cmove <t=%rbp,<x1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 336)
# asm 1: movq   336(<input_1=int64#2),>t=int64#15
# asm 2: movq   336(<input_1=%rsi),>t=%rbp
movq   336(%rsi),%rbp

# qhasm: x2 = t if =
# asm 1: cmove <t=int64#15,<x2=int64#7
# asm 2: cmove <t=%rbp,<x2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 344)
# asm 1: movq   344(<input_1=int64#2),>t=int64#15
# asm 2: movq   344(<input_1=%rsi),>t=%rbp
movq   344(%rsi),%rbp

# qhasm: x3 = t if =
# asm 1: cmove <t=int64#15,<x3=int64#8
# asm 2: cmove <t=%rbp,<x3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 352)
# asm 1: movq   352(<input_1=int64#2),>t=int64#15
# asm 2: movq   352(<input_1=%rsi),>t=%rbp
movq   352(%rsi),%rbp

# qhasm: x4 = t if =
# asm 1: cmove <t=int64#15,<x4=int64#9
# asm 2: cmove <t=%rbp,<x4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 360)
# asm 1: movq   360(<input_1=int64#2),>t=int64#15
# asm 2: movq   360(<input_1=%rsi),>t=%rbp
movq   360(%rsi),%rbp

# qhasm: y0 = t if =
# asm 1: cmove <t=int64#15,<y0=int64#10
# asm 2: cmove <t=%rbp,<y0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 368)
# asm 1: movq   368(<input_1=int64#2),>t=int64#15
# asm 2: movq   368(<input_1=%rsi),>t=%rbp
movq   368(%rsi),%rbp

# qhasm: y1 = t if =
# asm 1: cmove <t=int64#15,<y1=int64#11
# asm 2: cmove <t=%rbp,<y1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 376)
# asm 1: movq   376(<input_1=int64#2),>t=int64#15
# asm 2: movq   376(<input_1=%rsi),>t=%rbp
movq   376(%rsi),%rbp

# qhasm: y2 = t if =
# asm 1: cmove <t=int64#15,<y2=int64#12
# asm 2: cmove <t=%rbp,<y2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 384)
# asm 1: movq   384(<input_1=int64#2),>t=int64#15
# asm 2: movq   384(<input_1=%rsi),>t=%rbp
movq   384(%rsi),%rbp

# qhasm: y3 = t if =
# asm 1: cmove <t=int64#15,<y3=int64#13
# asm 2: cmove <t=%rbp,<y3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 392)
# asm 1: movq   392(<input_1=int64#2),>t=int64#15
# asm 2: movq   392(<input_1=%rsi),>t=%rbp
movq   392(%rsi),%rbp

# qhasm: y4 = t if =
# asm 1: cmove <t=int64#15,<y4=int64#14
# asm 2: cmove <t=%rbp,<y4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 4
# asm 1: cmp  $4,<u=int64#5
# asm 2: cmp  $4,<u=%r8
cmp  $4,%r8

# qhasm: t = *(uint64 *) (input_1 + 480)
# asm 1: movq   480(<input_1=int64#2),>t=int64#15
# asm 2: movq   480(<input_1=%rsi),>t=%rbp
movq   480(%rsi),%rbp

# qhasm: x0 = t if =
# asm 1: cmove <t=int64#15,<x0=int64#4
# asm 2: cmove <t=%rbp,<x0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 488)
# asm 1: movq   488(<input_1=int64#2),>t=int64#15
# asm 2: movq   488(<input_1=%rsi),>t=%rbp
movq   488(%rsi),%rbp

# qhasm: x1 = t if =
# asm 1: cmove <t=int64#15,<x1=int64#6
# asm 2: cmove <t=%rbp,<x1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 496)
# asm 1: movq   496(<input_1=int64#2),>t=int64#15
# asm 2: movq   496(<input_1=%rsi),>t=%rbp
movq   496(%rsi),%rbp

# qhasm: x2 = t if =
# asm 1: cmove <t=int64#15,<x2=int64#7
# asm 2: cmove <t=%rbp,<x2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 504)
# asm 1: movq   504(<input_1=int64#2),>t=int64#15
# asm 2: movq   504(<input_1=%rsi),>t=%rbp
movq   504(%rsi),%rbp

# qhasm: x3 = t if =
# asm 1: cmove <t=int64#15,<x3=int64#8
# asm 2: cmove <t=%rbp,<x3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 512)
# asm 1: movq   512(<input_1=int64#2),>t=int64#15
# asm 2: movq   512(<input_1=%rsi),>t=%rbp
movq   512(%rsi),%rbp

# qhasm: x4 = t if =
# asm 1: cmove <t=int64#15,<x4=int64#9
# asm 2: cmove <t=%rbp,<x4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 520)
# asm 1: movq   520(<input_1=int64#2),>t=int64#15
# asm 2: movq   520(<input_1=%rsi),>t=%rbp
movq   520(%rsi),%rbp

# qhasm: y0 = t if =
# asm 1: cmove <t=int64#15,<y0=int64#10
# asm 2: cmove <t=%rbp,<y0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 528)
# asm 1: movq   528(<input_1=int64#2),>t=int64#15
# asm 2: movq   528(<input_1=%rsi),>t=%rbp
movq   528(%rsi),%rbp

# qhasm: y1 = t if =
# asm 1: cmove <t=int64#15,<y1=int64#11
# asm 2: cmove <t=%rbp,<y1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 536)
# asm 1: movq   536(<input_1=int64#2),>t=int64#15
# asm 2: movq   536(<input_1=%rsi),>t=%rbp
movq   536(%rsi),%rbp

# qhasm: y2 = t if =
# asm 1: cmove <t=int64#15,<y2=int64#12
# asm 2: cmove <t=%rbp,<y2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 544)
# asm 1: movq   544(<input_1=int64#2),>t=int64#15
# asm 2: movq   544(<input_1=%rsi),>t=%rbp
movq   544(%rsi),%rbp

# qhasm: y3 = t if =
# asm 1: cmove <t=int64#15,<y3=int64#13
# asm 2: cmove <t=%rbp,<y3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 552)
# asm 1: movq   552(<input_1=int64#2),>t=int64#15
# asm 2: movq   552(<input_1=%rsi),>t=%rbp
movq   552(%rsi),%rbp

# qhasm: y4 = t if =
# asm 1: cmove <t=int64#15,<y4=int64#14
# asm 2: cmove <t=%rbp,<y4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 5
# asm 1: cmp  $5,<u=int64#5
# asm 2: cmp  $5,<u=%r8
cmp  $5,%r8

# qhasm: t = *(uint64 *) (input_1 + 640)
# asm 1: movq   640(<input_1=int64#2),>t=int64#15
# asm 2: movq   640(<input_1=%rsi),>t=%rbp
movq   640(%rsi),%rbp

# qhasm: x0 = t if =
# asm 1: cmove <t=int64#15,<x0=int64#4
# asm 2: cmove <t=%rbp,<x0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 648)
# asm 1: movq   648(<input_1=int64#2),>t=int64#15
# asm 2: movq   648(<input_1=%rsi),>t=%rbp
movq   648(%rsi),%rbp

# qhasm: x1 = t if =
# asm 1: cmove <t=int64#15,<x1=int64#6
# asm 2: cmove <t=%rbp,<x1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 656)
# asm 1: movq   656(<input_1=int64#2),>t=int64#15
# asm 2: movq   656(<input_1=%rsi),>t=%rbp
movq   656(%rsi),%rbp

# qhasm: x2 = t if =
# asm 1: cmove <t=int64#15,<x2=int64#7
# asm 2: cmove <t=%rbp,<x2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 664)
# asm 1: movq   664(<input_1=int64#2),>t=int64#15
# asm 2: movq   664(<input_1=%rsi),>t=%rbp
movq   664(%rsi),%rbp

# qhasm: x3 = t if =
# asm 1: cmove <t=int64#15,<x3=int64#8
# asm 2: cmove <t=%rbp,<x3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 672)
# asm 1: movq   672(<input_1=int64#2),>t=int64#15
# asm 2: movq   672(<input_1=%rsi),>t=%rbp
movq   672(%rsi),%rbp

# qhasm: x4 = t if =
# asm 1: cmove <t=int64#15,<x4=int64#9
# asm 2: cmove <t=%rbp,<x4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 680)
# asm 1: movq   680(<input_1=int64#2),>t=int64#15
# asm 2: movq   680(<input_1=%rsi),>t=%rbp
movq   680(%rsi),%rbp

# qhasm: y0 = t if =
# asm 1: cmove <t=int64#15,<y0=int64#10
# asm 2: cmove <t=%rbp,<y0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 688)
# asm 1: movq   688(<input_1=int64#2),>t=int64#15
# asm 2: movq   688(<input_1=%rsi),>t=%rbp
movq   688(%rsi),%rbp

# qhasm: y1 = t if =
# asm 1: cmove <t=int64#15,<y1=int64#11
# asm 2: cmove <t=%rbp,<y1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 696)
# asm 1: movq   696(<input_1=int64#2),>t=int64#15
# asm 2: movq   696(<input_1=%rsi),>t=%rbp
movq   696(%rsi),%rbp

# qhasm: y2 = t if =
# asm 1: cmove <t=int64#15,<y2=int64#12
# asm 2: cmove <t=%rbp,<y2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 704)
# asm 1: movq   704(<input_1=int64#2),>t=int64#15
# asm 2: movq   704(<input_1=%rsi),>t=%rbp
movq   704(%rsi),%rbp

# qhasm: y3 = t if =
# asm 1: cmove <t=int64#15,<y3=int64#13
# asm 2: cmove <t=%rbp,<y3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 712)
# asm 1: movq   712(<input_1=int64#2),>t=int64#15
# asm 2: movq   712(<input_1=%rsi),>t=%rbp
movq   712(%rsi),%rbp

# qhasm: y4 = t if =
# asm 1: cmove <t=int64#15,<y4=int64#14
# asm 2: cmove <t=%rbp,<y4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 6
# asm 1: cmp  $6,<u=int64#5
# asm 2: cmp  $6,<u=%r8
cmp  $6,%r8

# qhasm: t = *(uint64 *) (input_1 + 800)
# asm 1: movq   800(<input_1=int64#2),>t=int64#15
# asm 2: movq   800(<input_1=%rsi),>t=%rbp
movq   800(%rsi),%rbp

# qhasm: x0 = t if =
# asm 1: cmove <t=int64#15,<x0=int64#4
# asm 2: cmove <t=%rbp,<x0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 808)
# asm 1: movq   808(<input_1=int64#2),>t=int64#15
# asm 2: movq   808(<input_1=%rsi),>t=%rbp
movq   808(%rsi),%rbp

# qhasm: x1 = t if =
# asm 1: cmove <t=int64#15,<x1=int64#6
# asm 2: cmove <t=%rbp,<x1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 816)
# asm 1: movq   816(<input_1=int64#2),>t=int64#15
# asm 2: movq   816(<input_1=%rsi),>t=%rbp
movq   816(%rsi),%rbp

# qhasm: x2 = t if =
# asm 1: cmove <t=int64#15,<x2=int64#7
# asm 2: cmove <t=%rbp,<x2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 824)
# asm 1: movq   824(<input_1=int64#2),>t=int64#15
# asm 2: movq   824(<input_1=%rsi),>t=%rbp
movq   824(%rsi),%rbp

# qhasm: x3 = t if =
# asm 1: cmove <t=int64#15,<x3=int64#8
# asm 2: cmove <t=%rbp,<x3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 832)
# asm 1: movq   832(<input_1=int64#2),>t=int64#15
# asm 2: movq   832(<input_1=%rsi),>t=%rbp
movq   832(%rsi),%rbp

# qhasm: x4 = t if =
# asm 1: cmove <t=int64#15,<x4=int64#9
# asm 2: cmove <t=%rbp,<x4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 840)
# asm 1: movq   840(<input_1=int64#2),>t=int64#15
# asm 2: movq   840(<input_1=%rsi),>t=%rbp
movq   840(%rsi),%rbp

# qhasm: y0 = t if =
# asm 1: cmove <t=int64#15,<y0=int64#10
# asm 2: cmove <t=%rbp,<y0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 848)
# asm 1: movq   848(<input_1=int64#2),>t=int64#15
# asm 2: movq   848(<input_1=%rsi),>t=%rbp
movq   848(%rsi),%rbp

# qhasm: y1 = t if =
# asm 1: cmove <t=int64#15,<y1=int64#11
# asm 2: cmove <t=%rbp,<y1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 856)
# asm 1: movq   856(<input_1=int64#2),>t=int64#15
# asm 2: movq   856(<input_1=%rsi),>t=%rbp
movq   856(%rsi),%rbp

# qhasm: y2 = t if =
# asm 1: cmove <t=int64#15,<y2=int64#12
# asm 2: cmove <t=%rbp,<y2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 864)
# asm 1: movq   864(<input_1=int64#2),>t=int64#15
# asm 2: movq   864(<input_1=%rsi),>t=%rbp
movq   864(%rsi),%rbp

# qhasm: y3 = t if =
# asm 1: cmove <t=int64#15,<y3=int64#13
# asm 2: cmove <t=%rbp,<y3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 872)
# asm 1: movq   872(<input_1=int64#2),>t=int64#15
# asm 2: movq   872(<input_1=%rsi),>t=%rbp
movq   872(%rsi),%rbp

# qhasm: y4 = t if =
# asm 1: cmove <t=int64#15,<y4=int64#14
# asm 2: cmove <t=%rbp,<y4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 7
# asm 1: cmp  $7,<u=int64#5
# asm 2: cmp  $7,<u=%r8
cmp  $7,%r8

# qhasm: t = *(uint64 *) (input_1 + 960)
# asm 1: movq   960(<input_1=int64#2),>t=int64#15
# asm 2: movq   960(<input_1=%rsi),>t=%rbp
movq   960(%rsi),%rbp

# qhasm: x0 = t if =
# asm 1: cmove <t=int64#15,<x0=int64#4
# asm 2: cmove <t=%rbp,<x0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 968)
# asm 1: movq   968(<input_1=int64#2),>t=int64#15
# asm 2: movq   968(<input_1=%rsi),>t=%rbp
movq   968(%rsi),%rbp

# qhasm: x1 = t if =
# asm 1: cmove <t=int64#15,<x1=int64#6
# asm 2: cmove <t=%rbp,<x1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 976)
# asm 1: movq   976(<input_1=int64#2),>t=int64#15
# asm 2: movq   976(<input_1=%rsi),>t=%rbp
movq   976(%rsi),%rbp

# qhasm: x2 = t if =
# asm 1: cmove <t=int64#15,<x2=int64#7
# asm 2: cmove <t=%rbp,<x2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 984)
# asm 1: movq   984(<input_1=int64#2),>t=int64#15
# asm 2: movq   984(<input_1=%rsi),>t=%rbp
movq   984(%rsi),%rbp

# qhasm: x3 = t if =
# asm 1: cmove <t=int64#15,<x3=int64#8
# asm 2: cmove <t=%rbp,<x3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 992)
# asm 1: movq   992(<input_1=int64#2),>t=int64#15
# asm 2: movq   992(<input_1=%rsi),>t=%rbp
movq   992(%rsi),%rbp

# qhasm: x4 = t if =
# asm 1: cmove <t=int64#15,<x4=int64#9
# asm 2: cmove <t=%rbp,<x4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 1000)
# asm 1: movq   1000(<input_1=int64#2),>t=int64#15
# asm 2: movq   1000(<input_1=%rsi),>t=%rbp
movq   1000(%rsi),%rbp

# qhasm: y0 = t if =
# asm 1: cmove <t=int64#15,<y0=int64#10
# asm 2: cmove <t=%rbp,<y0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 1008)
# asm 1: movq   1008(<input_1=int64#2),>t=int64#15
# asm 2: movq   1008(<input_1=%rsi),>t=%rbp
movq   1008(%rsi),%rbp

# qhasm: y1 = t if =
# asm 1: cmove <t=int64#15,<y1=int64#11
# asm 2: cmove <t=%rbp,<y1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 1016)
# asm 1: movq   1016(<input_1=int64#2),>t=int64#15
# asm 2: movq   1016(<input_1=%rsi),>t=%rbp
movq   1016(%rsi),%rbp

# qhasm: y2 = t if =
# asm 1: cmove <t=int64#15,<y2=int64#12
# asm 2: cmove <t=%rbp,<y2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 1024)
# asm 1: movq   1024(<input_1=int64#2),>t=int64#15
# asm 2: movq   1024(<input_1=%rsi),>t=%rbp
movq   1024(%rsi),%rbp

# qhasm: y3 = t if =
# asm 1: cmove <t=int64#15,<y3=int64#13
# asm 2: cmove <t=%rbp,<y3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 1032)
# asm 1: movq   1032(<input_1=int64#2),>t=int64#15
# asm 2: movq   1032(<input_1=%rsi),>t=%rbp
movq   1032(%rsi),%rbp

# qhasm: y4 = t if =
# asm 1: cmove <t=int64#15,<y4=int64#14
# asm 2: cmove <t=%rbp,<y4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 8
# asm 1: cmp  $8,<u=int64#5
# asm 2: cmp  $8,<u=%r8
cmp  $8,%r8

# qhasm: t = *(uint64 *) (input_1 + 1120)
# asm 1: movq   1120(<input_1=int64#2),>t=int64#15
# asm 2: movq   1120(<input_1=%rsi),>t=%rbp
movq   1120(%rsi),%rbp

# qhasm: x0 = t if =
# asm 1: cmove <t=int64#15,<x0=int64#4
# asm 2: cmove <t=%rbp,<x0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 1128)
# asm 1: movq   1128(<input_1=int64#2),>t=int64#15
# asm 2: movq   1128(<input_1=%rsi),>t=%rbp
movq   1128(%rsi),%rbp

# qhasm: x1 = t if =
# asm 1: cmove <t=int64#15,<x1=int64#6
# asm 2: cmove <t=%rbp,<x1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 1136)
# asm 1: movq   1136(<input_1=int64#2),>t=int64#15
# asm 2: movq   1136(<input_1=%rsi),>t=%rbp
movq   1136(%rsi),%rbp

# qhasm: x2 = t if =
# asm 1: cmove <t=int64#15,<x2=int64#7
# asm 2: cmove <t=%rbp,<x2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 1144)
# asm 1: movq   1144(<input_1=int64#2),>t=int64#15
# asm 2: movq   1144(<input_1=%rsi),>t=%rbp
movq   1144(%rsi),%rbp

# qhasm: x3 = t if =
# asm 1: cmove <t=int64#15,<x3=int64#8
# asm 2: cmove <t=%rbp,<x3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 1152)
# asm 1: movq   1152(<input_1=int64#2),>t=int64#15
# asm 2: movq   1152(<input_1=%rsi),>t=%rbp
movq   1152(%rsi),%rbp

# qhasm: x4 = t if =
# asm 1: cmove <t=int64#15,<x4=int64#9
# asm 2: cmove <t=%rbp,<x4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 1160)
# asm 1: movq   1160(<input_1=int64#2),>t=int64#15
# asm 2: movq   1160(<input_1=%rsi),>t=%rbp
movq   1160(%rsi),%rbp

# qhasm: y0 = t if =
# asm 1: cmove <t=int64#15,<y0=int64#10
# asm 2: cmove <t=%rbp,<y0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 1168)
# asm 1: movq   1168(<input_1=int64#2),>t=int64#15
# asm 2: movq   1168(<input_1=%rsi),>t=%rbp
movq   1168(%rsi),%rbp

# qhasm: y1 = t if =
# asm 1: cmove <t=int64#15,<y1=int64#11
# asm 2: cmove <t=%rbp,<y1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 1176)
# asm 1: movq   1176(<input_1=int64#2),>t=int64#15
# asm 2: movq   1176(<input_1=%rsi),>t=%rbp
movq   1176(%rsi),%rbp

# qhasm: y2 = t if =
# asm 1: cmove <t=int64#15,<y2=int64#12
# asm 2: cmove <t=%rbp,<y2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 1184)
# asm 1: movq   1184(<input_1=int64#2),>t=int64#15
# asm 2: movq   1184(<input_1=%rsi),>t=%rbp
movq   1184(%rsi),%rbp

# qhasm: y3 = t if =
# asm 1: cmove <t=int64#15,<y3=int64#13
# asm 2: cmove <t=%rbp,<y3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 1192)
# asm 1: movq   1192(<input_1=int64#2),>t=int64#15
# asm 2: movq   1192(<input_1=%rsi),>t=%rbp
movq   1192(%rsi),%rbp

# qhasm: y4 = t if =
# asm 1: cmove <t=int64#15,<y4=int64#14
# asm 2: cmove <t=%rbp,<y4=%rbx
cmove %rbp,%rbx

# qhasm: mem64[input_0 + 0] = x0
# asm 1: movq   <x0=int64#4,0(<input_0=int64#1)
# asm 2: movq   <x0=%rcx,0(<input_0=%rdi)
movq   %rcx,0(%rdi)

# qhasm: mem64[input_0 + 8] = x1
# asm 1: movq   <x1=int64#6,8(<input_0=int64#1)
# asm 2: movq   <x1=%r9,8(<input_0=%rdi)
movq   %r9,8(%rdi)

# qhasm: mem64[input_0 + 16] = x2
# asm 1: movq   <x2=int64#7,16(<input_0=int64#1)
# asm 2: movq   <x2=%rax,16(<input_0=%rdi)
movq   %rax,16(%rdi)

# qhasm: mem64[input_0 + 24] = x3
# asm 1: movq   <x3=int64#8,24(<input_0=int64#1)
# asm 2: movq   <x3=%r10,24(<input_0=%rdi)
movq   %r10,24(%rdi)

# qhasm: mem64[input_0 + 32] = x4
# asm 1: movq   <x4=int64#9,32(<input_0=int64#1)
# asm 2: movq   <x4=%r11,32(<input_0=%rdi)
movq   %r11,32(%rdi)

# qhasm: mem64[input_0 + 40] = y0
# asm 1: movq   <y0=int64#10,40(<input_0=int64#1)
# asm 2: movq   <y0=%r12,40(<input_0=%rdi)
movq   %r12,40(%rdi)

# qhasm: mem64[input_0 + 48] = y1
# asm 1: movq   <y1=int64#11,48(<input_0=int64#1)
# asm 2: movq   <y1=%r13,48(<input_0=%rdi)
movq   %r13,48(%rdi)

# qhasm: mem64[input_0 + 56] = y2
# asm 1: movq   <y2=int64#12,56(<input_0=int64#1)
# asm 2: movq   <y2=%r14,56(<input_0=%rdi)
movq   %r14,56(%rdi)

# qhasm: mem64[input_0 + 64] = y3
# asm 1: movq   <y3=int64#13,64(<input_0=int64#1)
# asm 2: movq   <y3=%r15,64(<input_0=%rdi)
movq   %r15,64(%rdi)

# qhasm: mem64[input_0 + 72] = y4
# asm 1: movq   <y4=int64#14,72(<input_0=int64#1)
# asm 2: movq   <y4=%rbx,72(<input_0=%rdi)
movq   %rbx,72(%rdi)

# qhasm: z0 = 1
# asm 1: mov  $1,>z0=int64#4
# asm 2: mov  $1,>z0=%rcx
mov  $1,%rcx

# qhasm: z1 = 0
# asm 1: mov  $0,>z1=int64#6
# asm 2: mov  $0,>z1=%r9
mov  $0,%r9

# qhasm: z2 = 0
# asm 1: mov  $0,>z2=int64#7
# asm 2: mov  $0,>z2=%rax
mov  $0,%rax

# qhasm: z3 = 0
# asm 1: mov  $0,>z3=int64#8
# asm 2: mov  $0,>z3=%r10
mov  $0,%r10

# qhasm: z4 = 0
# asm 1: mov  $0,>z4=int64#9
# asm 2: mov  $0,>z4=%r11
mov  $0,%r11

# qhasm: t0 = 0
# asm 1: mov  $0,>t0=int64#10
# asm 2: mov  $0,>t0=%r12
mov  $0,%r12

# qhasm: t1 = 0
# asm 1: mov  $0,>t1=int64#11
# asm 2: mov  $0,>t1=%r13
mov  $0,%r13

# qhasm: t2 = 0
# asm 1: mov  $0,>t2=int64#12
# asm 2: mov  $0,>t2=%r14
mov  $0,%r14

# qhasm: t3 = 0
# asm 1: mov  $0,>t3=int64#13
# asm 2: mov  $0,>t3=%r15
mov  $0,%r15

# qhasm: t4 = 0
# asm 1: mov  $0,>t4=int64#14
# asm 2: mov  $0,>t4=%rbx
mov  $0,%rbx

# qhasm: =? u - 1
# asm 1: cmp  $1,<u=int64#5
# asm 2: cmp  $1,<u=%r8
cmp  $1,%r8

# qhasm: t = *(uint64 *) (input_1 + 80)
# asm 1: movq   80(<input_1=int64#2),>t=int64#15
# asm 2: movq   80(<input_1=%rsi),>t=%rbp
movq   80(%rsi),%rbp

# qhasm: z0 = t if =
# asm 1: cmove <t=int64#15,<z0=int64#4
# asm 2: cmove <t=%rbp,<z0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 88)
# asm 1: movq   88(<input_1=int64#2),>t=int64#15
# asm 2: movq   88(<input_1=%rsi),>t=%rbp
movq   88(%rsi),%rbp

# qhasm: z1 = t if =
# asm 1: cmove <t=int64#15,<z1=int64#6
# asm 2: cmove <t=%rbp,<z1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 96)
# asm 1: movq   96(<input_1=int64#2),>t=int64#15
# asm 2: movq   96(<input_1=%rsi),>t=%rbp
movq   96(%rsi),%rbp

# qhasm: z2 = t if =
# asm 1: cmove <t=int64#15,<z2=int64#7
# asm 2: cmove <t=%rbp,<z2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 104)
# asm 1: movq   104(<input_1=int64#2),>t=int64#15
# asm 2: movq   104(<input_1=%rsi),>t=%rbp
movq   104(%rsi),%rbp

# qhasm: z3 = t if =
# asm 1: cmove <t=int64#15,<z3=int64#8
# asm 2: cmove <t=%rbp,<z3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 112)
# asm 1: movq   112(<input_1=int64#2),>t=int64#15
# asm 2: movq   112(<input_1=%rsi),>t=%rbp
movq   112(%rsi),%rbp

# qhasm: z4 = t if =
# asm 1: cmove <t=int64#15,<z4=int64#9
# asm 2: cmove <t=%rbp,<z4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 120)
# asm 1: movq   120(<input_1=int64#2),>t=int64#15
# asm 2: movq   120(<input_1=%rsi),>t=%rbp
movq   120(%rsi),%rbp

# qhasm: t0 = t if =
# asm 1: cmove <t=int64#15,<t0=int64#10
# asm 2: cmove <t=%rbp,<t0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 128)
# asm 1: movq   128(<input_1=int64#2),>t=int64#15
# asm 2: movq   128(<input_1=%rsi),>t=%rbp
movq   128(%rsi),%rbp

# qhasm: t1 = t if =
# asm 1: cmove <t=int64#15,<t1=int64#11
# asm 2: cmove <t=%rbp,<t1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 136)
# asm 1: movq   136(<input_1=int64#2),>t=int64#15
# asm 2: movq   136(<input_1=%rsi),>t=%rbp
movq   136(%rsi),%rbp

# qhasm: t2 = t if =
# asm 1: cmove <t=int64#15,<t2=int64#12
# asm 2: cmove <t=%rbp,<t2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 144)
# asm 1: movq   144(<input_1=int64#2),>t=int64#15
# asm 2: movq   144(<input_1=%rsi),>t=%rbp
movq   144(%rsi),%rbp

# qhasm: t3 = t if =
# asm 1: cmove <t=int64#15,<t3=int64#13
# asm 2: cmove <t=%rbp,<t3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 152)
# asm 1: movq   152(<input_1=int64#2),>t=int64#15
# asm 2: movq   152(<input_1=%rsi),>t=%rbp
movq   152(%rsi),%rbp

# qhasm: t4 = t if =
# asm 1: cmove <t=int64#15,<t4=int64#14
# asm 2: cmove <t=%rbp,<t4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 2
# asm 1: cmp  $2,<u=int64#5
# asm 2: cmp  $2,<u=%r8
cmp  $2,%r8

# qhasm: t = *(uint64 *) (input_1 + 240)
# asm 1: movq   240(<input_1=int64#2),>t=int64#15
# asm 2: movq   240(<input_1=%rsi),>t=%rbp
movq   240(%rsi),%rbp

# qhasm: z0 = t if =
# asm 1: cmove <t=int64#15,<z0=int64#4
# asm 2: cmove <t=%rbp,<z0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 248)
# asm 1: movq   248(<input_1=int64#2),>t=int64#15
# asm 2: movq   248(<input_1=%rsi),>t=%rbp
movq   248(%rsi),%rbp

# qhasm: z1 = t if =
# asm 1: cmove <t=int64#15,<z1=int64#6
# asm 2: cmove <t=%rbp,<z1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 256)
# asm 1: movq   256(<input_1=int64#2),>t=int64#15
# asm 2: movq   256(<input_1=%rsi),>t=%rbp
movq   256(%rsi),%rbp

# qhasm: z2 = t if =
# asm 1: cmove <t=int64#15,<z2=int64#7
# asm 2: cmove <t=%rbp,<z2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 264)
# asm 1: movq   264(<input_1=int64#2),>t=int64#15
# asm 2: movq   264(<input_1=%rsi),>t=%rbp
movq   264(%rsi),%rbp

# qhasm: z3 = t if =
# asm 1: cmove <t=int64#15,<z3=int64#8
# asm 2: cmove <t=%rbp,<z3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 272)
# asm 1: movq   272(<input_1=int64#2),>t=int64#15
# asm 2: movq   272(<input_1=%rsi),>t=%rbp
movq   272(%rsi),%rbp

# qhasm: z4 = t if =
# asm 1: cmove <t=int64#15,<z4=int64#9
# asm 2: cmove <t=%rbp,<z4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 280)
# asm 1: movq   280(<input_1=int64#2),>t=int64#15
# asm 2: movq   280(<input_1=%rsi),>t=%rbp
movq   280(%rsi),%rbp

# qhasm: t0 = t if =
# asm 1: cmove <t=int64#15,<t0=int64#10
# asm 2: cmove <t=%rbp,<t0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 288)
# asm 1: movq   288(<input_1=int64#2),>t=int64#15
# asm 2: movq   288(<input_1=%rsi),>t=%rbp
movq   288(%rsi),%rbp

# qhasm: t1 = t if =
# asm 1: cmove <t=int64#15,<t1=int64#11
# asm 2: cmove <t=%rbp,<t1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 296)
# asm 1: movq   296(<input_1=int64#2),>t=int64#15
# asm 2: movq   296(<input_1=%rsi),>t=%rbp
movq   296(%rsi),%rbp

# qhasm: t2 = t if =
# asm 1: cmove <t=int64#15,<t2=int64#12
# asm 2: cmove <t=%rbp,<t2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 304)
# asm 1: movq   304(<input_1=int64#2),>t=int64#15
# asm 2: movq   304(<input_1=%rsi),>t=%rbp
movq   304(%rsi),%rbp

# qhasm: t3 = t if =
# asm 1: cmove <t=int64#15,<t3=int64#13
# asm 2: cmove <t=%rbp,<t3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 312)
# asm 1: movq   312(<input_1=int64#2),>t=int64#15
# asm 2: movq   312(<input_1=%rsi),>t=%rbp
movq   312(%rsi),%rbp

# qhasm: t4 = t if =
# asm 1: cmove <t=int64#15,<t4=int64#14
# asm 2: cmove <t=%rbp,<t4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 3
# asm 1: cmp  $3,<u=int64#5
# asm 2: cmp  $3,<u=%r8
cmp  $3,%r8

# qhasm: t = *(uint64 *) (input_1 + 400)
# asm 1: movq   400(<input_1=int64#2),>t=int64#15
# asm 2: movq   400(<input_1=%rsi),>t=%rbp
movq   400(%rsi),%rbp

# qhasm: z0 = t if =
# asm 1: cmove <t=int64#15,<z0=int64#4
# asm 2: cmove <t=%rbp,<z0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 408)
# asm 1: movq   408(<input_1=int64#2),>t=int64#15
# asm 2: movq   408(<input_1=%rsi),>t=%rbp
movq   408(%rsi),%rbp

# qhasm: z1 = t if =
# asm 1: cmove <t=int64#15,<z1=int64#6
# asm 2: cmove <t=%rbp,<z1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 416)
# asm 1: movq   416(<input_1=int64#2),>t=int64#15
# asm 2: movq   416(<input_1=%rsi),>t=%rbp
movq   416(%rsi),%rbp

# qhasm: z2 = t if =
# asm 1: cmove <t=int64#15,<z2=int64#7
# asm 2: cmove <t=%rbp,<z2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 424)
# asm 1: movq   424(<input_1=int64#2),>t=int64#15
# asm 2: movq   424(<input_1=%rsi),>t=%rbp
movq   424(%rsi),%rbp

# qhasm: z3 = t if =
# asm 1: cmove <t=int64#15,<z3=int64#8
# asm 2: cmove <t=%rbp,<z3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 432)
# asm 1: movq   432(<input_1=int64#2),>t=int64#15
# asm 2: movq   432(<input_1=%rsi),>t=%rbp
movq   432(%rsi),%rbp

# qhasm: z4 = t if =
# asm 1: cmove <t=int64#15,<z4=int64#9
# asm 2: cmove <t=%rbp,<z4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 440)
# asm 1: movq   440(<input_1=int64#2),>t=int64#15
# asm 2: movq   440(<input_1=%rsi),>t=%rbp
movq   440(%rsi),%rbp

# qhasm: t0 = t if =
# asm 1: cmove <t=int64#15,<t0=int64#10
# asm 2: cmove <t=%rbp,<t0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 448)
# asm 1: movq   448(<input_1=int64#2),>t=int64#15
# asm 2: movq   448(<input_1=%rsi),>t=%rbp
movq   448(%rsi),%rbp

# qhasm: t1 = t if =
# asm 1: cmove <t=int64#15,<t1=int64#11
# asm 2: cmove <t=%rbp,<t1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 456)
# asm 1: movq   456(<input_1=int64#2),>t=int64#15
# asm 2: movq   456(<input_1=%rsi),>t=%rbp
movq   456(%rsi),%rbp

# qhasm: t2 = t if =
# asm 1: cmove <t=int64#15,<t2=int64#12
# asm 2: cmove <t=%rbp,<t2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 464)
# asm 1: movq   464(<input_1=int64#2),>t=int64#15
# asm 2: movq   464(<input_1=%rsi),>t=%rbp
movq   464(%rsi),%rbp

# qhasm: t3 = t if =
# asm 1: cmove <t=int64#15,<t3=int64#13
# asm 2: cmove <t=%rbp,<t3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 472)
# asm 1: movq   472(<input_1=int64#2),>t=int64#15
# asm 2: movq   472(<input_1=%rsi),>t=%rbp
movq   472(%rsi),%rbp

# qhasm: t4 = t if =
# asm 1: cmove <t=int64#15,<t4=int64#14
# asm 2: cmove <t=%rbp,<t4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 4
# asm 1: cmp  $4,<u=int64#5
# asm 2: cmp  $4,<u=%r8
cmp  $4,%r8

# qhasm: t = *(uint64 *) (input_1 + 560)
# asm 1: movq   560(<input_1=int64#2),>t=int64#15
# asm 2: movq   560(<input_1=%rsi),>t=%rbp
movq   560(%rsi),%rbp

# qhasm: z0 = t if =
# asm 1: cmove <t=int64#15,<z0=int64#4
# asm 2: cmove <t=%rbp,<z0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 568)
# asm 1: movq   568(<input_1=int64#2),>t=int64#15
# asm 2: movq   568(<input_1=%rsi),>t=%rbp
movq   568(%rsi),%rbp

# qhasm: z1 = t if =
# asm 1: cmove <t=int64#15,<z1=int64#6
# asm 2: cmove <t=%rbp,<z1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 576)
# asm 1: movq   576(<input_1=int64#2),>t=int64#15
# asm 2: movq   576(<input_1=%rsi),>t=%rbp
movq   576(%rsi),%rbp

# qhasm: z2 = t if =
# asm 1: cmove <t=int64#15,<z2=int64#7
# asm 2: cmove <t=%rbp,<z2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 584)
# asm 1: movq   584(<input_1=int64#2),>t=int64#15
# asm 2: movq   584(<input_1=%rsi),>t=%rbp
movq   584(%rsi),%rbp

# qhasm: z3 = t if =
# asm 1: cmove <t=int64#15,<z3=int64#8
# asm 2: cmove <t=%rbp,<z3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 592)
# asm 1: movq   592(<input_1=int64#2),>t=int64#15
# asm 2: movq   592(<input_1=%rsi),>t=%rbp
movq   592(%rsi),%rbp

# qhasm: z4 = t if =
# asm 1: cmove <t=int64#15,<z4=int64#9
# asm 2: cmove <t=%rbp,<z4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 600)
# asm 1: movq   600(<input_1=int64#2),>t=int64#15
# asm 2: movq   600(<input_1=%rsi),>t=%rbp
movq   600(%rsi),%rbp

# qhasm: t0 = t if =
# asm 1: cmove <t=int64#15,<t0=int64#10
# asm 2: cmove <t=%rbp,<t0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 608)
# asm 1: movq   608(<input_1=int64#2),>t=int64#15
# asm 2: movq   608(<input_1=%rsi),>t=%rbp
movq   608(%rsi),%rbp

# qhasm: t1 = t if =
# asm 1: cmove <t=int64#15,<t1=int64#11
# asm 2: cmove <t=%rbp,<t1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 616)
# asm 1: movq   616(<input_1=int64#2),>t=int64#15
# asm 2: movq   616(<input_1=%rsi),>t=%rbp
movq   616(%rsi),%rbp

# qhasm: t2 = t if =
# asm 1: cmove <t=int64#15,<t2=int64#12
# asm 2: cmove <t=%rbp,<t2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 624)
# asm 1: movq   624(<input_1=int64#2),>t=int64#15
# asm 2: movq   624(<input_1=%rsi),>t=%rbp
movq   624(%rsi),%rbp

# qhasm: t3 = t if =
# asm 1: cmove <t=int64#15,<t3=int64#13
# asm 2: cmove <t=%rbp,<t3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 632)
# asm 1: movq   632(<input_1=int64#2),>t=int64#15
# asm 2: movq   632(<input_1=%rsi),>t=%rbp
movq   632(%rsi),%rbp

# qhasm: t4 = t if =
# asm 1: cmove <t=int64#15,<t4=int64#14
# asm 2: cmove <t=%rbp,<t4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 5
# asm 1: cmp  $5,<u=int64#5
# asm 2: cmp  $5,<u=%r8
cmp  $5,%r8

# qhasm: t = *(uint64 *) (input_1 + 720)
# asm 1: movq   720(<input_1=int64#2),>t=int64#15
# asm 2: movq   720(<input_1=%rsi),>t=%rbp
movq   720(%rsi),%rbp

# qhasm: z0 = t if =
# asm 1: cmove <t=int64#15,<z0=int64#4
# asm 2: cmove <t=%rbp,<z0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 728)
# asm 1: movq   728(<input_1=int64#2),>t=int64#15
# asm 2: movq   728(<input_1=%rsi),>t=%rbp
movq   728(%rsi),%rbp

# qhasm: z1 = t if =
# asm 1: cmove <t=int64#15,<z1=int64#6
# asm 2: cmove <t=%rbp,<z1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 736)
# asm 1: movq   736(<input_1=int64#2),>t=int64#15
# asm 2: movq   736(<input_1=%rsi),>t=%rbp
movq   736(%rsi),%rbp

# qhasm: z2 = t if =
# asm 1: cmove <t=int64#15,<z2=int64#7
# asm 2: cmove <t=%rbp,<z2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 744)
# asm 1: movq   744(<input_1=int64#2),>t=int64#15
# asm 2: movq   744(<input_1=%rsi),>t=%rbp
movq   744(%rsi),%rbp

# qhasm: z3 = t if =
# asm 1: cmove <t=int64#15,<z3=int64#8
# asm 2: cmove <t=%rbp,<z3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 752)
# asm 1: movq   752(<input_1=int64#2),>t=int64#15
# asm 2: movq   752(<input_1=%rsi),>t=%rbp
movq   752(%rsi),%rbp

# qhasm: z4 = t if =
# asm 1: cmove <t=int64#15,<z4=int64#9
# asm 2: cmove <t=%rbp,<z4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 760)
# asm 1: movq   760(<input_1=int64#2),>t=int64#15
# asm 2: movq   760(<input_1=%rsi),>t=%rbp
movq   760(%rsi),%rbp

# qhasm: t0 = t if =
# asm 1: cmove <t=int64#15,<t0=int64#10
# asm 2: cmove <t=%rbp,<t0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 768)
# asm 1: movq   768(<input_1=int64#2),>t=int64#15
# asm 2: movq   768(<input_1=%rsi),>t=%rbp
movq   768(%rsi),%rbp

# qhasm: t1 = t if =
# asm 1: cmove <t=int64#15,<t1=int64#11
# asm 2: cmove <t=%rbp,<t1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 776)
# asm 1: movq   776(<input_1=int64#2),>t=int64#15
# asm 2: movq   776(<input_1=%rsi),>t=%rbp
movq   776(%rsi),%rbp

# qhasm: t2 = t if =
# asm 1: cmove <t=int64#15,<t2=int64#12
# asm 2: cmove <t=%rbp,<t2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 784)
# asm 1: movq   784(<input_1=int64#2),>t=int64#15
# asm 2: movq   784(<input_1=%rsi),>t=%rbp
movq   784(%rsi),%rbp

# qhasm: t3 = t if =
# asm 1: cmove <t=int64#15,<t3=int64#13
# asm 2: cmove <t=%rbp,<t3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 792)
# asm 1: movq   792(<input_1=int64#2),>t=int64#15
# asm 2: movq   792(<input_1=%rsi),>t=%rbp
movq   792(%rsi),%rbp

# qhasm: t4 = t if =
# asm 1: cmove <t=int64#15,<t4=int64#14
# asm 2: cmove <t=%rbp,<t4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 6
# asm 1: cmp  $6,<u=int64#5
# asm 2: cmp  $6,<u=%r8
cmp  $6,%r8

# qhasm: t = *(uint64 *) (input_1 + 880)
# asm 1: movq   880(<input_1=int64#2),>t=int64#15
# asm 2: movq   880(<input_1=%rsi),>t=%rbp
movq   880(%rsi),%rbp

# qhasm: z0 = t if =
# asm 1: cmove <t=int64#15,<z0=int64#4
# asm 2: cmove <t=%rbp,<z0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 888)
# asm 1: movq   888(<input_1=int64#2),>t=int64#15
# asm 2: movq   888(<input_1=%rsi),>t=%rbp
movq   888(%rsi),%rbp

# qhasm: z1 = t if =
# asm 1: cmove <t=int64#15,<z1=int64#6
# asm 2: cmove <t=%rbp,<z1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 896)
# asm 1: movq   896(<input_1=int64#2),>t=int64#15
# asm 2: movq   896(<input_1=%rsi),>t=%rbp
movq   896(%rsi),%rbp

# qhasm: z2 = t if =
# asm 1: cmove <t=int64#15,<z2=int64#7
# asm 2: cmove <t=%rbp,<z2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 904)
# asm 1: movq   904(<input_1=int64#2),>t=int64#15
# asm 2: movq   904(<input_1=%rsi),>t=%rbp
movq   904(%rsi),%rbp

# qhasm: z3 = t if =
# asm 1: cmove <t=int64#15,<z3=int64#8
# asm 2: cmove <t=%rbp,<z3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 912)
# asm 1: movq   912(<input_1=int64#2),>t=int64#15
# asm 2: movq   912(<input_1=%rsi),>t=%rbp
movq   912(%rsi),%rbp

# qhasm: z4 = t if =
# asm 1: cmove <t=int64#15,<z4=int64#9
# asm 2: cmove <t=%rbp,<z4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 920)
# asm 1: movq   920(<input_1=int64#2),>t=int64#15
# asm 2: movq   920(<input_1=%rsi),>t=%rbp
movq   920(%rsi),%rbp

# qhasm: t0 = t if =
# asm 1: cmove <t=int64#15,<t0=int64#10
# asm 2: cmove <t=%rbp,<t0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 928)
# asm 1: movq   928(<input_1=int64#2),>t=int64#15
# asm 2: movq   928(<input_1=%rsi),>t=%rbp
movq   928(%rsi),%rbp

# qhasm: t1 = t if =
# asm 1: cmove <t=int64#15,<t1=int64#11
# asm 2: cmove <t=%rbp,<t1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 936)
# asm 1: movq   936(<input_1=int64#2),>t=int64#15
# asm 2: movq   936(<input_1=%rsi),>t=%rbp
movq   936(%rsi),%rbp

# qhasm: t2 = t if =
# asm 1: cmove <t=int64#15,<t2=int64#12
# asm 2: cmove <t=%rbp,<t2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 944)
# asm 1: movq   944(<input_1=int64#2),>t=int64#15
# asm 2: movq   944(<input_1=%rsi),>t=%rbp
movq   944(%rsi),%rbp

# qhasm: t3 = t if =
# asm 1: cmove <t=int64#15,<t3=int64#13
# asm 2: cmove <t=%rbp,<t3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 952)
# asm 1: movq   952(<input_1=int64#2),>t=int64#15
# asm 2: movq   952(<input_1=%rsi),>t=%rbp
movq   952(%rsi),%rbp

# qhasm: t4 = t if =
# asm 1: cmove <t=int64#15,<t4=int64#14
# asm 2: cmove <t=%rbp,<t4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 7
# asm 1: cmp  $7,<u=int64#5
# asm 2: cmp  $7,<u=%r8
cmp  $7,%r8

# qhasm: t = *(uint64 *) (input_1 + 1040)
# asm 1: movq   1040(<input_1=int64#2),>t=int64#15
# asm 2: movq   1040(<input_1=%rsi),>t=%rbp
movq   1040(%rsi),%rbp

# qhasm: z0 = t if =
# asm 1: cmove <t=int64#15,<z0=int64#4
# asm 2: cmove <t=%rbp,<z0=%rcx
cmove %rbp,%rcx

# qhasm: t = *(uint64 *) (input_1 + 1048)
# asm 1: movq   1048(<input_1=int64#2),>t=int64#15
# asm 2: movq   1048(<input_1=%rsi),>t=%rbp
movq   1048(%rsi),%rbp

# qhasm: z1 = t if =
# asm 1: cmove <t=int64#15,<z1=int64#6
# asm 2: cmove <t=%rbp,<z1=%r9
cmove %rbp,%r9

# qhasm: t = *(uint64 *) (input_1 + 1056)
# asm 1: movq   1056(<input_1=int64#2),>t=int64#15
# asm 2: movq   1056(<input_1=%rsi),>t=%rbp
movq   1056(%rsi),%rbp

# qhasm: z2 = t if =
# asm 1: cmove <t=int64#15,<z2=int64#7
# asm 2: cmove <t=%rbp,<z2=%rax
cmove %rbp,%rax

# qhasm: t = *(uint64 *) (input_1 + 1064)
# asm 1: movq   1064(<input_1=int64#2),>t=int64#15
# asm 2: movq   1064(<input_1=%rsi),>t=%rbp
movq   1064(%rsi),%rbp

# qhasm: z3 = t if =
# asm 1: cmove <t=int64#15,<z3=int64#8
# asm 2: cmove <t=%rbp,<z3=%r10
cmove %rbp,%r10

# qhasm: t = *(uint64 *) (input_1 + 1072)
# asm 1: movq   1072(<input_1=int64#2),>t=int64#15
# asm 2: movq   1072(<input_1=%rsi),>t=%rbp
movq   1072(%rsi),%rbp

# qhasm: z4 = t if =
# asm 1: cmove <t=int64#15,<z4=int64#9
# asm 2: cmove <t=%rbp,<z4=%r11
cmove %rbp,%r11

# qhasm: t = *(uint64 *) (input_1 + 1080)
# asm 1: movq   1080(<input_1=int64#2),>t=int64#15
# asm 2: movq   1080(<input_1=%rsi),>t=%rbp
movq   1080(%rsi),%rbp

# qhasm: t0 = t if =
# asm 1: cmove <t=int64#15,<t0=int64#10
# asm 2: cmove <t=%rbp,<t0=%r12
cmove %rbp,%r12

# qhasm: t = *(uint64 *) (input_1 + 1088)
# asm 1: movq   1088(<input_1=int64#2),>t=int64#15
# asm 2: movq   1088(<input_1=%rsi),>t=%rbp
movq   1088(%rsi),%rbp

# qhasm: t1 = t if =
# asm 1: cmove <t=int64#15,<t1=int64#11
# asm 2: cmove <t=%rbp,<t1=%r13
cmove %rbp,%r13

# qhasm: t = *(uint64 *) (input_1 + 1096)
# asm 1: movq   1096(<input_1=int64#2),>t=int64#15
# asm 2: movq   1096(<input_1=%rsi),>t=%rbp
movq   1096(%rsi),%rbp

# qhasm: t2 = t if =
# asm 1: cmove <t=int64#15,<t2=int64#12
# asm 2: cmove <t=%rbp,<t2=%r14
cmove %rbp,%r14

# qhasm: t = *(uint64 *) (input_1 + 1104)
# asm 1: movq   1104(<input_1=int64#2),>t=int64#15
# asm 2: movq   1104(<input_1=%rsi),>t=%rbp
movq   1104(%rsi),%rbp

# qhasm: t3 = t if =
# asm 1: cmove <t=int64#15,<t3=int64#13
# asm 2: cmove <t=%rbp,<t3=%r15
cmove %rbp,%r15

# qhasm: t = *(uint64 *) (input_1 + 1112)
# asm 1: movq   1112(<input_1=int64#2),>t=int64#15
# asm 2: movq   1112(<input_1=%rsi),>t=%rbp
movq   1112(%rsi),%rbp

# qhasm: t4 = t if =
# asm 1: cmove <t=int64#15,<t4=int64#14
# asm 2: cmove <t=%rbp,<t4=%rbx
cmove %rbp,%rbx

# qhasm: =? u - 8
# asm 1: cmp  $8,<u=int64#5
# asm 2: cmp  $8,<u=%r8
cmp  $8,%r8

# qhasm: t = *(uint64 *) (input_1 + 1200)
# asm 1: movq   1200(<input_1=int64#2),>t=int64#5
# asm 2: movq   1200(<input_1=%rsi),>t=%r8
movq   1200(%rsi),%r8

# qhasm: z0 = t if =
# asm 1: cmove <t=int64#5,<z0=int64#4
# asm 2: cmove <t=%r8,<z0=%rcx
cmove %r8,%rcx

# qhasm: t = *(uint64 *) (input_1 + 1208)
# asm 1: movq   1208(<input_1=int64#2),>t=int64#5
# asm 2: movq   1208(<input_1=%rsi),>t=%r8
movq   1208(%rsi),%r8

# qhasm: z1 = t if =
# asm 1: cmove <t=int64#5,<z1=int64#6
# asm 2: cmove <t=%r8,<z1=%r9
cmove %r8,%r9

# qhasm: t = *(uint64 *) (input_1 + 1216)
# asm 1: movq   1216(<input_1=int64#2),>t=int64#5
# asm 2: movq   1216(<input_1=%rsi),>t=%r8
movq   1216(%rsi),%r8

# qhasm: z2 = t if =
# asm 1: cmove <t=int64#5,<z2=int64#7
# asm 2: cmove <t=%r8,<z2=%rax
cmove %r8,%rax

# qhasm: t = *(uint64 *) (input_1 + 1224)
# asm 1: movq   1224(<input_1=int64#2),>t=int64#5
# asm 2: movq   1224(<input_1=%rsi),>t=%r8
movq   1224(%rsi),%r8

# qhasm: z3 = t if =
# asm 1: cmove <t=int64#5,<z3=int64#8
# asm 2: cmove <t=%r8,<z3=%r10
cmove %r8,%r10

# qhasm: t = *(uint64 *) (input_1 + 1232)
# asm 1: movq   1232(<input_1=int64#2),>t=int64#5
# asm 2: movq   1232(<input_1=%rsi),>t=%r8
movq   1232(%rsi),%r8

# qhasm: z4 = t if =
# asm 1: cmove <t=int64#5,<z4=int64#9
# asm 2: cmove <t=%r8,<z4=%r11
cmove %r8,%r11

# qhasm: t = *(uint64 *) (input_1 + 1240)
# asm 1: movq   1240(<input_1=int64#2),>t=int64#5
# asm 2: movq   1240(<input_1=%rsi),>t=%r8
movq   1240(%rsi),%r8

# qhasm: t0 = t if =
# asm 1: cmove <t=int64#5,<t0=int64#10
# asm 2: cmove <t=%r8,<t0=%r12
cmove %r8,%r12

# qhasm: t = *(uint64 *) (input_1 + 1248)
# asm 1: movq   1248(<input_1=int64#2),>t=int64#5
# asm 2: movq   1248(<input_1=%rsi),>t=%r8
movq   1248(%rsi),%r8

# qhasm: t1 = t if =
# asm 1: cmove <t=int64#5,<t1=int64#11
# asm 2: cmove <t=%r8,<t1=%r13
cmove %r8,%r13

# qhasm: t = *(uint64 *) (input_1 + 1256)
# asm 1: movq   1256(<input_1=int64#2),>t=int64#5
# asm 2: movq   1256(<input_1=%rsi),>t=%r8
movq   1256(%rsi),%r8

# qhasm: t2 = t if =
# asm 1: cmove <t=int64#5,<t2=int64#12
# asm 2: cmove <t=%r8,<t2=%r14
cmove %r8,%r14

# qhasm: t = *(uint64 *) (input_1 + 1264)
# asm 1: movq   1264(<input_1=int64#2),>t=int64#5
# asm 2: movq   1264(<input_1=%rsi),>t=%r8
movq   1264(%rsi),%r8

# qhasm: t3 = t if =
# asm 1: cmove <t=int64#5,<t3=int64#13
# asm 2: cmove <t=%r8,<t3=%r15
cmove %r8,%r15

# qhasm: t = *(uint64 *) (input_1 + 1272)
# asm 1: movq   1272(<input_1=int64#2),>t=int64#2
# asm 2: movq   1272(<input_1=%rsi),>t=%rsi
movq   1272(%rsi),%rsi

# qhasm: t4 = t if =
# asm 1: cmove <t=int64#2,<t4=int64#14
# asm 2: cmove <t=%rsi,<t4=%rbx
cmove %rsi,%rbx

# qhasm: mem64[input_0 + 80] = z0
# asm 1: movq   <z0=int64#4,80(<input_0=int64#1)
# asm 2: movq   <z0=%rcx,80(<input_0=%rdi)
movq   %rcx,80(%rdi)

# qhasm: mem64[input_0 + 88] = z1
# asm 1: movq   <z1=int64#6,88(<input_0=int64#1)
# asm 2: movq   <z1=%r9,88(<input_0=%rdi)
movq   %r9,88(%rdi)

# qhasm: mem64[input_0 + 96] = z2
# asm 1: movq   <z2=int64#7,96(<input_0=int64#1)
# asm 2: movq   <z2=%rax,96(<input_0=%rdi)
movq   %rax,96(%rdi)

# qhasm: mem64[input_0 + 104] = z3
# asm 1: movq   <z3=int64#8,104(<input_0=int64#1)
# asm 2: movq   <z3=%r10,104(<input_0=%rdi)
movq   %r10,104(%rdi)

# qhasm: mem64[input_0 + 112] = z4
# asm 1: movq   <z4=int64#9,112(<input_0=int64#1)
# asm 2: movq   <z4=%r11,112(<input_0=%rdi)
movq   %r11,112(%rdi)

# qhasm: mem64[input_0 + 120] = t0
# asm 1: movq   <t0=int64#10,120(<input_0=int64#1)
# asm 2: movq   <t0=%r12,120(<input_0=%rdi)
movq   %r12,120(%rdi)

# qhasm: mem64[input_0 + 128] = t1
# asm 1: movq   <t1=int64#11,128(<input_0=int64#1)
# asm 2: movq   <t1=%r13,128(<input_0=%rdi)
movq   %r13,128(%rdi)

# qhasm: mem64[input_0 + 136] = t2
# asm 1: movq   <t2=int64#12,136(<input_0=int64#1)
# asm 2: movq   <t2=%r14,136(<input_0=%rdi)
movq   %r14,136(%rdi)

# qhasm: mem64[input_0 + 144] = t3
# asm 1: movq   <t3=int64#13,144(<input_0=int64#1)
# asm 2: movq   <t3=%r15,144(<input_0=%rdi)
movq   %r15,144(%rdi)

# qhasm: mem64[input_0 + 152] = t4
# asm 1: movq   <t4=int64#14,152(<input_0=int64#1)
# asm 2: movq   <t4=%rbx,152(<input_0=%rdi)
movq   %rbx,152(%rdi)

# qhasm: r0 = mem64[input_0 + 0]
# asm 1: movq   0(<input_0=int64#1),>r0=int64#2
# asm 2: movq   0(<input_0=%rdi),>r0=%rsi
movq   0(%rdi),%rsi

# qhasm: r1 = mem64[input_0 + 8]
# asm 1: movq   8(<input_0=int64#1),>r1=int64#4
# asm 2: movq   8(<input_0=%rdi),>r1=%rcx
movq   8(%rdi),%rcx

# qhasm: r2 = mem64[input_0 + 16]
# asm 1: movq   16(<input_0=int64#1),>r2=int64#5
# asm 2: movq   16(<input_0=%rdi),>r2=%r8
movq   16(%rdi),%r8

# qhasm: r3 = mem64[input_0 + 24]
# asm 1: movq   24(<input_0=int64#1),>r3=int64#6
# asm 2: movq   24(<input_0=%rdi),>r3=%r9
movq   24(%rdi),%r9

# qhasm: r4 = mem64[input_0 + 32]
# asm 1: movq   32(<input_0=int64#1),>r4=int64#7
# asm 2: movq   32(<input_0=%rdi),>r4=%rax
movq   32(%rdi),%rax

# qhasm: s0 = 0xFFFFFFFFFFFDA
# asm 1: mov  $0xFFFFFFFFFFFDA,>s0=int64#8
# asm 2: mov  $0xFFFFFFFFFFFDA,>s0=%r10
mov  $0xFFFFFFFFFFFDA,%r10

# qhasm: s0 -= r0
# asm 1: sub  <r0=int64#2,<s0=int64#8
# asm 2: sub  <r0=%rsi,<s0=%r10
sub  %rsi,%r10

# qhasm: s1 = 0xFFFFFFFFFFFFE
# asm 1: mov  $0xFFFFFFFFFFFFE,>s1=int64#9
# asm 2: mov  $0xFFFFFFFFFFFFE,>s1=%r11
mov  $0xFFFFFFFFFFFFE,%r11

# qhasm: s1 -= r1
# asm 1: sub  <r1=int64#4,<s1=int64#9
# asm 2: sub  <r1=%rcx,<s1=%r11
sub  %rcx,%r11

# qhasm: s2 = 0xFFFFFFFFFFFFE
# asm 1: mov  $0xFFFFFFFFFFFFE,>s2=int64#10
# asm 2: mov  $0xFFFFFFFFFFFFE,>s2=%r12
mov  $0xFFFFFFFFFFFFE,%r12

# qhasm: s2 -= r2
# asm 1: sub  <r2=int64#5,<s2=int64#10
# asm 2: sub  <r2=%r8,<s2=%r12
sub  %r8,%r12

# qhasm: s3 = 0xFFFFFFFFFFFFE
# asm 1: mov  $0xFFFFFFFFFFFFE,>s3=int64#11
# asm 2: mov  $0xFFFFFFFFFFFFE,>s3=%r13
mov  $0xFFFFFFFFFFFFE,%r13

# qhasm: s3 -= r3
# asm 1: sub  <r3=int64#6,<s3=int64#11
# asm 2: sub  <r3=%r9,<s3=%r13
sub  %r9,%r13

# qhasm: s4 = 0xFFFFFFFFFFFFE
# asm 1: mov  $0xFFFFFFFFFFFFE,>s4=int64#12
# asm 2: mov  $0xFFFFFFFFFFFFE,>s4=%r14
mov  $0xFFFFFFFFFFFFE,%r14

# qhasm: s4 -= r4
# asm 1: sub  <r4=int64#7,<s4=int64#12
# asm 2: sub  <r4=%rax,<s4=%r14
sub  %rax,%r14

# qhasm: signed<? b - 0
# asm 1: cmp  $0,<b=int64#3
# asm 2: cmp  $0,<b=%rdx
cmp  $0,%rdx

# qhasm: r0 = s0 if signed<
# asm 1: cmovl <s0=int64#8,<r0=int64#2
# asm 2: cmovl <s0=%r10,<r0=%rsi
cmovl %r10,%rsi

# qhasm: mem64[input_0 + 0] = r0
# asm 1: movq   <r0=int64#2,0(<input_0=int64#1)
# asm 2: movq   <r0=%rsi,0(<input_0=%rdi)
movq   %rsi,0(%rdi)

# qhasm: r1 = s1 if signed<
# asm 1: cmovl <s1=int64#9,<r1=int64#4
# asm 2: cmovl <s1=%r11,<r1=%rcx
cmovl %r11,%rcx

# qhasm: mem64[input_0 + 8] = r1
# asm 1: movq   <r1=int64#4,8(<input_0=int64#1)
# asm 2: movq   <r1=%rcx,8(<input_0=%rdi)
movq   %rcx,8(%rdi)

# qhasm: r2 = s2 if signed<
# asm 1: cmovl <s2=int64#10,<r2=int64#5
# asm 2: cmovl <s2=%r12,<r2=%r8
cmovl %r12,%r8

# qhasm: mem64[input_0 + 16] = r2
# asm 1: movq   <r2=int64#5,16(<input_0=int64#1)
# asm 2: movq   <r2=%r8,16(<input_0=%rdi)
movq   %r8,16(%rdi)

# qhasm: r3 = s3 if signed<
# asm 1: cmovl <s3=int64#11,<r3=int64#6
# asm 2: cmovl <s3=%r13,<r3=%r9
cmovl %r13,%r9

# qhasm: mem64[input_0 + 24] = r3
# asm 1: movq   <r3=int64#6,24(<input_0=int64#1)
# asm 2: movq   <r3=%r9,24(<input_0=%rdi)
movq   %r9,24(%rdi)

# qhasm: r4 = s4 if signed<
# asm 1: cmovl <s4=int64#12,<r4=int64#7
# asm 2: cmovl <s4=%r14,<r4=%rax
cmovl %r14,%rax

# qhasm: mem64[input_0 + 32] = r4
# asm 1: movq   <r4=int64#7,32(<input_0=int64#1)
# asm 2: movq   <r4=%rax,32(<input_0=%rdi)
movq   %rax,32(%rdi)

# qhasm: r0 = mem64[input_0 + 120]
# asm 1: movq   120(<input_0=int64#1),>r0=int64#2
# asm 2: movq   120(<input_0=%rdi),>r0=%rsi
movq   120(%rdi),%rsi

# qhasm: r1 = mem64[input_0 + 128]
# asm 1: movq   128(<input_0=int64#1),>r1=int64#4
# asm 2: movq   128(<input_0=%rdi),>r1=%rcx
movq   128(%rdi),%rcx

# qhasm: r2 = mem64[input_0 + 136]
# asm 1: movq   136(<input_0=int64#1),>r2=int64#5
# asm 2: movq   136(<input_0=%rdi),>r2=%r8
movq   136(%rdi),%r8

# qhasm: r3 = mem64[input_0 + 144]
# asm 1: movq   144(<input_0=int64#1),>r3=int64#6
# asm 2: movq   144(<input_0=%rdi),>r3=%r9
movq   144(%rdi),%r9

# qhasm: r4 = mem64[input_0 + 152]
# asm 1: movq   152(<input_0=int64#1),>r4=int64#7
# asm 2: movq   152(<input_0=%rdi),>r4=%rax
movq   152(%rdi),%rax

# qhasm: s0 = 0xFFFFFFFFFFFDA
# asm 1: mov  $0xFFFFFFFFFFFDA,>s0=int64#8
# asm 2: mov  $0xFFFFFFFFFFFDA,>s0=%r10
mov  $0xFFFFFFFFFFFDA,%r10

# qhasm: s0 -= r0
# asm 1: sub  <r0=int64#2,<s0=int64#8
# asm 2: sub  <r0=%rsi,<s0=%r10
sub  %rsi,%r10

# qhasm: s1 = 0xFFFFFFFFFFFFE
# asm 1: mov  $0xFFFFFFFFFFFFE,>s1=int64#9
# asm 2: mov  $0xFFFFFFFFFFFFE,>s1=%r11
mov  $0xFFFFFFFFFFFFE,%r11

# qhasm: s1 -= r1
# asm 1: sub  <r1=int64#4,<s1=int64#9
# asm 2: sub  <r1=%rcx,<s1=%r11
sub  %rcx,%r11

# qhasm: s2 = 0xFFFFFFFFFFFFE
# asm 1: mov  $0xFFFFFFFFFFFFE,>s2=int64#10
# asm 2: mov  $0xFFFFFFFFFFFFE,>s2=%r12
mov  $0xFFFFFFFFFFFFE,%r12

# qhasm: s2 -= r2
# asm 1: sub  <r2=int64#5,<s2=int64#10
# asm 2: sub  <r2=%r8,<s2=%r12
sub  %r8,%r12

# qhasm: s3 = 0xFFFFFFFFFFFFE
# asm 1: mov  $0xFFFFFFFFFFFFE,>s3=int64#11
# asm 2: mov  $0xFFFFFFFFFFFFE,>s3=%r13
mov  $0xFFFFFFFFFFFFE,%r13

# qhasm: s3 -= r3
# asm 1: sub  <r3=int64#6,<s3=int64#11
# asm 2: sub  <r3=%r9,<s3=%r13
sub  %r9,%r13

# qhasm: s4 = 0xFFFFFFFFFFFFE
# asm 1: mov  $0xFFFFFFFFFFFFE,>s4=int64#12
# asm 2: mov  $0xFFFFFFFFFFFFE,>s4=%r14
mov  $0xFFFFFFFFFFFFE,%r14

# qhasm: s4 -= r4
# asm 1: sub  <r4=int64#7,<s4=int64#12
# asm 2: sub  <r4=%rax,<s4=%r14
sub  %rax,%r14

# qhasm: signed<? b - 0
# asm 1: cmp  $0,<b=int64#3
# asm 2: cmp  $0,<b=%rdx
cmp  $0,%rdx

# qhasm: r0 = s0 if signed<
# asm 1: cmovl <s0=int64#8,<r0=int64#2
# asm 2: cmovl <s0=%r10,<r0=%rsi
cmovl %r10,%rsi

# qhasm: mem64[input_0 + 120] = r0
# asm 1: movq   <r0=int64#2,120(<input_0=int64#1)
# asm 2: movq   <r0=%rsi,120(<input_0=%rdi)
movq   %rsi,120(%rdi)

# qhasm: r1 = s1 if signed<
# asm 1: cmovl <s1=int64#9,<r1=int64#4
# asm 2: cmovl <s1=%r11,<r1=%rcx
cmovl %r11,%rcx

# qhasm: mem64[input_0 + 128] = r1
# asm 1: movq   <r1=int64#4,128(<input_0=int64#1)
# asm 2: movq   <r1=%rcx,128(<input_0=%rdi)
movq   %rcx,128(%rdi)

# qhasm: r2 = s2 if signed<
# asm 1: cmovl <s2=int64#10,<r2=int64#5
# asm 2: cmovl <s2=%r12,<r2=%r8
cmovl %r12,%r8

# qhasm: mem64[input_0 + 136] = r2
# asm 1: movq   <r2=int64#5,136(<input_0=int64#1)
# asm 2: movq   <r2=%r8,136(<input_0=%rdi)
movq   %r8,136(%rdi)

# qhasm: r3 = s3 if signed<
# asm 1: cmovl <s3=int64#11,<r3=int64#6
# asm 2: cmovl <s3=%r13,<r3=%r9
cmovl %r13,%r9

# qhasm: mem64[input_0 + 144] = r3
# asm 1: movq   <r3=int64#6,144(<input_0=int64#1)
# asm 2: movq   <r3=%r9,144(<input_0=%rdi)
movq   %r9,144(%rdi)

# qhasm: r4 = s4 if signed<
# asm 1: cmovl <s4=int64#12,<r4=int64#7
# asm 2: cmovl <s4=%r14,<r4=%rax
cmovl %r14,%rax

# qhasm: mem64[input_0 + 152] = r4
# asm 1: movq   <r4=int64#7,152(<input_0=int64#1)
# asm 2: movq   <r4=%rax,152(<input_0=%rdi)
movq   %rax,152(%rdi)

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
