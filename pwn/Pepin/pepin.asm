bits 64
global _start

_start:
	mov rax, 333
	syscall

	xchg rax, rdi
	mov rax, 60
	syscall