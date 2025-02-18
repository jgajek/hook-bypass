.data
EXTERN SyscallJumpAddress:QWORD

.code 
	AllocMemSyscall PROC
		mov r10, rcx
		mov eax, 18h ; NtAllocateVirtualMemory syscall number
		syscall
		ret
	AllocMemSyscall ENDP

	AllocMemIndirect PROC
		mov r10, rcx
		mov eax, 18h ; NtAllocateVirtualMemory syscall number
		jmp SyscallJumpAddress
	AllocMemIndirect ENDP
end