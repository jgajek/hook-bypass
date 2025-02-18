#pragma D option quiet

this SIZE_T Size;

syscall::NtAllocateVirtualMemory:entry
/execname == "hookbypass.exe" && (ULONG)arg5 == 0x40/
{
	this->Size = *(PSIZE_T)copyin(arg3, sizeof(PSIZE_T));
	printf("Requested RWX Allocation Size: %d\n", (ULONG)this->Size);
	allocations++;
}

END
{
    	printf("Total NtAllocateVirtualMemory calls with RWX protection: %d\n", allocations);
}
