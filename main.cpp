#include <windows.h>
#include <iostream>
#include "detours.h"

extern "C" NTSTATUS AllocMemSyscall(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

extern "C" NTSTATUS AllocMemIndirect(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
);

static int g_rwxCount = 0;

// Define the NtAllocateVirtualMemory function pointer type
typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// Target pointer for the uninstrumented NtAllocateVirtualMemory API.
static NtAllocateVirtualMemory_t TrueNtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtAllocateVirtualMemory");
static NtAllocateVirtualMemory_t OrigNtAllocateVirtualMemory = TrueNtAllocateVirtualMemory;

// Function to search for the 'syscall; ret' instruction sequence.
PVOID FindSyscallRetSequence(PVOID startAddress)
{
    BYTE* address = static_cast<BYTE*>(startAddress);
    while (true)
    {
        if (address[0] == 0x0F && address[1] == 0x05 && address[2] == 0xC3)
        {
            return address;
        }
        address++;
    }
}

extern "C" PVOID SyscallJumpAddress = FindSyscallRetSequence(OrigNtAllocateVirtualMemory);

// Detour function that replaces the NtAllocateVirtualMemory API.
NTSTATUS WINAPI MyNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
)
{
    if (Protect & PAGE_EXECUTE_READWRITE)
    {
        g_rwxCount++;
    }
    return TrueNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

// Function to hook the NtAllocateVirtualMemory API.
void HookNtAllocateVirtualMemory()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueNtAllocateVirtualMemory, MyNtAllocateVirtualMemory);
    DetourTransactionCommit();
}

// Function to unhook the NtAllocateVirtualMemory API.
void UnhookNtAllocateVirtualMemory()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)TrueNtAllocateVirtualMemory, MyNtAllocateVirtualMemory);
    DetourTransactionCommit();
}

// Function to allocate a chunk of executable memory using VirtualAlloc.
void AllocateExecutableMemoryWithVirtualAlloc()
{
    LPVOID lpAddress = VirtualAlloc(NULL, 1111, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (lpAddress != NULL)
    {
        std::cout << "Allocated 1111 bytes of RWX memory at address " << lpAddress << " using VirtualAlloc()" << std::endl;
    }
    else
    {
        std::cout << "Failed to allocate RWX memory using VirtualAlloc()" << std::endl;
    }
}

// Function to allocate a chunk of executable memory using NtAllocateVirtualMemory.
void AllocateExecutableMemoryWithNtAllocateVirtualMemory()
{
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 2222;
    NTSTATUS status = OrigNtAllocateVirtualMemory(GetCurrentProcess(), &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status == 0)
    {
        std::cout << "Allocated 2222 bytes of RWX memory at address " << baseAddress << " using NtAllocateVirtualMemory()" << std::endl;
    }
    else
    {
        std::cout << "Failed to allocate RWX memory using NtAllocateVirtualMemory(), status: " << status << std::endl;
    }
}

// Function to allocate a chunk of executable memory using direct syscall.
void AllocateExecutableMemoryWithSyscall()
{
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 3333;
    NTSTATUS status = AllocMemSyscall(GetCurrentProcess(), &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status == 0)
    {
        std::cout << "Allocated 3333 bytes of RWX memory at address " << baseAddress << " using direct syscall" << std::endl;
    }
    else
    {
        std::cout << "Failed to allocate RWX memory using direct syscall, status: " << status << std::endl;
    }
}

// Function to allocate a chunk of executable memory using indirect syscall.
void AllocateExecutableMemoryWithIndirect()
{
    PVOID baseAddress = nullptr;
    SIZE_T regionSize = 4444;
    NTSTATUS status = AllocMemIndirect(GetCurrentProcess(), &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status == 0)
    {
        std::cout << "Allocated 4444 bytes of RWX memory at address " << baseAddress << " using indirect syscall" << std::endl;
    }
    else
    {
        std::cout << "Failed to allocate RWX memory using indirect syscall, status: " << status << std::endl;
    }
}

int main()
{
    // Hook the NtAllocateVirtualMemory API.
    HookNtAllocateVirtualMemory();

    // Allocate a chunk of executable memory using VirtualAlloc.
    AllocateExecutableMemoryWithVirtualAlloc();

    // Allocate a chunk of executable memory using NtAllocateVirtualMemory.
    AllocateExecutableMemoryWithNtAllocateVirtualMemory();

    // Allocate a chunk of executable memory using direct syscall.
    AllocateExecutableMemoryWithSyscall();

	// Allocate a chunk of executable memory using indirect syscall.
	AllocateExecutableMemoryWithIndirect();

    // Unhook the NtAllocateVirtualMemory API.
    UnhookNtAllocateVirtualMemory();

    std::cout << "RWX count: " << g_rwxCount << std::endl;
    return 0;
}
