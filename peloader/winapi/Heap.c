#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "Heap.h"

#define HEAP_ZERO_MEMORY 8

STATIC HANDLE WINAPI GetProcessHeap(void)
{
    DebugLog("");
    return (HANDLE)'HEAP';
}

STATIC HANDLE WINAPI HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    DebugLog("%#x, %u, %u", flOptions, dwInitialSize, dwMaximumSize);
    return (HANDLE)'HEAP';
}

PVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    PVOID Buffer;

    // DebugLog("%p, %#x, %u", hHeap, dwFlags, dwBytes);

    if (dwFlags & HEAP_ZERO_MEMORY)
    {
        Buffer = calloc(dwBytes, 1);
    }
    else
    {
        Buffer = malloc(dwBytes);
    }

    return Buffer;
}

BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, PVOID lpMem)
{
    // DebugLog("%p, %#x, %p", hHeap, dwFlags, lpMem);

    free(lpMem);

    return TRUE;
}

STATIC BOOL WINAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress)
{
    DebugLog("%p, %#x, %p", HeapHandle, Flags, BaseAddress);

    free(BaseAddress);

    return TRUE;
}

STATIC SIZE_T WINAPI HeapSize(HANDLE hHeap, DWORD dwFlags, PVOID lpMem)
{
    DebugLog("");
    return malloc_usable_size(lpMem);
}

STATIC PVOID WINAPI HeapReAlloc(HANDLE hHeap, DWORD dwFlags, PVOID lpMem, SIZE_T dwBytes)
{
    DebugLog("");
    return realloc(lpMem, dwBytes);
}

STATIC PVOID WINAPI LocalAlloc(UINT uFlags, SIZE_T uBytes)
{
    PVOID Buffer = malloc(uBytes);
    assert(uFlags == 0);

    DebugLog("%#x, %u => %p", uFlags, uBytes, Buffer);

    return Buffer;
}

STATIC PVOID WINAPI LocalFree(PVOID hMem)
{
    DebugLog("%p", hMem);
    free(hMem);
    return NULL;
}

STATIC PVOID WINAPI RtlCreateHeap(ULONG Flags,
                                  PVOID HeapBase,
                                  SIZE_T ReserveSize,
                                  SIZE_T CommitSize,
                                  PVOID Lock,
                                  PVOID Parameters)
{
    DebugLog("%#x, %p, %#x, %#x, %p, %p",
             Flags,
             HeapBase,
             ReserveSize,
             CommitSize,
             Lock,
             Parameters);

    return (HANDLE)'HEAP';
}

STATIC PVOID WINAPI RtlAllocateHeap(PVOID HeapHandle,
                                    ULONG Flags,
                                    SIZE_T Size)
{
    DebugLog("%p, %#x, %u", HeapHandle, Flags, Size);

    return malloc(Size);
}

STATIC NTSTATUS WINAPI RtlSetHeapInformation(PVOID Heap,
                                             HEAP_INFORMATION_CLASS HeapInformationClass,
                                             PVOID HeapInformation,
                                             SIZE_T HeapInformationLength)
{
    DebugLog("%p, %d", Heap, HeapInformationLength);
    return 0;
}

STATIC PVOID WINAPI GlobalAlloc(UINT uFlags, SIZE_T uBytes)
{
    PVOID Buffer = malloc(uBytes);
    assert(uFlags == 0);

    DebugLog("%#x, %u => %p", uFlags, uBytes, Buffer);

    return Buffer;
}

STATIC PVOID WINAPI GlobalFree(PVOID hMem)
{
    DebugLog("%p", hMem);
    free(hMem);
    return NULL;
}

DECLARE_CRT_EXPORT("HeapCreate", HeapCreate);

DECLARE_CRT_EXPORT("GetProcessHeap", GetProcessHeap);

DECLARE_CRT_EXPORT("HeapAlloc", HeapAlloc);

DECLARE_CRT_EXPORT("HeapFree", HeapFree);

DECLARE_CRT_EXPORT("RtlFreeHeap", RtlFreeHeap);

DECLARE_CRT_EXPORT("RtlSetHeapInformation", RtlSetHeapInformation);

DECLARE_CRT_EXPORT("HeapSize", HeapSize);

DECLARE_CRT_EXPORT("HeapReAlloc", HeapReAlloc);

DECLARE_CRT_EXPORT("LocalAlloc", LocalAlloc);

DECLARE_CRT_EXPORT("LocalFree", LocalFree);

DECLARE_CRT_EXPORT("RtlCreateHeap", RtlCreateHeap);

DECLARE_CRT_EXPORT("RtlAllocateHeap", RtlAllocateHeap);

DECLARE_CRT_EXPORT("GlobalAlloc", GlobalAlloc);

DECLARE_CRT_EXPORT("GlobalFree", GlobalFree);

// Define PMEMORY_BASIC_INFORMATION

typedef struct _MEMORY_BASIC_INFORMATION
{
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

// VirtualQuery

STATIC SIZE_T WINAPI VirtualQuery(void *lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
    DebugLog("");
    return 0;
}

DECLARE_CRT_EXPORT("VirtualQuery", VirtualQuery);

// HeapDestroy

STATIC BOOL WINAPI HeapDestroy(HANDLE hHeap)
{
    DebugLog("");
    return TRUE;
}

DECLARE_CRT_EXPORT("HeapDestroy", HeapDestroy);

// Sleep

STATIC VOID WINAPI Sleep(DWORD dwMilliseconds)
{
    DebugLog("%u", dwMilliseconds);
}

DECLARE_CRT_EXPORT("Sleep", Sleep);

// OpenThread

STATIC HANDLE WINAPI OpenThread(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
{
    DebugLog("%#x, %d, %u", dwDesiredAccess, bInheritHandle, dwThreadId);
    return (HANDLE)'THRD';
}

DECLARE_CRT_EXPORT("OpenThread", OpenThread);

// SuspendThread

STATIC DWORD WINAPI SuspendThread(HANDLE hThread)
{
    DebugLog("%p", hThread);
    return 0;
}

DECLARE_CRT_EXPORT("SuspendThread", SuspendThread);

// ResumeThread

STATIC DWORD WINAPI ResumeThread(HANDLE hThread)
{
    DebugLog("%p", hThread);
    return 0;
}

DECLARE_CRT_EXPORT("ResumeThread", ResumeThread);

// GetThreadContext

STATIC BOOL WINAPI GetThreadContext(HANDLE hThread, CONTEXT lpContext)
{
    DebugLog("%p, %p", hThread, lpContext);
    return TRUE;
}

DECLARE_CRT_EXPORT("GetThreadContext", GetThreadContext);

// SetThreadContext

STATIC BOOL WINAPI SetThreadContext(HANDLE hThread, const CONTEXT *lpContext)
{
    DebugLog("%p, %p", hThread, lpContext);
    return TRUE;
}

DECLARE_CRT_EXPORT("SetThreadContext", SetThreadContext);

// FlushInstructionCache

STATIC BOOL WINAPI FlushInstructionCache(HANDLE hProcess, void *lpBaseAddress, SIZE_T dwSize)
{
    DebugLog("%p, %p, %u", hProcess, lpBaseAddress, dwSize);
    return TRUE;
}

DECLARE_CRT_EXPORT("FlushInstructionCache", FlushInstructionCache);

// CreateToolhelp32Snapshot

STATIC HANDLE WINAPI CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
    DebugLog("%#x, %u", dwFlags, th32ProcessID);
    return (HANDLE)'TH32S';
}

DECLARE_CRT_EXPORT("CreateToolhelp32Snapshot", CreateToolhelp32Snapshot);

// Thread32First

typedef struct tagTHREADENTRY32
{
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ThreadID;
    DWORD th32OwnerProcessID;
    LONG tpBasePri;
    LONG tpDeltaPri;
    DWORD dwFlags;
} THREADENTRY32, *PTHREADENTRY32, *LPTHREADENTRY32;

STATIC BOOL WINAPI Thread32First(HANDLE hSnapshot, LPTHREADENTRY32 lpte)
{
    DebugLog("%p, %p", hSnapshot, lpte);
    return FALSE;
}

DECLARE_CRT_EXPORT("Thread32First", Thread32First);

// Thread32Next

STATIC BOOL WINAPI Thread32Next(HANDLE hSnapshot, LPTHREADENTRY32 lpte)
{
    DebugLog("%p, %p", hSnapshot, lpte);
    return FALSE;
}

DECLARE_CRT_EXPORT("Thread32Next", Thread32Next);

// RtlLookupFunctionEntry

STATIC PRUNTIME_FUNCTION WINAPI RtlLookupFunctionEntry(ULONG64 ControlPc, PULONG64 ImageBase, PUNWIND_HISTORY_TABLE HistoryTable)
{
    DebugLog("%llu, %p, %p", ControlPc, ImageBase, HistoryTable);
    return NULL;
}

DECLARE_CRT_EXPORT("RtlLookupFunctionEntry", RtlLookupFunctionEntry);

// RtlVirtualUnwind

STATIC NTSTATUS WINAPI RtlVirtualUnwind(ULONG HandlerType,
                                        ULONG64 ImageBase,
                                        ULONG64 ControlPc,
                                        PRUNTIME_FUNCTION FunctionEntry,
                                        PCONTEXT ContextRecord,
                                        PVOID *HandlerData,
                                        PULONG64 EstablisherFrame,
                                        PKNONVOLATILE_CONTEXT_POINTERS ContextPointers)
{
    DebugLog("%u, %llu, %llu, %p, %p, %p, %p, %p", HandlerType, ImageBase, ControlPc, FunctionEntry, ContextRecord, HandlerData, EstablisherFrame, ContextPointers);
    return 0;
}

DECLARE_CRT_EXPORT("RtlVirtualUnwind", RtlVirtualUnwind);

// UnhandledExceptionFilter

STATIC LONG WINAPI UnhandledExceptionFilter(struct EXCEPTION_POINTERS *ExceptionInfo)
{
    DebugLog("%p", ExceptionInfo);
    return 0;
}

DECLARE_CRT_EXPORT("UnhandledExceptionFilter", UnhandledExceptionFilter);

// SetUnhandledExceptionFilter

typedef LONG(WINAPI *LPTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *ExceptionInfo);

STATIC LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)
{
    DebugLog("%p", lpTopLevelExceptionFilter);
    return NULL;
}

DECLARE_CRT_EXPORT("SetUnhandledExceptionFilter", SetUnhandledExceptionFilter);

// TherminateProcess

STATIC BOOL WINAPI TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
    DebugLog("%p, %u", hProcess, uExitCode);
    return TRUE;
}

DECLARE_CRT_EXPORT("TerminateProcess", TerminateProcess);

// DisableThreadLibraryCalls

STATIC BOOL WINAPI DisableThreadLibraryCalls(HMODULE hLibModule)
{
    DebugLog("%p", hLibModule);
    return TRUE;
}

DECLARE_CRT_EXPORT("DisableThreadLibraryCalls", DisableThreadLibraryCalls);

// RtlCaptureContext

STATIC VOID WINAPI RtlCaptureContext(PCONTEXT ContextRecord)
{
    DebugLog("%p", ContextRecord);
}

DECLARE_CRT_EXPORT("RtlCaptureContext", RtlCaptureContext);

// ConnectNamedPipe

typedef struct _OVERLAPPED
{
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union
    {
        struct
        {
            DWORD Offset;
            DWORD OffsetHigh;
        };
        PVOID Pointer;
    };
    HANDLE hEvent;
} OVERLAPPED, *LPOVERLAPPED;

typedef struct _STARTUPINFOA
{
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION
{
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef struct _SECURITY_ATTRIBUTES
{
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

STATIC BOOL WINAPI ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped)
{
    DebugLog("%p, %p", hNamedPipe, lpOverlapped);
    return TRUE;
}

DECLARE_CRT_EXPORT("ConnectNamedPipe", ConnectNamedPipe);

// CreateNamedPipeA

STATIC HANDLE WINAPI CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
{
    DebugLog("%s, %#x, %#x, %u, %u, %u, %u, %p", lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize, nDefaultTimeOut, lpSecurityAttributes);
    return (HANDLE)'PIPE';
}

DECLARE_CRT_EXPORT("CreateNamedPipeA", CreateNamedPipeA);

// CreateProcessA

STATIC BOOL WINAPI CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    DebugLog("%s, %s, %p, %p, %d, %#x, %p, %s, %p, %p", lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
    return TRUE;
}

DECLARE_CRT_EXPORT("CreateProcessA", CreateProcessA);
