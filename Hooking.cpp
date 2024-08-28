#include "hooking.h"
#include <stdio.h>

FindFirstFileA_t OriginalFFF = NULL;
FindNextFileA_t OriginalFNF = NULL;
char FileName[] = "hidded.txt";

extern "C" {
	HANDLE WINAPI HookedFFF(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindData) {
		HANDLE hFind = OriginalFFF(lpFileName, lpFindData);

		if (hFind != INVALID_HANDLE_VALUE && strcmp(lpFindData->cFileName, FileName) == 0) FindNextFileA(hFind, lpFindData);

		return hFind;
	}

	BOOL WINAPI HookedFNF(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFileData) {
		BOOL result;
		
		while ((result = OriginalFNF(hFindFile, lpFileData)) == TRUE) {
			if (strcmp(lpFileData->cFileName, FileName) != 0) return result;
		}

		return result;
	}

	void InstallIATHOOK() {
		HMODULE hModule = GetModuleHandle(NULL);



	}

}