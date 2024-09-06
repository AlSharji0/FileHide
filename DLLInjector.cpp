#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include "pch.h"
#include "Hooking.h"

bool DLLInject(DWORD processID, const char* dllPath) {

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (hProcess == NULL) {
		printf("Failed to open target process. Error: %d\n", GetLastError());
		return FALSE;
	}
}
