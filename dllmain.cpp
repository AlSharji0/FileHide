#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include "Hooking.h"

extern "C" BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		InstallIATHOOK();
		break;
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
