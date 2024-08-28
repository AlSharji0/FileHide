#ifndef Hooking.h
#define Hooking.h
#include <Windows.h>

typedef HANDLE (WINAPI *FindFirstFileA_t)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL(WINAPI* FindNextFileA_t)(HANDLE, LPWIN32_FIND_DATAA);

extern FindFirstFileA_t OriginalFFF;
extern FindNextFileA_t OriginalFNF;
extern char FileName[];

HANDLE WINAPI HookedFFF(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindData);
BOOL WINAPI HookedFNF(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFileData);
void InstallIATHOOK();

#endif // !Hooking.h
