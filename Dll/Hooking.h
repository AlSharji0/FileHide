#ifndef Hooking_h
#define Hooking_h
#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef HANDLE (WINAPI *FindFirstFileA_t)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL(WINAPI* FindNextFileA_t)(HANDLE, LPWIN32_FIND_DATAA);

extern char FileName[];

HANDLE WINAPI HookedFFF(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindData);
BOOL WINAPI HookedFNF(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFileData);
void InstallIATHOOK();

#ifdef __cplusplus
}
#endif

#endif
