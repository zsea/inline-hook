#pragma once
#include <Windows.h>
#ifdef UNICODE
#define GetHookAddress GetHookAddressW
#else
#define GetHookAddress GetHookAddressA
#endif // UNICODE

struct HHANDLE {
	DWORD address;
	BYTE* origin;
	DWORD codeLength;
};
typedef void(*HHooker)();
HHANDLE* InlineHook(DWORD hookAddr, HHooker handler, DWORD originLength = 5);
BOOL InlineUnHook(HHANDLE* hHandle);
DWORD GetHookAddressW(const wchar_t * model, DWORD offset);
DWORD GetHookAddressA(const char * model, DWORD offset);
void FreeHHandle(HHANDLE *hHandle);