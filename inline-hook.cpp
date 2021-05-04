#include "inline-hook.h"

HHANDLE* InlineHook(DWORD hookAddr, HHooker handler, DWORD originLength)
{
	if (originLength < 5) return NULL;
	HHANDLE* hHandle = (HHANDLE*)malloc(sizeof(HHANDLE));
	memset(hHandle, 0, sizeof(HHANDLE));
	hHandle->address = hookAddr;
	hHandle->origin = (BYTE*)malloc(sizeof(BYTE)*originLength);
	hHandle->codeLength = originLength;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	if (hProcess == INVALID_HANDLE_VALUE) {
		OutputDebugString(L"[InlineHook] open process fail.");
		FreeHHandle(hHandle);
		return NULL;
	}
	DWORD jmpAddr = ((DWORD)handler) - (hookAddr + 5);
	BYTE jmpCode[5];
	*(jmpCode + 0) = 0xE8;
	*(DWORD *)(jmpCode + 1) = jmpAddr;


	if (ReadProcessMemory(hProcess, (LPVOID)hookAddr, hHandle->origin, originLength, NULL) == 0) {
		OutputDebugString(L"[InlineHook] read code fail.");
		FreeHHandle(hHandle);
		::CloseHandle(hProcess);
		return NULL;
	}
	if (WriteProcessMemory(hProcess, (LPVOID)hookAddr, jmpCode, 5, NULL) == 0) {
		OutputDebugString(L"[InlineHook] write code fail.");
		FreeHHandle(hHandle);
		::CloseHandle(hProcess);
		return NULL;
	}
	::CloseHandle(hProcess);
	return hHandle;
}

BOOL InlineUnHook(HHANDLE * hHandle)
{

	if (hHandle == NULL) return FALSE;
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, GetCurrentProcessId());
	if (hProcess == INVALID_HANDLE_VALUE) {
		return FALSE;
	}
	if (WriteProcessMemory(hProcess, (LPVOID)hHandle->address, hHandle->origin, hHandle->codeLength, NULL) == 0) {
		::CloseHandle(hProcess);
		return FALSE;
	}
	::CloseHandle(hProcess);

	return TRUE;
}

DWORD GetHookAddressW(const wchar_t * model, DWORD offset)
{
	return (DWORD)GetModuleHandleW(model) + offset;
}
DWORD GetHookAddressA(const char * model, DWORD offset) {
	return (DWORD)GetModuleHandleA(model) + offset;
}
void FreeHHandle(HHANDLE * hHandle)
{
	if (hHandle == NULL) return;
	free(hHandle->origin);
	free(hHandle);
}