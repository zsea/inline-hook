windows上的inline hook库
# 示例
```c++
	DWORD hookAddress = GetHookAddress(L".dll", 0x27F570);
	HHANDLE *hHandle= InlineHook(hookAddress, HookUnReadMessage, 5);
	if (hHandle != NULL) {
		OutputDebugString(L"DLL Hook 成功！");
		InlineUnHook(hHandle);
		OutputDebugString(L"hHandle 已取消！");
		FreeHHandle(hHandle);
		hHandle = NULL;
		OutputDebugString(L"hHandle 已释放！");
	}
	else {
		OutputDebugString(L"DLL Hook 失败！");
	}
```

# API 列表
* typedef void(*HHooker)();
* HHANDLE* InlineHook(DWORD hookAddr, HHooker * handler, DWORD originLength = 5);
* BOOL InlineUnHook(HHANDLE* hHandle);
* DWORD GetHookAddressW(const wchar_t * model, DWORD offset);
* DWORD GetHookAddressA(const char * model, DWORD offset);
* void FreeHHandle(HHANDLE *hHandle);