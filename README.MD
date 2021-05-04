windows上的inline hook库
# 示例
```c++
__declspec(naked) void HookUnReadMessage() {
	__asm {
		call unCall
		pushad
		push eax
		call SaveUnReadMessage
		add esp, 0x4
		popad
		retn
	}
}
int main(){
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
}    
```

# API 列表
* typedef void(*HHooker)();
* HHANDLE* InlineHook(DWORD hookAddr, HHooker * handler, DWORD originLength = 5);
* BOOL InlineUnHook(HHANDLE* hHandle);
* DWORD GetHookAddressW(const wchar_t * model, DWORD offset);
* DWORD GetHookAddressA(const char * model, DWORD offset);
* void FreeHHandle(HHANDLE *hHandle);

# 注意

* HHooker回调方法需要是一个裸函数，且需要在最后使用```retn```进行返回。