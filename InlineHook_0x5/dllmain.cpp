// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

BOOL Hook();
BOOL UnHook();
typedef struct _HOOK_DATA {
    // 需要HOOK的API名称
    char szHookApiName[128];
    // 被HOOK的API所在DLL名称
    char szApiDllName[64];
    // HOOK 长度
    int HookCodeLen = 5;
    // HOOK 前的代码
    BYTE oldCode[5];
    // HOOK 后的代码
    BYTE newCode[5] = {0xE9,0,};
    // HOOK的地址
    ULONG_PTR HookAddr;
    ULONG_PTR pfnDetourFun;
}HOOK_DATA;

HOOK_DATA HookData;

// 修改为你想要HOOK的函数信息
#define hModToHook "user32.dll"
#define hFuncToHook "MessageBoxA"


// 修改为需要HOOK的函数的定义
typedef int (WINAPI* pMessageBoxA)(
    _In_opt_ HWND   hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_     UINT   uType
    );
// 修改为你想要程序执行的代码
int WINAPI MyDetourFunc(
    _In_opt_ HWND   hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_     UINT   uType
)
{
    FARPROC pFunc;
    UnHook();
    pFunc = GetProcAddress(GetModuleHandleA(HookData.szApiDllName), HookData.szHookApiName);
    WinExec("C:\\Windows\\System32\\calc.exe", SW_SHOW);
    char newText[1024] = { 0 };
    char newCaption[256] = "HookTool";

    lstrcpy(newText, lpText);
    lstrcat(newText, "\n\t0x5 InlineHook Success!");
    uType |= MB_ICONERROR;
    int ret = ((pMessageBoxA)pFunc)(
        hWnd,
        newText,
        newCaption,
        uType);
    Hook();
    return ret;
}


VOID InitHookData()
{
    strcpy_s(HookData.szApiDllName, hModToHook);
    strcpy_s(HookData.szHookApiName, hFuncToHook);
    HookData.pfnDetourFun = (ULONG_PTR)MyDetourFunc;
    return VOID();
}

BOOL Hook()
{
	PBYTE pByte;
	HANDLE hProcess;
	HookData.HookAddr = (ULONG_PTR)GetProcAddress(GetModuleHandleA(HookData.szApiDllName), HookData.szHookApiName);
	pByte = (PBYTE)HookData.HookAddr;
	if (HookData.HookAddr == NULL)
		return FALSE;
	if (pByte[0] == 0xE9)
		return FALSE;
	hProcess = GetCurrentProcess();
	ReadProcessMemory(hProcess, (LPCVOID)HookData.HookAddr, HookData.oldCode, HookData.HookCodeLen, 0);
	* (ULONG*)(HookData.newCode + 1) = (ULONG)HookData.pfnDetourFun - (ULONG)HookData.HookAddr - 5;
	WriteProcessMemory(hProcess, (LPVOID)HookData.HookAddr, HookData.newCode, HookData.HookCodeLen, 0);
	return TRUE;
}

BOOL UnHook()
{
	if (HookData.HookAddr != NULL)
	{
		PBYTE pByte = (PBYTE)HookData.HookAddr;
		if (pByte[0] == 0xE9)
		{
			WriteProcessMemory(GetCurrentProcess(), (LPVOID)HookData.HookAddr, HookData.oldCode, HookData.HookCodeLen, 0);
			return TRUE;
		}
		return FALSE;
	}
	return FALSE;
}




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InitHookData();
        Hook();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        UnHook();
        break;
    }
    return TRUE;
}

