// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

typedef struct _HOOK_DATA {
    // 需要HOOK的API名称
    char szHookApiName[128];
    // 被HOOK的API所在DLL名称
    char szApiDllName[64];
    // HOOK 长度
    int HookCodeLen[2] = { 5,2 };
    // HOOK后第一个jmp
    BYTE newJmp1[2] = { 0xEB,0xF9 };
    // HOOK后第二个jmp
    BYTE newJmp2[5] = { 0xE9,0, };
    // HOOK前的Code
    BYTE OldCode1[5] = { 0x90,0x90,0x90,0x90,0x90 };
    BYTE OldCode2[2] = { 0x8B,0xFF };
    // HOOK的地址
    ULONG_PTR HookAddr;
    // HOOK后要去执行的函数
    ULONG_PTR pfnDetourFun;
}HOOK_DATA;

HOOK_DATA HookData;

// 修改为你想要HOOK的函数定义
typedef int (WINAPI* pMessageBoxA)(
    _In_opt_ HWND   hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_     UINT   uType
    );


// 修改为你想要HOOK的函数定义
#define hModToHook "user32.dll"
#define hFuncToHook "MessageBoxA"


// 修改为你想要执行的HOOK过程
int WINAPI MyDetourFunc(
    _In_opt_ HWND   hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_     UINT   uType
)
{
    FARPROC pFunc;
    pFunc = GetProcAddress(GetModuleHandleA(HookData.szApiDllName), HookData.szHookApiName);
    WinExec("C:\\Windows\\System32\\calc.exe", SW_SHOW);


    pFunc = (FARPROC)((ULONG_PTR)pFunc + 2);
    int ret = ((pMessageBoxA)pFunc)(
        hWnd,
        lpText,
        lpCaption,
        uType);
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
    if (pByte[0] == 0xEB)
        return FALSE;
    hProcess = GetCurrentProcess();
    *(ULONG_PTR*)(HookData.newJmp2 + 1) = HookData.pfnDetourFun - HookData.HookAddr;
    WriteProcessMemory(hProcess, (LPVOID)(HookData.HookAddr - 5), HookData.newJmp2, HookData.HookCodeLen[0], 0);
    WriteProcessMemory(hProcess, (LPVOID)HookData.HookAddr, HookData.newJmp1, HookData.HookCodeLen[1], 0);
    return TRUE;
}

BOOL UnHook()
{
    if (HookData.HookAddr != NULL)
    {
        PBYTE pByte = (PBYTE)HookData.HookAddr;
        if (pByte[0] == 0xEB)
        {
            WriteProcessMemory(GetCurrentProcess(), (LPVOID)(HookData.HookAddr - 5), HookData.OldCode1, HookData.HookCodeLen[0], 0);
            WriteProcessMemory(GetCurrentProcess(), (LPVOID)HookData.HookAddr, HookData.OldCode2, HookData.HookCodeLen[1], 0);
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}




BOOL APIENTRY DllMain(HMODULE hModule,
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

