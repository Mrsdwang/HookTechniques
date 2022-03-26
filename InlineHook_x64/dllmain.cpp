// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

//定义如下结构，保存一次InlineHook所需要的信息
typedef struct _HOOK_DATA {
    char szApiName[128];	//待Hook的API名字
    char szModuleName[64];	//待Hook的API所属模块的名字
    int  HookCodeLen;		//Hook长度
    BYTE oldEntry[16];		//保存Hook位置的原始指令
    BYTE newEntry[16];		//保存要写入Hook位置的新指令
    ULONG_PTR HookPoint;		//待HOOK的位置
    ULONG_PTR JmpBackAddr;		//回跳到原函数中的位置
    ULONG_PTR pfnTrampolineFun;	//调用原始函数的通道
    ULONG_PTR pfnDetourFun;		//HOOK过滤函数
}HOOK_DATA, * PHOOK_DATA;

HOOK_DATA HookData;


// 修改为你想要HOOK的函数定义
#define hModToHook "user32.dll"
#define hFuncToHook "MessageBoxA"

//修改为你想要HOOK的函数定义
typedef int
(WINAPI* PFN_MessageBoxA)(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType
    );

//修改为你想要执行HOOK的过程
int WINAPI MyDetour(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType
)
{
    int ret;
    PFN_MessageBoxA OriginalMessageBox = (PFN_MessageBoxA)HookData.pfnTrampolineFun;
    ret = OriginalMessageBox(hWnd, "Hook by Inline 0x14 bytes", lpCaption, uType);
    return ret;
}

LPVOID GetAddress(LPCSTR DllName, LPCSTR ApiName)
{
    HMODULE hMod;
    if (hMod = GetModuleHandle(DllName))
        return GetProcAddress(hMod, ApiName);
    else
    {
       hMod =  LoadLibraryA(DllName);
       return GetProcAddress(hMod, ApiName);
    }
}

ULONG_PTR SkipJmpAddress(ULONG_PTR uAddress)
{
    ULONG_PTR TrueAddrss = 0;
    PBYTE pFn = (PBYTE)uAddress;
    if (memcmp(pFn, "\xFF\x25", 2) == 0)
    {
        TrueAddrss = *(ULONG_PTR*)(pFn + 2);
        return TrueAddrss;
    }
    if (pFn[0] == 0xE9)
    {
        TrueAddrss = (ULONG_PTR)pFn + *(ULONG_PTR*)(pFn + 1) + 5;
        return TrueAddrss;
    }
    if (pFn[0] == 0xEB)
    {
        TrueAddrss = (ULONG_PTR)pFn + pFn[1] + 2;
        return TrueAddrss;
    }
    return (ULONG_PTR)uAddress;
}

VOID InitHookEntry(PHOOK_DATA pHookData)
{
    if (pHookData == NULL
        || pHookData->pfnDetourFun == NULL
        || pHookData->HookPoint == NULL)
        return;
   
    memset(pHookData->newEntry, 0, 14);
    pHookData->newEntry[0] = 0xFF;
    pHookData->newEntry[1] = 0x25;
    *(ULONG_PTR*)(pHookData->newEntry + 6) = (ULONG_PTR)pHookData->pfnDetourFun;
}

VOID InitTrampoline(PHOOK_DATA pHookData)
{
    PBYTE pFun = (PBYTE)pHookData->pfnTrampolineFun;
    memcpy(pFun, (PVOID)pHookData->HookPoint, 14);
    //该方法思路为 求出原目的地址，然后减去转移后的新地址和指令长度
    // 该思路没问题，但64位系统中，计算的相对地址结果可能为8字节，如果强行转化成4字节就会丢失数据，导致目的地址计算错误
    /*ULONG DataOffset;
    // 计算原目的地址
    ULONG_PTR pData = (ULONG_PTR)pHookData->HookPoint + 7 + 7 + *(ULONG*)(pHookData->HookPoint + 10);
    // 计算相对地址 = 目的地址-当前地址-指令长度
    DataOffset = (ULONG)(pData - ((ULONG_PTR)pFun + 14));

    *(ULONG*)(pFun + 10) = DataOffset;*/

    // 计算原目的地址
    ULONG_PTR pData = (ULONG_PTR)pHookData->HookPoint + 7 + 7 + *(ULONG*)(pHookData->HookPoint + 10);
    // 获取原目的地址的值并写入空闲空间
    *(ULONG*)((ULONG_PTR)pFun + 30) = *(ULONG*)pData;
    // 将重定位的目的地址计算出的相对地址写入cmp指令
    *(ULONG*)(pFun + 10) = (ULONG)(((ULONG_PTR)pFun + 30) - ((ULONG_PTR)pFun + 14));

    pFun += 14;
    pFun[0] = 0xff;
    pFun[1] = 0x25;
    *(ULONG_PTR*)(pFun + 6) = pHookData->JmpBackAddr;

}

BOOL InstallCodeHook(PHOOK_DATA pHookData)
{
    SIZE_T dwBytesReturned = 0;
    HANDLE hProcess = GetCurrentProcess();
    BOOL bResult = FALSE;
    if (pHookData == NULL
        || pHookData->HookPoint == 0
        || pHookData->pfnDetourFun == NULL
        || pHookData->pfnTrampolineFun == NULL)
        return FALSE;

    pHookData->HookPoint = SkipJmpAddress(pHookData->HookPoint);
    pHookData->JmpBackAddr = pHookData->HookPoint + pHookData->HookCodeLen;
    LPVOID OriginalAddr = (LPVOID)pHookData->HookPoint;
    InitHookEntry(pHookData);
    InitTrampoline(pHookData);
    if (ReadProcessMemory(hProcess, OriginalAddr, pHookData->oldEntry, pHookData->HookCodeLen, &dwBytesReturned))
    {
        if (WriteProcessMemory(hProcess, OriginalAddr, pHookData->newEntry, pHookData->HookCodeLen, &dwBytesReturned))

        {
            bResult = TRUE;
        }
    }
    return bResult;
}

BOOL InstallHook()
{
    ZeroMemory(&HookData, sizeof(HOOK_DATA));
    strcpy_s(HookData.szModuleName, hModToHook);
    strcpy_s(HookData.szApiName, hFuncToHook);
    HookData.HookCodeLen = 14;
    HookData.HookPoint = (ULONG_PTR)GetAddress(HookData.szModuleName, HookData.szApiName);
    HookData.pfnTrampolineFun = (ULONG_PTR)VirtualAlloc(NULL, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    HookData.pfnDetourFun = (ULONG_PTR)MyDetour;
    return InstallCodeHook(&HookData);

}


BOOL UnInstallCodeHook(PHOOK_DATA pHookData)
{
    SIZE_T dwBytesReturned = 0;
    HANDLE hProcess = GetCurrentProcess();
    BOOL bResult = FALSE;
    LPVOID OrigianlAddr;
    if (pHookData == NULL
        || pHookData->HookPoint == 0
        || pHookData->oldEntry == 0)
        return FALSE;
    OrigianlAddr = (LPVOID)pHookData->HookPoint;
    bResult = WriteProcessMemory(hProcess, OrigianlAddr, pHookData->oldEntry, pHookData->HookCodeLen, &dwBytesReturned);
    return bResult;
}

BOOL UnInstallHook()
{
    return UnInstallCodeHook(&HookData);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InstallHook();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        UnInstallHook();
        break;
    }
    return TRUE;
}

