// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

// 修改为你需要的HOOK函数的定义
typedef int
(WINAPI* PFN_MessageBoxA)(
    _In_opt_ HWND   hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_     UINT   uType
    );

// 修改为你需要HOOK的函数信息
#define hModToHook "user32.dll"
#define hFuncToHook "MessageBoxA"

ULONG_PTR g_pOrgFunc = NULL;
PULONG_PTR g_pToEATThunk = NULL;
HMODULE g_hModule;

// 修改为你想要程序去执行的代码
int WINAPI MyDetourFunc(
    _In_opt_ HWND   hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_     UINT   uType
)
{
    int ret;
    WinExec("C:\\Windows\\System32\\calc.exe", SW_SHOW);
    ret = ((PFN_MessageBoxA)g_pOrgFunc)(
        hWnd,
        "HOOK",
        lpCaption,
        uType);
    return ret;
}



BOOL hook_eat(LPCSTR szDllName,LPCSTR szFuncName, ULONG_PTR pfnNew)
{
    PIMAGE_EXPORT_DIRECTORY pExportDir;
    DWORD dwOldProtect;
    PBYTE uiBaseAddr;
    PBYTE uiNtHeader;
    PULONG FuncAddr;
    HANDLE hProcess;
    hProcess = GetCurrentProcess();
    uiBaseAddr = (PBYTE)g_hModule;
    uiNtHeader = uiBaseAddr + ((PIMAGE_DOS_HEADER)uiBaseAddr)->e_lfanew;
    pExportDir = (PIMAGE_EXPORT_DIRECTORY)(uiBaseAddr + ((PIMAGE_NT_HEADERS)uiNtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    FuncAddr = (PULONG)(uiBaseAddr + pExportDir->AddressOfFunctions);
    while (*FuncAddr)
    {
        
        if (*FuncAddr == g_pOrgFunc)
        {
            printf("%x == %I64x\n", *FuncAddr, g_pOrgFunc);
            MEMORY_BASIC_INFORMATION mbi;
            VirtualQuery(FuncAddr, &mbi, sizeof(mbi));
            VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
            g_pToEATThunk = (PULONG_PTR)FuncAddr;
            *FuncAddr = (ULONG)((ULONG_PTR)pfnNew - (ULONG_PTR)g_hModule) ;
            printf("实际Detour地址:%I64x - DLL基址:%I64x = 四字DetourRVA:%I64x -> 双字DetourRVA:%x\n",  (ULONG_PTR)pfnNew, (ULONG_PTR)g_hModule, (ULONG_PTR)pfnNew - (ULONG_PTR)g_hModule,*FuncAddr);
            printf("DetourRVA:%x + DLL基址:%I64x = 计算出的Detour地址:%I64x\n", *FuncAddr, (ULONG_PTR)pfnNew, (ULONG_PTR)(*FuncAddr +(ULONG_PTR)g_hModule));
            VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, dwOldProtect, &dwOldProtect);
            return TRUE;
            
        }
        else
        FuncAddr++;
    }
        return FALSE;
}

VOID unhook_eat()
{
    DWORD dwOldProcetect;
    MEMORY_BASIC_INFORMATION mbi;
    HANDLE hProcess = GetCurrentProcess();
    if (g_pToEATThunk)
    {
        VirtualQuery((LPCVOID)g_pToEATThunk, &mbi, sizeof(mbi));
        VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProcetect);
        *g_pToEATThunk = (ULONG)g_pOrgFunc;
        VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, dwOldProcetect, &dwOldProcetect);
    }
}

// IAT在程序加载过程就完成，在程序运行时更改DLL的导出表没有意义
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_hModule = GetModuleHandle(hModToHook);
        g_pOrgFunc = (ULONG_PTR)GetProcAddress(g_hModule, hFuncToHook);
        g_pOrgFunc = (ULONG)(g_pOrgFunc - (ULONG_PTR)g_hModule);
        hook_eat( hModToHook,hFuncToHook ,(ULONG_PTR)MyDetourFunc);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        printf("EXIT2");
        unhook_eat();
        break;
    }
    return TRUE;
}

