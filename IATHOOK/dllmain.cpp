// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
// 此处修改为需要HOOK的函数定义
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

FARPROC g_pOrgFunc = NULL;
PULONG_PTR g_pToIATThunk = NULL;

// 在此修改为你需要执行的代码
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
        lpText,
        lpCaption,
        uType);
    return ret;
}



BOOL hook_iat(LPCSTR szDllName, FARPROC pfnOrg, PROC pfnNew)
{
    HMODULE ExeBaseAddr;
    LPCSTR szLibName;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
    PIMAGE_THUNK_DATA pThunk;
    DWORD dwOldProtect;
    PBYTE uiBaseAddr;
    PBYTE uiNtHeader;
    PULONG_PTR lpAddr;
    HANDLE hProcess;

    hProcess = GetCurrentProcess();
    ExeBaseAddr = GetModuleHandle(NULL);
    uiBaseAddr = (PBYTE)ExeBaseAddr;
    uiNtHeader = uiBaseAddr + ((PIMAGE_DOS_HEADER)uiBaseAddr)->e_lfanew;
    pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(uiBaseAddr + ((PIMAGE_NT_HEADERS)uiNtHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDescriptor->Characteristics && pImportDescriptor->FirstThunk != NULL)
    {
        szLibName = (LPCSTR)(uiBaseAddr + pImportDescriptor->Name);
        if (!_strcmpi(szLibName, szDllName))
        {
            pThunk = (PIMAGE_THUNK_DATA)(uiBaseAddr + pImportDescriptor->FirstThunk);
            printf("%I64x\n", pThunk);
            for (; pThunk->u1.Function; pThunk++)
            {
                lpAddr = (ULONG_PTR*)pThunk;
                if ((*lpAddr) == (ULONG_PTR)pfnOrg)
                {
                    MEMORY_BASIC_INFORMATION mbi;
                    VirtualQuery(lpAddr, &mbi, sizeof(mbi));
                    VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                    g_pToIATThunk = lpAddr;
                    *lpAddr = (ULONG_PTR)pfnNew;
                    VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, dwOldProtect, &dwOldProtect);
                    return TRUE;
                }
            }
        }
        else
            pImportDescriptor++;
    }
    return FALSE;

}

VOID unhook_iat()
{
    DWORD dwOldProcetect;
    MEMORY_BASIC_INFORMATION mbi;
    HANDLE hProcess = GetCurrentProcess();
    if (g_pToIATThunk)
    {
        VirtualQuery((LPCVOID)g_pToIATThunk, &mbi, sizeof(mbi));
        VirtualProtectEx(hProcess, mbi.BaseAddress,mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOldProcetect);
        *g_pToIATThunk = (ULONG_PTR)g_pOrgFunc;
        VirtualProtectEx(hProcess, mbi.BaseAddress, mbi.RegionSize, dwOldProcetect, &dwOldProcetect);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        g_pOrgFunc = (FARPROC)GetProcAddress(GetModuleHandle(hModToHook), hFuncToHook);
        hook_iat(hModToHook, g_pOrgFunc, (PROC)MyDetourFunc);
        PFN_MessageBoxA test = (PFN_MessageBoxA)GetProcAddress(GetModuleHandle(hModToHook), hFuncToHook);
        test(
            NULL,
            "EATHOOK SUCCESS",
            "HOOKTOOL",
            MB_OK);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        unhook_iat();
        break;
    }
    return TRUE;
}

