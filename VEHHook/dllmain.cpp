// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

// 修改为你想要HOOK的函数定义
typedef int (WINAPI* PFN_MessageBox)(
    _In_opt_ HWND   hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_     UINT   uType
    );

// 修改为你想要HOOK的函数信息
#define hModToHook "user32.dll"
#define hFuncToHook "MessageBoxA"

PFN_MessageBox g_OriginalMessageBoxA;
PVOID g_AddrofMessageBoxA = 0;
PVOID g_hVector;
BYTE g_OldCode[16] = { 0 };

// 修改为你想要执行的HOOK过程
int WINAPI MyDetour(
    HWND hWnd,          
    LPCSTR lpText,     
    LPCSTR lpCaption,  
    UINT uType          
)
{
    int result;
    result = g_OriginalMessageBoxA(hWnd, "Hooked By VEH", lpCaption, uType);
    return result;

}

ULONG_PTR InitTrampolineFunc()
{
    ULONG_PTR retAddrOfTrampoline=0;
    PBYTE AddrofTrampoline=NULL;
#ifdef  _WIN64
    AddrofTrampoline = (PBYTE)VirtualAlloc(NULL, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    retAddrOfTrampoline = (ULONG_PTR)AddrofTrampoline;

    memset(AddrofTrampoline, 0, 128);
    memcpy(AddrofTrampoline, (PVOID)g_AddrofMessageBoxA, 4);

    AddrofTrampoline += 4;
    AddrofTrampoline[0] = 0xff;
    AddrofTrampoline[1] = 0x25;
    *(ULONG_PTR*)(AddrofTrampoline + 6) = (ULONG_PTR)g_AddrofMessageBoxA + 4;
#else 
    retAddrOfTrampoline = (ULONG_PTR)g_AddrofMessageBoxA + 2;
#endif
    return retAddrOfTrampoline;

}

LONG WINAPI VectoredHandler(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
    //char* szNewText = "VEHHOOKED";
    LONG lresult = EXCEPTION_CONTINUE_SEARCH;
    PEXCEPTION_RECORD pExceptionRecord;
    PCONTEXT pContextRecord;
    int ret = 0;
    pExceptionRecord = ExceptionInfo->ExceptionRecord;
    pContextRecord = ExceptionInfo->ContextRecord;
    if (pExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT
        && pExceptionRecord->ExceptionAddress == g_AddrofMessageBoxA)
    {
        // 这里就是写HOOK后要执行的操作的地方
#ifdef _WIN64
        ULONG_PTR* uRsp = 0;

        // 可以直接更改参数后再次调用trampoline(已经跳过0xCC)
        // 
        //pContextRecord->Rdx = (ULONG_PTR)szNewText;
        //pContextRecord->Rip = (ULONG_PTR)g_OriginalMessageBoxA;
        // 
        // 也可以把Rip改为自己写的Detour,但是要把Rsp对应变化 并在调用Detour后让Rip指向返回地址
        // 刚调用目标函数时，栈顶为调用MessageBox时存的返回地址
        uRsp = (ULONG_PTR*)pContextRecord->Rsp;
        // 调用Mydetour，此时栈顶存的返回地址是返回该VEH异常处理程序的，里面继续执行了MessageBox
        ret = MyDetour((HWND)pContextRecord->Rcx, (LPCSTR)pContextRecord->Rdx, (LPCSTR)pContextRecord->R8, (int)pContextRecord->R9);
        // 手动保持栈平衡，模拟pop，因为将要手动设置异常处理结束后要执行的代码地址，程序就不会自动pop出去。
        pContextRecord->Rsp += sizeof(ULONG_PTR);
        // 将RIP设置为调用MessageBox时存的返回地址
        pContextRecord->Rip = uRsp[0];
#else
        ULONG_PTR* uESP = 0;
        uESP = (ULONG_PTR)pContextRecord->Esp;
        uESP[2] = (ULONG_PTR)szNewText;
        pContextRecord->Eip = (ULONG_PTR)g_OriginalMessageBoxA;
#endif // _WIN64
        lresult = EXCEPTION_CONTINUE_EXECUTION;

    }
    return lresult;
}


BOOL InstallVEH(PVECTORED_EXCEPTION_HANDLER Handler)
{
    g_hVector = AddVectoredExceptionHandler(1, Handler);
    return g_hVector != NULL;
}

VOID UninstallVEH()
{
    RemoveVectoredExceptionHandler(g_hVector);
}


BOOL SetBreakPoint(PVOID pFuncAddr)
{
    DWORD dwOld = 0;
    BYTE* pTarget = (BYTE*)pFuncAddr;
    g_OldCode[0] = *pTarget;
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(pTarget, &mbi, sizeof(mbi));
    VirtualProtectEx(GetCurrentProcess(), mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOld);
    *pTarget = 0xCC;
    VirtualProtectEx(GetCurrentProcess(), mbi.BaseAddress, mbi.RegionSize, dwOld, 0);
    return TRUE;
}

BOOL ClearBreakPoint(PVOID pFuncAddr)
{
    DWORD dwOld = 0;
    BYTE* pTarget = (BYTE*)pFuncAddr;
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(pTarget, &mbi, sizeof(mbi));
    VirtualProtectEx(GetCurrentProcess(), mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOld);
    *pTarget = g_OldCode[0];
    VirtualProtectEx(GetCurrentProcess(), mbi.BaseAddress, mbi.RegionSize, dwOld, 0);
    return TRUE;
}

VOID InstallHook()
{
    HMODULE hMod = LoadLibrary(hModToHook);
    g_AddrofMessageBoxA = (PVOID)GetProcAddress(hMod, hFuncToHook);
    g_OriginalMessageBoxA = (PFN_MessageBox)InitTrampolineFunc();
    InstallVEH(VectoredHandler);
    SetBreakPoint(g_AddrofMessageBoxA);
}

VOID UnInstallHook()
{
    ClearBreakPoint(g_AddrofMessageBoxA);
    UninstallVEH();
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

