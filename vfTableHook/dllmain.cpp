// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
using namespace std;

// 修改为想要执行的HOOK 过程
class DetourClass
{
public:
    virtual int DetourFun(int a, int b);
};

class TrampolineClass
{
public:
    virtual int TrampolineFunc(int a, int b)
    {
        printf("TrampolineFun");
        return a + b;
    }
};

DetourClass Detour;
TrampolineClass Trampoline;

int DetourClass::DetourFun(int a, int b)
{
    MessageBoxA(NULL, "Hook", "HookTest", MB_OK);
    TrampolineClass* pTrampoline = new TrampolineClass;
    int ret = pTrampoline->TrampolineFunc(a, b);
    delete pTrampoline;
    return ret;
}

LPVOID GetClassVirtualFnAddress(LPVOID pthis, int Index)
{
    ULONG_PTR* vfTable = (ULONG_PTR*)*(ULONG_PTR*)pthis;
    return (LPVOID)vfTable[Index];
}

void VirtualTableHook(PULONG_PTR pvfTableToHook)
{

    DWORD dwOld;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR* vfTableTrampoline = (ULONG_PTR*)*(ULONG_PTR*)&Trampoline;

    VirtualQuery(vfTableTrampoline, &mbi, sizeof(mbi));
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOld);
    vfTableTrampoline[0] = pvfTableToHook[0];
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, dwOld, 0);

    VirtualQuery(pvfTableToHook, &mbi, sizeof(mbi));
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOld);
    pvfTableToHook[0] = (ULONG_PTR)GetClassVirtualFnAddress(&Detour, 0);
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, dwOld, 0);

}


void VirtualTableUnHook(PULONG_PTR pvfTableToHook)
{
    DWORD dwOld;
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR* vfTableTrampoline = (ULONG_PTR*)*(ULONG_PTR*)&Trampoline;
    ULONG_PTR OrigAddr;


    VirtualQuery(vfTableTrampoline, &mbi, sizeof(mbi));
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOld);
    OrigAddr = vfTableTrampoline[0];
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, dwOld, 0);

    VirtualQuery(pvfTableToHook, &mbi, sizeof(mbi));
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &dwOld);
    pvfTableToHook[0] = OrigAddr;
    VirtualProtect(mbi.BaseAddress, mbi.RegionSize, dwOld, 0);
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    // 需要先获得目标进程中要HOOK的虚表地址，然后修改为虚表地址
    PULONG_PTR vfTableAddrToHook = (PULONG_PTR)0x7ff7673f3300;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        VirtualTableHook(vfTableAddrToHook);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        VirtualTableUnHook(vfTableAddrToHook);
        break;
    }
    return TRUE;
}

