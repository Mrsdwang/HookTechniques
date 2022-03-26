# HookTech

This projest build for exercising the Hook techniques.all the hook techniques Take user32.dll!MessageBoxA for example

HookTest is exe file for hooking test,
VirtualTableHookTest is exe file for virtual table hooking test.

EATHOOK hooks the EAT of the target DLL in the target process, but it has to hook before the Exe file rebuilds the IAT or it can influence the way that gets the address from EAT of Target DLL after hooking.The target DLL baseaddress should larger than the Detour function Address, otherwise RVA address of the Detour function will caculate wrong.

IATHOOK hooks the IAT of the target Process.

InlineHook series hooks the instructions of target API.

VEHHook registers the Detour Function as VEH and triggers the exception by writing the 0xCC to the beginning of target API.

vfTableHook hooks the C++ virtual table.
