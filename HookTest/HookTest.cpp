#include <Windows.h>
#include <stdio.h>


int main()
{
	
	system("pause");
	char Text[128];
	char LpCation[64];
	strcpy_s(Text, "Test");
	strcpy_s(LpCation, "HookTest");
	MessageBoxA(NULL, Text, LpCation, MB_OK);

	return 0;
}