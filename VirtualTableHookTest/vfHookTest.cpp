#include <iostream>
#include <Windows.h>
using namespace std;

class MyTest
{
public:
	virtual int Add(int a, int b);
	virtual void g() { cout << "test::g" << endl; };
	virtual void h() { cout << "test::h" << endl; };
	void novirtual() { cout << "test::not virtual" << endl; };

};

int MyTest::Add(int a, int b)
{
	printf("Test::Add\n");
	return a + b;
}

int main()
{
	MyTest test;
	MyTest* ptest = &test;

	ptest->Add(1, 2);
	ULONG_PTR vfTable = *(ULONG_PTR*)ptest;
	printf("%I64x", vfTable);
	getchar();
	ptest->Add(1, 2);
	printf("OK");
	getchar();
	return 0;
}