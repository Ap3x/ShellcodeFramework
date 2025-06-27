#include <Windows.h>
#include "shellcodex64.h"
#include "shellcodex86.h"

using namespace std;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef int(*_code_t)(const wchar_t* dllPath, PULONG DLLChar, PUNICODE_STRING dllName);

int main()
{
	HANDLE moduleHandle;
	DWORD old_flag;
	VirtualProtect(_code_raw, sizeof _code_raw, PAGE_EXECUTE_READWRITE, &old_flag);

	_code_t fn_code = (_code_t)(void*)&_code_raw[FUNCTION_OFFSET];
#ifdef _WIN64
	const wchar_t* dllPath = L"C:\\Test";
	UNICODE_STRING moduleName; 
	WCHAR dllName[] = L"Testx64.dll\0";
	moduleName.Length = wcslen(dllName) * sizeof(WCHAR);
	moduleName.MaximumLength = (wcslen(dllName) + 1) * sizeof(WCHAR);
	moduleName.Buffer = dllName;
#else
	const wchar_t* dllPath = L"C:\\Test";
	UNICODE_STRING moduleName;
	WCHAR dllName[] = L"TestDLLx86.dll";
	moduleName.Length = wcslen(dllName) * sizeof(WCHAR);
	moduleName.MaximumLength = (wcslen(dllName) + 1) * sizeof(WCHAR);
	moduleName.Buffer = dllName;
#endif
	printf("Result of function : %d\n", fn_code(dllPath, NULL, &moduleName));
	return EXIT_SUCCESS;
}