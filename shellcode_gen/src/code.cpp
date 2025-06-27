#include "structs.h"
#define RAND_NUM 4562 

#pragma comment(linker, "/merge:.rdata=.text")

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef NTSTATUS(WINAPI* LDRLOADDLL)(PCWSTR, PULONG, PUNICODE_STRING, PVOID*);

constexpr DWORD get_hash_from_string(CONST CHAR* string) {
	DWORD hash = 0;
	CHAR ch = 0;

	while (*string) {
		ch = *string;
		if (ch >= 0x61 && ch <= 0x7A) {
			ch = *string - 0x20;
		}
		hash += (hash * RAND_NUM + ch) & 0xffffff;
		string++;
}
	return hash;
}

VOID* get_proc_address(DWORD module_hash, DWORD function_hash, CHAR* module_name) {
#ifdef _WIN64
	_PEB* peb = (_PEB*)__readgsqword(0x60);
#else
	_PEB* peb = (_PEB*)__readfsdword(0x30);
#endif
	bool again = false;

	// Get the head of list
	PLIST_ENTRY list_head = &peb->pLdr->InMemoryOrderModuleList;
	PLIST_ENTRY list_current = list_head;

	// Start looping through the double linked list
	while ((list_current = list_current->Flink) != list_head) {
		PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list_current, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList);

		// Get all pointers setup
		BYTE* base_address = (BYTE*)entry->DllBase;
		IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)base_address;
		IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(base_address + dos_header->e_lfanew);

		IMAGE_DATA_DIRECTORY* data_directory = &nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*)(base_address + data_directory->VirtualAddress);

		// Skips the module if it doesn't have exports. Our own executeable is always loaded first so this is needed to skip it
		if (data_directory->VirtualAddress == NULL)
			continue;

		// Check if the module is the one we are looking for
		if (get_hash_from_string((CHAR*)(base_address + export_directory->Name)) != module_hash) {
			continue;
		}

		// Get table of name addresses
		DWORD* name_rvas = (DWORD*)(base_address + export_directory->AddressOfNames);

		// Loop through all of the names and hash them and compare for the function we want
		for (DWORD i = 0; i < export_directory->NumberOfNames; ++i) {
			if (function_hash == get_hash_from_string((CHAR*)(base_address + name_rvas[i]))) {
				WORD ordinal = ((WORD*)(base_address + export_directory->AddressOfNameOrdinals))[i];
				DWORD function_rva = ((DWORD*)(base_address + export_directory->AddressOfFunctions))[ordinal];
				return base_address + function_rva;
			}
		}
	}
}

extern "C" bool _code(const wchar_t* dllPath, PULONG dllCharacteristics, PUNICODE_STRING dllName)
{
	//CHAR kernel32Arr[] = { 'k','e','r','n','e','l','3','2','.','d','l','l','\0' };
	CHAR ntdllArr[] = { 'n','t','d','l','l','.','d','l','l','\0' };
	DWORD module_hash = get_hash_from_string(ntdllArr);
	//CHAR LoadLibraryAArr[] = { 'L','o','a','d','L','i','b','r','a','r','y','A','\0' };
	CHAR LdrLoadDllArr[] = { 'L','d','r','L','o','a','d','D','l','l','\0' };
	DWORD func_hash = get_hash_from_string(LdrLoadDllArr);
	PVOID pLdrLoadDll = get_proc_address(module_hash, func_hash, "LdrLoadDll");
	HANDLE dllHandle = NULL;
	(LONG)((LDRLOADDLL)pLdrLoadDll)(dllPath, dllCharacteristics, dllName, &dllHandle);
	return true;
}