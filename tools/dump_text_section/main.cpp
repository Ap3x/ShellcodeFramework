#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>

int main(int argc, char* argv[]) {
	std::cout << "Usage: " << argv[0] << " <input_exe> <output_file>\n" << std::endl;
	const char* inputFile;
	const char* outputFile;

	if (argc == 3) {
		inputFile = argv[1];
		outputFile = argv[2];
	}

	inputFile = ".\\shellcode_gen.dll";
	outputFile = ".\\shellcode_gen.text";

	std::cout << "Using Input File: " << inputFile << std::endl;
	std::cout << "Using Output File: " << outputFile << std::endl;

	// Open the executable file
	HANDLE hFile = CreateFileA(inputFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open input file" << std::endl;
		return 1;
	}

	// Create file mapping
	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapping == NULL) {
		std::cerr << "Failed to create file mapping" << std::endl;
		CloseHandle(hFile);
		return 1;
	}

	// Map the file into memory
	LPVOID lpBaseAddress = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (lpBaseAddress == NULL) {
		std::cerr << "Failed to map view of file" << std::endl;
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return 1;
	}

	// Get DOS header
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Invalid DOS signature" << std::endl;
		UnmapViewOfFile(lpBaseAddress);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return 1;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpBaseAddress + dosHeader->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Invalid NT signature" << std::endl;
		UnmapViewOfFile(lpBaseAddress);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return 1;
	}

	// Find .text section
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	PIMAGE_SECTION_HEADER textSection = NULL;
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		if (strcmp((char*)sectionHeader->Name, ".text") == 0) {
			textSection = sectionHeader;
			break;
		}
		sectionHeader++;
	}

	if (textSection == NULL) {
		std::cerr << "No .text section found" << std::endl;
		UnmapViewOfFile(lpBaseAddress);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return 1;
	}

	// Read .text section
	std::vector<BYTE> textContent(textSection->SizeOfRawData);
	memcpy(textContent.data(), (BYTE*)lpBaseAddress + textSection->PointerToRawData, textSection->SizeOfRawData);

	// Write .text section to output file
	std::ofstream outFile(outputFile, std::ios::binary);
	if (!outFile) {
		std::cerr << "Failed to open output file" << std::endl;
		UnmapViewOfFile(lpBaseAddress);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return 1;
	}
	outFile.write(reinterpret_cast<const char*>(textContent.data()), textContent.size());
	outFile.close();

	std::cout << "The .text section has been dumped to " << outputFile << std::endl;

	// Clean up
	UnmapViewOfFile(lpBaseAddress);
	CloseHandle(hMapping);
	CloseHandle(hFile);

	return 0;
}
