#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

std::string get_function_start_address(const std::string& line) {
	std::istringstream iss(line);
	std::string part;

	// Get section and offset
	if (std::getline(iss, part, ':')) {
		std::getline(iss, part, ' ');
	}

	return part;
}

int main(int argc, char* argv[]) {
	std::cout << "Usage: " << argv[0] << " <map_file> <function_name> <dumped_section_file>" << std::endl;
	
	std::string mapFilePath;
	std::string targetFunction;
	std::string dumpedSectionFilePath;
	
	if (argc == 4) {
		mapFilePath = argv[1];
		targetFunction = argv[2];
		dumpedSectionFilePath = argv[3];
	}
	
	mapFilePath = "shellcode_gen.map";
	targetFunction = "_code";
	dumpedSectionFilePath = "shellcode_gen.text";

	std::cout << "Using Map File: " << mapFilePath << std::endl;
	std::cout << "Using Function Name: " << targetFunction << std::endl;
	std::cout << "Using Dump Text File: " << dumpedSectionFilePath << std::endl;


	targetFunction = targetFunction + " ";

	std::ifstream mapFile(mapFilePath);
	if (!mapFile.is_open()) {
		std::cerr << "Failed to open map file: " << mapFilePath << std::endl;
		return 1;
	}

	unsigned long long baseAddress;
	std::string line;

	// Find base address
	while (std::getline(mapFile, line)) {
		if (line.find("Preferred load address is") != std::string::npos) {
			std::string hex_string = line.substr(line.find_last_of(' ') + 1);
			baseAddress = std::stoull(hex_string, nullptr, 16);
			break;
		}
	}

	// Reset file pointer to beginning
	mapFile.clear();
	mapFile.seekg(0, std::ios::beg);

	std::string strOffset;

	while (std::getline(mapFile, line)) {
		if (strstr(line.c_str(), targetFunction.c_str())) {
			strOffset = get_function_start_address(line);
		}
	}
	mapFile.close();

	auto offset = stoul(strOffset, 0, 16);

	std::ifstream dumpFile(dumpedSectionFilePath, std::ios::binary | std::ios::ate);

	if (!dumpFile) {
		std::cerr << "Unable to open file: " << dumpedSectionFilePath << std::endl;
		return 1;
	}

	int size = dumpFile.tellg();
	std::cout << "#define FUNCTION_OFFSET " << "0x" << std::hex << offset << std::endl;;
	std::cout << "unsigned char _code_raw[" << std::dec << size << "] = { " << std::endl;;

	char byte;
	int count = 0;
	dumpFile.seekg(0, std::ios::beg);
	while (dumpFile.get(byte)) {
		if (size-1 == count) {
			std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex
				<< static_cast<int>(static_cast<unsigned char>(byte)) << " ";
		}
		else {
			std::cout << "0x" << std::setw(2) << std::setfill('0') << std::hex
				<< static_cast<int>(static_cast<unsigned char>(byte)) << ", ";
		}


		if (++count % 16 == 0) {
			std::cout << std::endl;
		}

	}

	if (count % 16 != 0) {
		std::cout << std::endl;
	}

	std::cout << "};";

	dumpFile.close();

	return 0;
}
