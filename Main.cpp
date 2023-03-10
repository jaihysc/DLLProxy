#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstdint>

#include <Windows.h>
#include <Commdlg.h>
#include <String.h>
#include <winnt.h>
#include <imagehlp.h>
#include <fstream>
#include <tchar.h>
#include <stdio.h>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Imagehlp.lib")

#pragma region File Templates
// It searches for text of the format: /* DLLPROXY: <key> */ and replaces it with the appropriate strings
	const auto* cppFileTemplate = R"(
#include <Windows.h>
#include <PathCch.h>
#include <xmmintrin.h>

#pragma comment(lib, "pathcch.lib")

#include <mutex>
#include <iostream>
#include <fstream>
#include <iomanip>

static void Alert(const char* msg) {
	MessageBoxA(NULL, msg, "/* DLLPROXY: DllName */ proxy", 0);
}

static void Alert(const wchar_t* msg) {
	MessageBoxW(NULL, msg, L"/* DLLPROXY: DllName */ proxy", 0);
}

extern "C" {
	HMODULE originalDll;
	FARPROC originalDllExports[/* DLLPROXY: DllNumExports */];
	const char* originalDllExportsName[] = {
/* DLLPROXY: DllExportsName */
	};
}
enum class DllExport : uint32_t {
/* DLLPROXY: DllExportEnum */
};

class Dll
{
public:
	Dll() {
		logFile.open("/* DLLPROXY: DllName */.log", std::ofstream::out);
	}
	~Dll() {
		logFile.close();
	}

	std::ofstream& LogFile() {
		if (logFile.bad()) Alert("Failed to write to file");
		return logFile;
	}

	std::mutex& Mutex() { return mutex; }

private:
	std::ofstream logFile;
	std::mutex mutex;
} *dll = nullptr;

bool Init() {
	// Search for original dll in the same directory as the proxy dll
	HMODULE thisDll;
	if (!GetModuleHandleExW(
		GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCWSTR)&Init,
		&thisDll)) {
		Alert("Failed to get handle to this dll");
		return false;
	}
	wchar_t thisDllPath[MAX_PATH];
	if (!GetModuleFileNameW(thisDll, thisDllPath, MAX_PATH)) {
		Alert("Failed to get path to this dll");
		return false;
	}
	if (PathCchRemoveFileSpec(thisDllPath, MAX_PATH) != S_OK) {
		Alert("Failed to get directory to this dll");
		return false;
	}
	wcscat_s(thisDllPath, MAX_PATH, L"\\/* DLLPROXY: DllName */_original.dll");
	if ((originalDll = LoadLibraryW(thisDllPath)) == NULL) {
		Alert("Failed to load original dll");
		return false;
	}

	for (int i = 0; i < /* DLLPROXY: DllNumExports */; ++i) {
		originalDllExports[i] = GetProcAddress(originalDll, originalDllExportsName[i]);
	}

	try {
		dll = new Dll();
	}
	catch (std::exception& e) {
		Alert(e.what());
		return false;
	}

	return true;
}

// If you are able to identify a function which de-inits the original dll,
// and exits without any further calls to the original dll,
// you can call Deinit. Otherwise we let the OS cleanup
void Deinit() {
	FreeLibrary(originalDll);
	delete dll;
}

#pragma region Injected Functions
/* DLLPROXY: DllInjectedFunctions */
#pragma endregion

// Struct holding arguments in registers
struct alignas(16) Arguments {
	alignas(16) __m64 rcx;
	alignas(16) __m64 rdx;
	alignas(16) __m64 r8;
	alignas(16) __m64 r9;
	alignas(16) __m128 xmm0;
	alignas(16) __m128 xmm1;
	alignas(16) __m128 xmm2;
	alignas(16) __m128 xmm3;

	BOOL toHex() {
		dll->LogFile() << std::hex;

		dll->LogFile() << "rcx:" << std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 0);
		dll->LogFile() << " rdx:" << std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 1);
		dll->LogFile() << " r8:" << std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 2);
		dll->LogFile() << " r9:" << std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 3);
		dll->LogFile() << " xmm0:"
			<< std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 4 + 8) << " "
			<< std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 4);
		dll->LogFile() << " xmm1:"
			<< std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 5 + 8) << " "
			<< std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 5);
		dll->LogFile() << " xmm2:"
			<< std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 6 + 8) << " "
			<< std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 6);
		dll->LogFile() << " xmm3:"
			<< std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 7 + 8) << " "
			<< std::setfill('0') << std::setw(16) << *(size_t*)((char*)this + 16 * 7);

		dll->LogFile() << std::dec;
		return TRUE;
	}
};
static_assert(offsetof(Arguments, rcx) == 0, "Incorrect offset for rcx");
static_assert(offsetof(Arguments, rdx) == 16, "Incorrect offset for rdx");
static_assert(offsetof(Arguments, r8) == 32, "Incorrect offset for r8");
static_assert(offsetof(Arguments, r9) == 48, "Incorrect offset for r9");
static_assert(offsetof(Arguments, xmm0) == 64, "Incorrect offset for xmm0");
static_assert(offsetof(Arguments, xmm1) == 80, "Incorrect offset for xmm1");
static_assert(offsetof(Arguments, xmm2) == 96, "Incorrect offset for xmm2");
static_assert(offsetof(Arguments, xmm3) == 112, "Incorrect offset for xmm3");

extern "C" void* onExportFuncCall(Arguments * args, DllExport dllExport) {
	size_t padding;
	auto idx = (int)dllExport;

	if (dll == nullptr) {
		if (!Init()) Alert("Failed to init");
	}

	std::lock_guard<std::mutex> lock(dll->Mutex());
	dll->LogFile() << originalDllExportsName[idx];

	// Align the register values
	padding = 100 - strlen(originalDllExportsName[idx]);
	if (padding < 0) padding = 0;
	for (int i = 0; i < padding; ++i) {
		dll->LogFile() << " ";
	}
	args->toHex();
	dll->LogFile() << "\n";

	void* result = nullptr;
	switch (dllExport) {
/* DLLPROXY: DllCaseDispatch */
	}
	return result;
})";
			const auto* asmFileTemplate = R"(
fwdcall macro idx
	; Align stack to 16 (Required for Arguments struct)
	push rbp
	mov rbp, rsp
	and rsp, -16
	; Save registers in struct Arguments, they keep to restored since they are volatile
	sub rsp, 16*8+32
	mov [rsp+16*0+32], rcx
	mov [rsp+16*1+32], rdx
	mov [rsp+16*2+32], r8
	mov [rsp+16*3+32], r9
	movdqu [rsp+16*4+32], xmm0
	movdqu [rsp+16*5+32], xmm1
	movdqu [rsp+16*6+32], xmm2
	movdqu [rsp+16*7+32], xmm3
	; Make call
	lea rcx, [rsp+32]
	mov edx, idx
	call onExportFuncCall
	; Restore registers
	movdqu xmm3, [rsp+16*7+32]
	movdqu xmm2, [rsp+16*6+32]
	movdqu xmm1, [rsp+16*5+32]
	movdqu xmm0, [rsp+16*4+32]
	mov r9, [rsp+16*3+32]
	mov r8, [rsp+16*2+32]
	mov rdx, [rsp+16*1+32]
	mov rcx, [rsp+16*0+32]
	; Restore stack
	add rsp, 16*8+32
	mov rsp, rbp
	pop rbp
	; Jump to address of original function
	jmp qword ptr [originalDllExports+idx*8]
endm

ovrdcall macro idx
	; Align stack to 16 (Required for Arguments struct)
	push rbp
	mov rbp, rsp
	and rsp, -16
	; Save registers in struct Arguments, no restore necessary since we directly return
	sub rsp, 16*8+32
	mov [rsp+16*0+32], rcx
	mov [rsp+16*1+32], rdx
	mov [rsp+16*2+32], r8
	mov [rsp+16*3+32], r9
	movdqu [rsp+16*4+32], xmm0
	movdqu [rsp+16*5+32], xmm1
	movdqu [rsp+16*6+32], xmm2
	movdqu [rsp+16*7+32], xmm3
	; Make call, result in rax
	lea rcx, [rsp+32]
	mov edx, idx
	call onExportFuncCall
	; Restore stack
	add rsp, 16*8+32
	mov rsp, rbp
	pop rbp
	ret
endm

onExportFuncCall proto C
.data
extern originalDllExports : qword
.code)";
#pragma endregion

std::vector<std::string> dllExports;

// Replaces all occurrences of "find" in "str" with "replace"
void replaceAll(std::string& str, const std::string& find, std::string replace) {
	std::string newStr;
	std::size_t lastPos = 0;

	while (true) {
		std::size_t pos = str.find(find, lastPos);
		if (pos == std::string::npos) break;

		// Text from lastPos to text before find
		newStr.append(str, lastPos, pos - lastPos);
		newStr.append(replace);

		lastPos = pos + find.length();
	}
	// Remaining text
	newStr.append(str, lastPos, str.length() - lastPos);
	str = newStr;
}

const std::vector<std::string> explode(const std::string& s, const char& c) {
	std::string buff{ "" };
	std::vector<std::string> v;

	for (auto n : s) {
		if (n != c) buff += n;
		else if (n == c && buff != "") {
			v.push_back(buff);
			buff = "";
		}
	}
	if (buff != "") v.push_back(buff);

	return v;
}

void listDllFunctions(std::string sADllName, std::vector<std::string>& slListOfDllFunctions) {
	DWORD* dNameRVAs(0);
	DWORD* dNameRVAs2(0);
	_IMAGE_EXPORT_DIRECTORY* ImageExportDirectory;
	unsigned long cDirSize;
	_LOADED_IMAGE LoadedImage;
	std::string sName;
	slListOfDllFunctions.clear();
	if (MapAndLoad(sADllName.c_str(), 0, &LoadedImage, 1, 1)) {
		ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

		if (ImageExportDirectory != 0) {
			dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, 0);

			for (size_t i = 0; i < ImageExportDirectory->NumberOfNames; i++) {
				sName = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], 0);
				slListOfDllFunctions.push_back(sName);
			}
		}
		UnMapAndLoad(&LoadedImage);
	}
}

void generateDef(std::string name, std::vector<std::string> names) {
	std::fstream file;
	file.open(name + ".def", std::ios::out);
	file << "LIBRARY " << name << std::endl;
	file << "EXPORTS" << std::endl;

	for (unsigned int i = 0; i < names.size(); i++) {
		file << "\t" << names[i] << "=Proxy_" << names[i] << " @" << i + 1 << std::endl;
	}

	file.close();
}

void generateMainCpp(std::string name, std::vector<std::string> dllExports) {
	std::string text = cppFileTemplate;

	replaceAll(text, "/* DLLPROXY: DllName */", name);

	replaceAll(text, "/* DLLPROXY: DllNumExports */", std::to_string(dllExports.size()));

	std::string buf;
	for (unsigned int i = 0; i < dllExports.size(); i++) {
		buf += std::string("\t\t\"") + dllExports[i] + "\",\n";
	}
	replaceAll(text, "/* DLLPROXY: DllExportsName */", buf);
	buf.clear();

	for (unsigned int i = 0; i < dllExports.size(); i++) {
		buf += std::string("\t") + dllExports[i] + ",\n";
	}
	replaceAll(text, "/* DLLPROXY: DllExportEnum */", buf);
	buf.clear();

	for (unsigned int i = 0; i < dllExports.size(); i++) {
		buf += std::string("static void* Inject_") + dllExports[i] + "() { return nullptr; }\n";
	}
	replaceAll(text, "/* DLLPROXY: DllInjectedFunctions */", buf);
	buf.clear();

	for (unsigned int i = 0; i < dllExports.size(); i++) {
		buf += std::string("\tcase DllExport::") + dllExports[i] + ":\n";
		buf += std::string("\t\tresult = Inject_") + dllExports[i] + "();\n";
		buf += std::string("\t\tbreak;\n");
	}
	replaceAll(text, "/* DLLPROXY: DllCaseDispatch */", buf);
	buf.clear();

	int fileNameLength = name.size() + 6;
	std::fstream file;
	file.open("dllmain.cpp", std::ios::out);
	file << text;

	file.close();
}

void generateAsm(std::string name, std::vector<std::string> dllExports) {
	std::fstream file;
	file.open(name + ".asm", std::ios::out);
	file << asmFileTemplate << std::endl;

	for (size_t i = 0; i < dllExports.size(); ++i) {
		const auto& dllExport = dllExports[i];
		file << std::endl;
		file << "Proxy_" << dllExport << " proc" << std::endl;
		file << "\tfwdcall " << i << std::endl;
		file << "Proxy_" << dllExport << " endp" << std::endl;
	}

	file << "end" << std::endl;

	file.close();
}

int main(int argc, char* argv[]) {
	std::vector<std::string> args(argv, argv + argc);
	if (argc == 1) {
		std::cout << "Invalid arguments." << std::endl;
		return 0;
	}

	std::cout << "Starting..." << std::endl;

	std::vector<std::string> fileNameV = explode(args[1], '\\');
	std::string fileName = fileNameV[fileNameV.size() - 1];
	fileName = fileName.substr(0, fileName.size() - 4);
	std::cout << "Generating DLL Proxy for DLL " << fileName << "..." << std::endl;

	listDllFunctions(args[1], dllExports);

	std::cout << "Generating DEF file..." << std::endl;
	generateDef(fileName, dllExports);

	std::cout << "Generating CPP file..." << std::endl;
	generateMainCpp(fileName, dllExports);

	std::cout << "Generating ASM file..." << std::endl;
	generateAsm(fileName, dllExports);

	std::cout << "Done!" << std::endl;
	return 0;
}