#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

DWORD FindProcessIdByName(const char* processName) {
	DWORD pid = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe)) {
		do {
			if (_stricmp(pe.szExeFile, processName) == 0) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return pid;
}

// Declare indirect function pointers
int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
void (WINAPI *pSleep)(DWORD);
BOOL(WINAPI *pBeep)(DWORD, DWORD);
BOOL(WINAPI *pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
int (WINAPI *pGetDeviceCaps)(HDC, int);

void CallIndirectly() {
	// Assign imported functions to pointers
	pMessageBoxA = MessageBoxA;
	pSleep = Sleep;
	pBeep = Beep;
	pOpenProcessToken = OpenProcessToken;
	pGetDeviceCaps = GetDeviceCaps;

	// Call through pointers
	pMessageBoxA(NULL, "Indirect MessageBoxA", "Win32 C", MB_OK);

	pSleep(500);
	pBeep(1000, 300);

	HANDLE token;
	if (pOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
		printf("OpenProcessToken succeeded.\n");
		CloseHandle(token);
	}

	HDC hdc = GetDC(NULL);
	if (hdc) {
		int width = pGetDeviceCaps(hdc, HORZRES);
		printf("Screen width: %d px\n", width);
		ReleaseDC(NULL, hdc);
	}
}
void Hello() {
	printf("Hello from indirect call!\n");
}

void CallMultipleDllFunctionsIndirectly() {
	// Function pointers
	int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
	void (WINAPI *pSleep)(DWORD);
	BOOL(WINAPI *pBeep)(DWORD, DWORD);
	HDC(WINAPI *pGetDC)(HWND);

	// Load libraries
	HMODULE hUser32 = LoadLibraryA("user32.dll");
	HMODULE hKernel32 = LoadLibraryA("kernel32.dll");
	HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");
	HMODULE hGdi32 = LoadLibraryA("gdi32.dll");

	if (!hUser32 || !hKernel32 || !hAdvapi32 || !hGdi32) {
		printf("Failed to load one or more DLLs\n");
		return;
	}

	// Resolve function addresses
	pMessageBoxA = (int (WINAPI *)(HWND, LPCSTR, LPCSTR, UINT))
		GetProcAddress(hUser32, "MessageBoxA");

	pSleep = (void (WINAPI *)(DWORD))
		GetProcAddress(hKernel32, "Sleep");

	pBeep = (BOOL(WINAPI *)(DWORD, DWORD))
		GetProcAddress(hKernel32, "Beep");

	pGetDC = (HDC(WINAPI *)(HWND))
		GetProcAddress(hUser32, "GetDC"); // from gdi32 indirectly via user32

// Use the functions
	if (pMessageBoxA) {
		pMessageBoxA(NULL, "Calling Sleep and Beep next", "Indirect Win32 Calls", MB_OK);
	}

	if (pSleep) {
		pSleep(500);
	}

	if (pBeep) {
		pBeep(750, 300); // 750 Hz for 300 ms
	}

	if (pGetDC) {
		HDC hdc = pGetDC(NULL); // Just retrieve screen DC (example)
		printf("Got screen HDC: 0x%p\n", hdc);
	}

	// Clean up
	FreeLibrary(hUser32);
	FreeLibrary(hKernel32);
	FreeLibrary(hAdvapi32);
	FreeLibrary(hGdi32);
}

void MyFunction() {
	MessageBoxA(NULL, "Called indirectly via ECX", "Indirect Call", MB_OK);
}
 
void MyFunc() {
	MessageBoxA(NULL, "Indirect call", "Info", MB_OK);
}

void Func1() {
	printf("Func1 called\n");
}

void Func2() {
	printf("Func2 called\n");
}

void Func3() {
	printf("Func3 called\n");
}

void CallIndirect() {
	void(*func)() = MyFunc;
	func();  // compiler emits indirect call, often via register
}
int main() {
	// Array of function pointers (all void functions with no params)
	void(*funcs[])() = { Func1, Func2, Func3 };

	int count = sizeof(funcs) / sizeof(funcs[0]);
	for (int i = 0; i < count; i++) {
		funcs[i]();  // Call function indirectly
	}
	CallIndirect();
	const char* targetProcess = "notepad.exe";
	DWORD pid = FindProcessIdByName(targetProcess);

	if (pid != 0) {
		printf("Found %s with PID: %lu\n", targetProcess, pid);
	}
	else {
		printf("Process %s not found.\n", targetProcess);
	}
	// Declare a function pointer
	void(*funcPtr)();

	// Assign the address of the target function
	funcPtr = &Hello;
	CallIndirectly();
	// Indirect call
	funcPtr();
	CallMultipleDllFunctionsIndirectly();
	return 0;
	return 0;
}
