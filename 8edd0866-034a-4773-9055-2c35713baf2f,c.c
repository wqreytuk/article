#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <stdlib.h>

void PrintLaunchProtectionLevel(DWORD level) {
	switch (level) {
	case 0:
		wprintf(L"Launch Protection: None (0)\n");
		break;
	case 1:
		wprintf(L"Launch Protection: Windows (1)\n");
		break;
	case 2:
		wprintf(L"Launch Protection: Windows Light (2)\n");
		break;
	case 3:
		wprintf(L"Launch Protection: Antimalware Light (3)\n");
		break;
	default:
		wprintf(L"Launch Protection: Unknown (%lu)\n", level);
	}
}

void GetServiceConfig(const wchar_t* serviceName) {
	SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (!hSCManager) {
		wprintf(L"OpenSCManager failed. Error: %lu\n", GetLastError());
		return;
	}

	SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_QUERY_CONFIG);
	if (!hService) {
		wprintf(L"OpenService failed. Error: %lu\n", GetLastError());
		CloseServiceHandle(hSCManager);
		return;
	}

	DWORD bytesNeeded = 0;
	QueryServiceConfig(hService, NULL, 0, &bytesNeeded);
	LPQUERY_SERVICE_CONFIG config = (LPQUERY_SERVICE_CONFIG)malloc(bytesNeeded);
	if (!config) {
		wprintf(L"Memory allocation failed\n");
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCManager);
		return;
	}

	if (QueryServiceConfig(hService, config, bytesNeeded, &bytesNeeded)) {
		wprintf(L"--- Basic Configuration ---\n");
		wprintf(L"Binary Path: %s\n", config->lpBinaryPathName);
		wprintf(L"Start Type: %lu\n", config->dwStartType);
		wprintf(L"Service Type: %lu\n", config->dwServiceType);
		wprintf(L"Display Name: %s\n", config->lpDisplayName);
	}
	else {
		wprintf(L"QueryServiceConfig failed. Error: %lu\n", GetLastError());
	}

	// Get launch protection level
	SERVICE_LAUNCH_PROTECTED_INFO lpInfo = { 0 };
	DWORD outBytes = 0;
	if (QueryServiceConfig2W(hService, SERVICE_CONFIG_LAUNCH_PROTECTED,
		(LPBYTE)&lpInfo, sizeof(lpInfo), &outBytes)) {
		wprintf(L"\n--- Extended Configuration ---\n");
		PrintLaunchProtectionLevel(lpInfo.dwLaunchProtected);
	}
	else {
		DWORD err = GetLastError();
		if (err == ERROR_ACCESS_DENIED)
			wprintf(L"Access denied querying launch protection level.\n");
		else if (err == ERROR_INVALID_LEVEL)
			wprintf(L"Launch protection info not supported on this system.\n");
		else
			wprintf(L"QueryServiceConfig2 failed. Error: %lu\n", err);
	}

	free(config);
	CloseServiceHandle(hService);
	CloseServiceHandle(hSCManager);
}

#include "fltuser.h"
#include "Windows.h"


typedef LONG NTSTATUS;
#define SystemProcessInformation 5
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;


typedef NTSTATUS(NTAPI *PFN_NTQUERYSYSTEMINFORMATION)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

typedef struct _SYSTEM_BIGPOOL_ENTRY {
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;     // lowest bit indicates if NonPaged
	};
	SIZE_T SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
	// ULONG PoolType;  // 根据我实际测试的结果，根本看不到pooltype，他只有va、size和tag，这个结构体一共就0xc字节  chatgpt骗我
	// 错了，size不是c  由于padding的存在实际上 是8+4+padding+4+padding -> 18h
} SYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1]; // variable size array
} SYSTEM_BIGPOOL_INFORMATION;
int wmain(int argc, wchar_t* argv[]) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	PFN_NTQUERYSYSTEMINFORMATION NtQuerySystemInformation =
		(PFN_NTQUERYSYSTEMINFORMATION)GetProcAddress(ntdll, "NtQuerySystemInformation");

	// Note: This is poor programming (hardcoding 4MB).
	// The correct way would be to issue the system call
	// twice, and use the resultLength of the first call
	// to dynamically size the buffer to the correct size
	//
	DWORD64	bigPoolInfo2 = (DWORD64)malloc(
		4 * 1024 * 1024);

#define SystemBigPoolInformation 0x42
	DWORD resultLength = 0;
	NTSTATUS res = NtQuerySystemInformation(SystemBigPoolInformation,
		(PVOID)bigPoolInfo2,
		4 * 1024 * 1024,
		&resultLength);



	SYSTEM_BIGPOOL_INFORMATION* bigPoolInfo = (SYSTEM_BIGPOOL_INFORMATION*)bigPoolInfo2;
	printf("big pool structure addr: 0x%p\n", bigPoolInfo);
	printf("big page count: 0x%x\n", bigPoolInfo->Count);
	system("pause");
	SYSTEM_BIGPOOL_ENTRY* entry = (SYSTEM_BIGPOOL_ENTRY*)&bigPoolInfo->AllocatedInfo;
	printf("TYPE     ADDRESS\tBYTES\tTAG\n");
	for (int i = 0; i < bigPoolInfo->Count; i++)
	{
		printf("%s0x%p\t0x%lx\t%c%c%c%c\n",
			((DWORD)(entry[i].VirtualAddress) & 1) == 1 ?
			"Nonpaged " : "Paged    ",
			(DWORD)(entry[i].VirtualAddress)&(~1),
			entry[i].SizeInBytes,
			entry[i].Tag[0],
			entry[i].Tag[1],
			entry[i].Tag[2],
			entry[i].Tag[3]);

	}

	return 0;
}
