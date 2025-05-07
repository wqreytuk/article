#include <windows.h>
#include <stdio.h>

typedef NTSTATUS(WINAPI* NtQuerySystemInformation_t)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

#define SystemHandleInformation 0x10
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

typedef struct _SYSTEM_HANDLE {
	ULONG       ProcessId;
	BYTE        ObjectTypeNumber;
	BYTE        Flags;
	USHORT      Handle;
	PVOID       Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1]; // Variable-length array
} SYSTEM_HANDLE_INFORMATION;

int main() {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) {
		printf("Failed to load ntdll.dll\n");
		return 1;
	}

	NtQuerySystemInformation_t NtQuerySystemInformation =
		(NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");

	if (!NtQuerySystemInformation) {
		printf("Failed to get NtQuerySystemInformation address\n");
		return 1;
	}

	ULONG bufferSize = 0x10000;
	PVOID buffer = NULL;
	ULONG returnLength = 0;
	NTSTATUS status;

	do {
		if (buffer) free(buffer);
		buffer = malloc(bufferSize);
		if (!buffer) {
			printf("Memory allocation failed\n");
			return 1;
		}

		status = NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, &returnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			bufferSize *= 2;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (status != 0) {
		printf("NtQuerySystemInformation failed: 0x%08X\n", status);
		free(buffer);
		return 1;
	}

	SYSTEM_HANDLE_INFORMATION* handleInfo = (SYSTEM_HANDLE_INFORMATION*)buffer;
	printf("Number of handles: %lu\n", handleInfo->HandleCount);

	for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE h = handleInfo->Handles[i];
		if (h.ObjectTypeNumber==8 && h.ProcessId == 1404) {

			printf("PID: %5lu  Handle: 0x%04X  ObjectType: %-3u  Access: 0x%08X\n",
				h.ProcessId, h.Handle, h.ObjectTypeNumber, h.GrantedAccess);
			printf("object address: 0x%p\n", h.Object);
			system("pause");
		}
	}

	free(buffer);
	return 0;
}
