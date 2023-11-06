#include<iostream>
#include<Windows.h>
#include<stdio.h>

using namespace std;
char _clion_installation_path[200];

bool FBFileExists(const char* szPath) {
    DWORD dwAttrib = GetFileAttributesA(szPath);
    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
        !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
bool EnableDebugPrivilege()
{
    HANDLE tokenHandle;
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
    {
        // std::cout << "Failed to open process token. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
    {
        // std::cout << "Failed to lookup privilege value. Error: " << GetLastError() << std::endl;
        CloseHandle(tokenHandle);
        return false;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
    {
        // std::cout << "Failed to adjust token privileges. Error: " << GetLastError() << std::endl;
        CloseHandle(tokenHandle);
        return false;
    }

    CloseHandle(tokenHandle);
    return true;
}
BOOL _ReplaceTimeStampToInstallDate(PBYTE _dll_content) {
    // clion的默认安装路径为 C:\Program Files\JetBrains\CLion 2023.2.2\bin
    // Uninstall.exe文件的创建时间就是安装时间
    memset(_clion_installation_path, 0, 200);
    printf("[*] please input the absolute path of Uninstall.exe (it should be in your IDE installation folder):\n\t");
    scanf("%[^\n]", _clion_installation_path);

    if (!FBFileExists(_clion_installation_path)) {
        printf("[-] still can not find Uninstall.exe, abort...\n");
        return 0;
    }
    WIN32_FIND_DATA _find_file_data;
    if (FindFirstFile(_clion_installation_path, &_find_file_data) == INVALID_HANDLE_VALUE) {
        printf("[-] can not locate Uninstall.exe, error code: %x, abort...\n", GetLastError());
        return 0;
    }

    // 输出人类可读的安装时间
    SYSTEMTIME _system_time;
    FileTimeToSystemTime(&_find_file_data.ftCreationTime, &_system_time);
    char _date_string[255] = { 0 };
    char _time_string[255] = { 0 };
    GetDateFormatA(LOCALE_USER_DEFAULT, DATE_SHORTDATE, &_system_time, NULL, _date_string, 255);
    GetTimeFormatA(LOCALE_USER_DEFAULT, 0, &_system_time, NULL, _time_string, 255);
    printf("[*] IDE installation date: %s %s\n", _date_string, _time_string);

    DWORD64 _installation_time_stamp = *reinterpret_cast<PDWORD64>(&_find_file_data.ftCreationTime);
    printf("[*] timestamp: 0x%p\n", _installation_time_stamp);
    *(PDWORD64)(_dll_content + 0x4A5) = _installation_time_stamp;


    // 替换systemtime，用于修改kernelbase!getsystemtime
    PBYTE _temp = (PBYTE)&_system_time;
    DWORD64 _temp_2 = *reinterpret_cast<PDWORD64>(_temp);
    DWORD64 _temp_3 = *reinterpret_cast<PDWORD64>(_temp+8);
    *(PDWORD64)(_dll_content + 0x4FE) = _temp_2;
    *(PDWORD64)(_dll_content + 0x516) = _temp_3;

    return 1;
}

int
main(int argc, char* argv[])
{

    DeleteFileA("C:\\users\\public\\dbghelp.dll");
    DeleteFileA("C:\\users\\public\\asdguaisd");

    printf("JetBrain's all kinds of IDE activation tool, proudly provide to you by 12138 [https://144.one]\n\n");
    // 读取PE文件本身，从里面把嵌入的DLL读出来
    CopyFileA(argv[0], "C:\\users\\public\\asdguaisd", FALSE);
    if (!FBFileExists("C:\\users\\public\\asdguaisd")) {
        printf("[-] failed to copy our self to temp file, abort...\n");
        return -1;
    }
    HANDLE _temp_file_handle = CreateFileA("C:\\users\\public\\asdguaisd", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (_temp_file_handle == INVALID_HANDLE_VALUE) {
        printf("[-] failed to open temp file, abort...\n");
        return -1;
    }
    DWORD _out = 0;

    // 将dll内容读取出来
    DWORD _total_file_size = GetFileSize(_temp_file_handle, 0);
    if (INVALID_FILE_SIZE == _total_file_size) {
        printf("[-] failed to get filesize of temp file, abort...\n");
        return -1;
    }
    printf("[*] total file size is: 0x%p\n", _total_file_size);
    PBYTE _whole_file_content = (PBYTE)malloc(_total_file_size);
    if (0 == _whole_file_content) {
        printf("[-] memory allocate failed, seriously?\n");
        return -1;
    }
    if (!ReadFile(_temp_file_handle, _whole_file_content, _total_file_size, &_out, 0)) {
        printf("[-] failed to get whole file content from temp file, abort...\n");
        return -1;
    }

    DWORD _dll_size = *(PDWORD)(_whole_file_content + (_total_file_size - 4));
    printf("[*] dll file size is: 0x%p\n", _dll_size);

    PBYTE _dll_content = (PBYTE)malloc(_dll_size);
    if (0 == _dll_content) {
        printf("[-] memory allocate failed, seriously?\n");
        return -1;
    }
    printf("[*] dll content offset: 0x%p\n", _total_file_size - 4 - _dll_size);
    memcpy(_dll_content, _whole_file_content + (_total_file_size - 4 - _dll_size), _dll_size);
    CloseHandle(_temp_file_handle);
    free(_whole_file_content);
    DeleteFileA("C:\\users\\public\\asdguaisd");

    // 将时间戳替换为安装时间
    if (!_ReplaceTimeStampToInstallDate(_dll_content)) {
        return -1;
    }
    printf("[+] successfully replace timestamp to installation date\n");

    // 生成DLL文件
    HANDLE _dll_file_handle = CreateFileA("C:\\users\\public\\dbghelp.dll", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (_dll_file_handle == INVALID_HANDLE_VALUE) {
        printf("[-] failed to craete dll file, error code: 0x%x, abort...\n", GetLastError());
        return -1;
    }
    if (!WriteFile(_dll_file_handle, _dll_content, _dll_size, &_out, 0)) {
        printf("[-] failed to write dll file, abort...\n");
        return -1;
    }
    CloseHandle(_dll_file_handle);
    free(_dll_content);

    printf("[+] dll generate succeed\n");

    // 进行文件拷贝工作
    char _installation_dir[200] = { 0 };
    memcpy(_installation_dir, _clion_installation_path, strlen(_clion_installation_path) - 13);
    char _dbghelp_string[20] = "winmm.dll";
    char _dbghelp_orgi_string[20] = "winmm_orig.dll";
    char _dbghelp_path[200] = { 0 };
    memcpy(_dbghelp_path, _installation_dir, strlen(_installation_dir));
    memcpy(_dbghelp_path + strlen(_installation_dir), _dbghelp_string, strlen(_dbghelp_string));
    char _dbghelp_orgi_path[200] = { 0 };
    memcpy(_dbghelp_orgi_path, _installation_dir, strlen(_installation_dir));
    memcpy(_dbghelp_orgi_path + strlen(_installation_dir), _dbghelp_orgi_string, strlen(_dbghelp_orgi_string));
    printf("[*] copying files...\n");
    if (!CopyFileA("C:\\users\\public\\dbghelp.dll", _dbghelp_path, FALSE)) {
        printf("[-] failed to copy our evil dll to installation directory, error code: 0x%x, abort...\n", GetLastError());
        return -1;
    }
    if (!CopyFileA("C:\\Windows\\System32\\winmm.dll", _dbghelp_orgi_path, FALSE)) {
        printf("[-] failed to copy original dll to installation directory, error code: 0x%x,abort...\n", GetLastError());
        return -1;
    }

    DeleteFileA("C:\\users\\public\\dbghelp.dll");

    printf("[+] activation is done, (re)start your clion to check\n");


    return 0;
}
