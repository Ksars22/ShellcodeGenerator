#include "peb.h"
void custom_memset(void* ptr, int value, size_t num_bytes) {
    unsigned char* p = static_cast<unsigned char*>(ptr);
    for (size_t i = 0; i < num_bytes; ++i) {
        p[i] = static_cast<unsigned char>(value);
    }
}

int main()
{
     
     
    wchar_t kernel32_dll_name[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0 };
    LPVOID base = get_module_by_name((const LPWSTR)kernel32_dll_name);
    if (!base) {
        return 1;
    }
    char load_lib_name[] = { 'L','o','a','d','L','i','b','r','a','r','y','A',0 };
    LPVOID load_lib = get_func_by_name((HMODULE)base, (LPSTR)load_lib_name);
    if (!load_lib) {
        return 2;
    }
    char get_proc_name[] = { 'G','e','t','P','r','o','c','A','d','d','r','e','s','s',0 };
    LPVOID get_proc = get_func_by_name((HMODULE)base, (LPSTR)get_proc_name);
    if (!get_proc) {
        return 3;
    }
    char create_process_name[] = { 'C','r','e','a','t','e','P','r','o','c','e','s','s','A',0 };
    LPVOID create_process = get_func_by_name((HMODULE)base, (LPSTR)create_process_name);
    if (!create_process) {
        return 4;
    }
    char wait_for_single_object_name[] = { 'W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t',0 };
    LPVOID wait_for_single_object = get_func_by_name((HMODULE)base, (LPSTR)wait_for_single_object_name);
    if (!wait_for_single_object)
    {
        return 5;
    }
    char close_handle_name[] = {'C','l','o','s','e','H','a','n','d','l','e',0};
    LPVOID close_handle = get_func_by_name((HMODULE)base, (LPSTR)close_handle_name);
    if (!close_handle)
    {
        return 6;
    }
    HMODULE(WINAPI * _LoadLibraryA)(LPCSTR lpLibFileName) = (HMODULE(WINAPI*)(LPCSTR))load_lib;
    FARPROC(WINAPI * _GetProcAddress)(HMODULE hModule, LPCSTR lpProcName) = (FARPROC(WINAPI*)(HMODULE, LPCSTR)) get_proc;
    BOOL(WINAPI * _CreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) = (BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION))create_process;
    DWORD(WINAPI * _WaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds) = (DWORD(WINAPI*)(HANDLE, DWORD)) wait_for_single_object;
    BOOL(WINAPI * _CloseHandle)(HANDLE hObject) = (BOOL(WINAPI*)(HANDLE)) close_handle;

    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInfo;
    custom_memset(&startupInfo, 0, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    custom_memset(&processInfo, 0, sizeof(processInfo));

    _CreateProcessA(NULL, const_cast<LPSTR>(command), NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo);
    
    _WaitForSingleObject(processInfo.hProcess, INFINITE);

    _CloseHandle(processInfo.hProcess);
    _CloseHandle(processInfo.hThread);

    return 0;
}
