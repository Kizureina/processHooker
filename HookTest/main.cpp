#define _CRT_SECURE_NO_WARNINGS 1
#include <iostream>
#include <Windows.h>
#include "../HookDll/HookDll.h"
#include <fstream>
#include "tchar.h"

void UnHook();

FARPROC pFunction = NULL;
SIZE_T bytesWritten = 0;
char messageBoxOriginalBytes[6] = {};


void writeText2File(LPCSTR lpText) {
    std::ofstream myfile("example.txt"); // 新建文件example.txt，以写入模式打开
    if (myfile.is_open()) { // 检查文件是否成功打开
        myfile << lpText << std::endl; // 向文件中输出字符串
        myfile.close(); // 关闭文件
        std::cout << "File created and text written to it." << std::endl;
    }
    else {
        std::cout << "Failed to create file." << std::endl;
    }
}


int __stdcall HookedMessageBox(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

    // print intercepted values from the MessageBoxA function
    std::cout << "Ohai from the hooked function\n";
    std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << std::endl;
    // SetWindowText(hwndTextBox2, lpText);

    //WriteToSharedMemory(lpText);
    UnHook();
    MessageBoxA(NULL, lpText, "GET IT", MB_OK);

    //MessageBoxA(NULL, "写入共享内存成功！", "Hooker GET IT!!", MB_OK);
    // writeText2File(lpText);

    // call the original MessageBoxA
    return MessageBoxA(NULL, lpText, lpCaption, uType);
}



void HookAPI() {
    pFunction = getLibraryProcAddress("user32.dll", "MessageBoxA");
    SIZE_T bytesRead = 0;

    // save the first 6 bytes of the original MessageBoxA function - will need for unhooking
    ReadProcessMemory(GetCurrentProcess(), pFunction, messageBoxOriginalBytes, 6, &bytesRead);

    // create a patch "push <address of new MessageBoxA); ret"
    void* hookedMessageBoxAddress = &HookedMessageBox;
    char patch[6] = { 0 };
    memcpy_s(patch, 1, "\x68", 1); //push
    memcpy_s(patch + 1, 4, &hookedMessageBoxAddress, 4); //32位地址为4字节长度
    memcpy_s(patch + 5, 1, "\xC3", 1); //ret

    // patch the MessageBoxA
    if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)pFunction, patch, sizeof(patch), &bytesWritten)) {
        DWORD dwError = GetLastError();
        // 当dwError为5时，说明写入进程数据的请求被拒绝，即为权限或者安全问题
    }
}


void UnHook() {
    // unpatch MessageBoxA
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)pFunction, messageBoxOriginalBytes, sizeof(messageBoxOriginalBytes), &bytesWritten);
}



/* ================================= 测试读取共享内存空间的数据 ==================================*/

// 共享内存区域的名称
const char* sharedMemoryName = "MySharedMemory";

// 数据结构（示例）
struct MyData {
    int value;
    char message[256];
};

void ReadFromSharedMemory() {
    // 打开共享内存区域
    HANDLE hMapFile = OpenFileMappingA(FILE_MAP_READ, FALSE, sharedMemoryName);
    if (hMapFile == NULL) {
        std::cout << "Failed to open shared memory: " << GetLastError() << std::endl;
        return;
    }

    // 获取共享内存的指针
    LPVOID pSharedMemory = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, sizeof(MyData));
    if (pSharedMemory == NULL) {
        std::cout << "Failed to map view of shared memory: " << GetLastError() << std::endl;
        CloseHandle(hMapFile);
        return;
    }

    // 读取数据从共享内存
    MyData* pData = static_cast<MyData*>(pSharedMemory);
    std::cout << "Value: " << pData->value << std::endl;
    std::cout << "Message: " << pData->message << std::endl;

    // 解除映射和关闭句柄
    UnmapViewOfFile(pSharedMemory);
    CloseHandle(hMapFile);
}

/* ============================================= 测试通过远程线程实现DLL注入 ==============================================*/

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
    HANDLE hProcess = NULL, hThread = NULL;
    HMODULE hMod = NULL;
    LPVOID pRemoteBuf = NULL;
    DWORD dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
    LPTHREAD_START_ROUTINE pThreadProc;
    // Open target process to inject dll
    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
    {
        _tprintf(L"Fail to open process %d ! [%d]\n", dwPID, GetLastError());
        return FALSE;
    }
    // Allocate memory in the remote process big enough for the DLL path name
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
    // Write the DLL path name to the space allocated in the target process
    WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllPath, dwBufSize, NULL);
    // Find the address of LoadLibrary in target process(same to this process)
    hMod = GetModuleHandle(L"kernel32.dll");
    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
    // Create a remote thread in target process
    hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}


bool RemoteThreadInject(DWORD targetProcessId, const char* dllPath)
{
    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, targetProcessId);
    if (hProcess == NULL)
    {
        // 处理打开进程失败的情况
        return false;
    }

    // 在目标进程中分配内存
    size_t dllPathLength = strlen(dllPath) + 1;
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, dllPathLength, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteMemory == NULL)
    {
        // 处理内存分配失败的情况
        CloseHandle(hProcess);
        return false;
    }

    // 将DLL路径写入目标进程的内存中
    SIZE_T bytesRead;
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, dllPathLength, &bytesRead) || bytesRead != dllPathLength)
    {
        // 处理写入内存失败的情况
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 获取LoadLibrary函数地址
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibrary == NULL)
    {
        // 处理获取LoadLibrary函数地址失败的情况
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 在目标进程中创建远程线程执行LoadLibrary函数
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibrary), pRemoteMemory, 0, NULL);
    if (hRemoteThread == NULL)
    {
        // 处理创建远程线程失败的情况
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 等待远程线程结束
    WaitForSingleObject(hRemoteThread, INFINITE);

    // 关闭句柄
    CloseHandle(hRemoteThread);

    // 释放内存
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);

    // 关闭进程句柄
    CloseHandle(hProcess);

    return true;
}


int main()
{
    //ReadFromSharedMemory();
    /*
    MessageBoxA(NULL, "Hi", "test", MB_OK);
    HookAPI();
    MessageBoxA(NULL, "Hi", "test11", MB_OK);
    */
    if (RemoteThreadInject(30192, "HookDll.dll")) {
        printf("注入成功！\n");
    }
    return 0;
}
