#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NON_CONFORMING_SWPRINTFS
// WindowsProject3.cpp : 定义应用程序的入口点。
//

#include "ProcessHooker.h"
#include "framework.h"
#include "WindowsProject3.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <Psapi.h>
#include <iostream>
#include <string>
#include <sstream>
#include <gdiplus.h>

#define MAX_LOADSTRING 100
#define BUFSIZE 512

// 全局变量:
HINSTANCE hInst;                                // 当前实例
WCHAR szTitle[MAX_LOADSTRING];                  // 标题栏文本
WCHAR szWindowClass[MAX_LOADSTRING];            // 主窗口类名

/*窗口句柄*/
HWND hListBox;  //  ListBox 句柄
HWND hwndTextBox1; // 文本框1句柄
HWND hwndTextBox2; // 文本框2句柄
HWND btn; // 按钮句柄

HANDLE hProcess = NULL; // 获取选中进程的句柄
FARPROC pFunction = NULL; // 目标函数的地址
HMODULE hModule = NULL;


// 定义接受消息的数据结构
struct MyData
{
    int intValue;
    float floatValue;
    char stringValue[256];
};


// 此代码模块中包含的函数的前向声明:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);



/* ================================================ 工具函数 =====================================================*/

// 在文本框中以添加形式输出文本(正常char类型字符数组，即x86字符串)
void AppendTextToTextBox2(const char* text)
{
    int textLength = GetWindowTextLength(hwndTextBox2);
    SendMessageA(hwndTextBox2, EM_SETSEL, textLength, textLength);
    SendMessageA(hwndTextBox2, EM_REPLACESEL, FALSE, (LPARAM)text);
}

// 接受宽字符的重载
void AppendTextToTextBox2(const wchar_t* text)
{
    int textLength = GetWindowTextLength(hwndTextBox2);
    SendMessage(hwndTextBox2, EM_SETSEL, textLength, textLength);
    SendMessage(hwndTextBox2, EM_REPLACESEL, FALSE, (LPARAM)text);
}


/*=========================================== 获取当前所有进程（除了一些系统进程） ==========================================*/

int ProcessIDList[1024] = {};
int i = 0;
void ListProcesses(HWND hListBox) {
    // 创建一个进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        perror("CreateToolhelp32Snapshot");
        SetWindowText(hwndTextBox2, L"[ERROR] CreateToolhelp32Snapshot has been failed！\r\n=============================\r\n");
        return;
    }

    // 设置结构体的大小
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 获取第一个进程的信息
    if (Process32First(hSnapshot, &pe32)) {
        int i = 0;
        do {
            // 排除系统进程
            if (wcsstr(pe32.szExeFile, L"System") == NULL && wcsstr(pe32.szExeFile, L"svchost") == NULL) {
                ProcessIDList[i] = pe32.th32ProcessID;
                // 添加进程信息到 ListBox 控件
                WCHAR buffer[256];
                // 将格式化的数据写入宽字符数组
                swprintf(buffer, L"PID: %lu, Process Name: %s", pe32.th32ProcessID, pe32.szExeFile);
                // 将添加字符串的消息发送给ListBox句柄
                SendMessage(hListBox, LB_ADDSTRING, 0, (LPARAM)buffer);
                i++;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    else {
        perror("Process32First");
    }

    // 关闭进程快照句柄
    CloseHandle(hSnapshot);
}

/*
void ListProcesses(HWND hListBox) {
    // 创建一个进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        perror("CreateToolhelp32Snapshot");
        return;
    }

    // 设置结构体的大小
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 获取第一个进程的信息
    if (Process32First(hSnapshot, &pe32)) {
        int i = 0;
        do {
            ProcessIDList[i] = pe32.th32ProcessID;
            // 添加进程信息到 ListBox 控件
            WCHAR buffer[256];
            // 将格式化的数据写入宽字符数组
            swprintf(buffer, L"Process ID: %lu, Process Name: %s", pe32.th32ProcessID, pe32.szExeFile);
            // 将添加字符串的消息发送给ListBox句柄
            SendMessage(hListBox, LB_ADDSTRING, 0, (LPARAM)buffer);
            i++;
        } while (Process32Next(hSnapshot, &pe32));
    }
    else {
        perror("Process32First");
    }

    // 关闭进程快照句柄
    CloseHandle(hSnapshot);
}
*/

/*
void ListProcesses(HWND hListBox) {
    // 创建一个进程快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        perror("CreateToolhelp32Snapshot");
        return;
    }

    // 设置结构体的大小
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // 获取第一个进程的信息
    if (Process32First(hSnapshot, &pe32)) {
        // 遍历所有进程，将进程 ID 存储在数组中
        do {
            ProcessIDList[i] = pe32.th32ProcessID;
            i++;
        } while (Process32Next(hSnapshot, &pe32));

        // 从数组末尾开始向列表框控件中添加进程信息
        for (int j = i - 1; j >= 0; j--) {
            // 获取进程句柄
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ProcessIDList[j]);
            if (hProcess) {
                // 获取进程文件名
                WCHAR processName[MAX_PATH];
                if (GetModuleBaseNameW(hProcess, NULL, processName, MAX_PATH)) {
                    // 将进程信息添加到 ListBox 控件
                    WCHAR buffer[256];
                    swprintf(buffer, L"Process ID: %lu, Process Name: %s", ProcessIDList[j], processName);
                    SendMessage(hListBox, LB_ADDSTRING, 0, (LPARAM)buffer);
                }
                CloseHandle(hProcess);
            }
        }
    }
    else {
        perror("Process32First");
    }

    // 关闭进程快照句柄
    CloseHandle(hSnapshot);
}

*/

/*================================================ 获取进程运行信息 ====================================================*/

WCHAR* GetProcessInfo(DWORD pid)
{
    std::string processInfo;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess != NULL)
    {
        TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
        {
            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
        }

        TCHAR szProcessPath[MAX_PATH];
        DWORD dwSize = sizeof(szProcessPath) / sizeof(TCHAR);
        if (QueryFullProcessImageName(hProcess, 0, szProcessPath, &dwSize))
        {
            //char szProcessInfo[1024];
            //sprintf(szProcessInfo, "Process name: %s\nExecutable path: %s\n", szProcessName, szProcessPath);
            //processInfo = szProcessInfo;
            return szProcessPath;
        }
        else
        {
            char szError[256];
            sprintf(szError, "Failed to retrieve process image path. Error: %d\n", GetLastError());
            SetWindowText(hwndTextBox2, L"[ERROR] Failed to retrieve process image path\r\n=============================\r\n");
            processInfo = szError;
        }

        CloseHandle(hProcess);
    }
    else
    {
        char szError[256];
        sprintf(szError, "Failed to open the process. Error: %d\n", GetLastError());
        SetWindowText(hwndTextBox2, L"[ERROR] Failed to open the process.\r\n=============================\r\n");
        processInfo = szError;
    }

}


/*================================================ 获取进程内存信息 ====================================================*/

PROCESS_MEMORY_COUNTERS_EX PrintProcessMemoryInfo(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    PROCESS_MEMORY_COUNTERS_EX pmc;
    memset(&pmc, 0, sizeof(pmc));


    if (hProcess) {
        if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            /*
            // 打印进程内存信息
            printf("Working Set Size: %llu bytes\n", pmc.WorkingSetSize);
            printf("Private Usage: %llu bytes\n", pmc.PrivateUsage);
            printf("Peak Working Set Size: %llu bytes\n", pmc.PeakWorkingSetSize);
            printf("Pagefile Usage: %llu bytes\n", pmc.PagefileUsage);
            printf("Peak Pagefile Usage: %llu bytes\n", pmc.PeakPagefileUsage);
            */
        }
        CloseHandle(hProcess);
    }
    else
    {
        DWORD error = GetLastError();
    }
    return pmc;
}


/*============================================= 判断目标进程是否调用了目标模块 ==============================================*/

bool IsProcessUsingDll(HANDLE hProcess, char* moduleName) {
    bool result = false;

    HMODULE hModules[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModule[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hModules[i], szModule, sizeof(szModule))) {
                if (_stricmp(szModule + strlen(szModule) - strlen(moduleName), moduleName) == 0) {
                    result = true;
                    break;
                }
            }
        }
    }
    // CloseHandle(hProcess);
    // 此处不能关闭进程句柄
    return result;
}


/*============================================= 获取目标函数所在的模块和地址 ==============================================*/

bool GetFunctionModuleAndAddress(HANDLE hProcess, const char* moduleName, const char* functionName, HMODULE* pModule, FARPROC* pFunction)
{
    HMODULE hModules[1024];
    DWORD cbNeeded = 0;

    // 枚举进程中所有模块的句柄
    if (!EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        DWORD dwError = GetLastError();

        // 输出错误码，可通过返回的int确定API函数报错原因
        // 当错误码为6时，说明句柄无效，即为hProcess的问题
        // 当错误码为299时，尝试读取进程模块信息时发生了部分复制错误，多半是架构不同

        SetWindowText(hwndTextBox2, L"[ERROR] EnumProcessModules failed with error code\r\n=============================\r\n");
        // printf("EnumProcessModules failed with error code %d\n", dwError);
        return false;
    }

    for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        HMODULE hModule = hModules[i];
        CHAR szModuleName[MAX_PATH];

        // 获取模块路径
        if (GetModuleFileNameExA(hProcess, hModule, szModuleName, sizeof(szModuleName)) == 0) {
            continue;
        }

        // 检查模块名称是否匹配
        if (_stricmp(szModuleName + strlen(szModuleName) - strlen(moduleName), moduleName) == 0) {
            // 找到包含目标函数的模块
            // 从目标模块中获取目标函数的地址
            FARPROC pFunc = GetProcAddress(hModule, functionName);
            if (pFunc != NULL) {
                *pModule = hModule;
                *pFunction = pFunc;
                return true;
            }
        }
    }

    return false;
}


/*======================== 通过修改机器码直接inline Hook，使用jmp指令，但需要计算偏移量，比较麻烦（NOT Work） =======================*/

// 备份原始函数的机器码
BYTE* BackupOriginalFunction(HANDLE hProcess, FARPROC pFunction, DWORD dwSize)
{
    BYTE* pOriginalCode = new BYTE[dwSize];
    ReadProcessMemory(hProcess, pFunction, pOriginalCode, dwSize, NULL);
    return pOriginalCode;
}


// 修改目标函数的机器码
void ModifyTargetFunction(HANDLE hProcess, FARPROC pFunction, BYTE* pPatch, DWORD dwSize)
{
    WriteProcessMemory(hProcess, pFunction, pPatch, dwSize, NULL);
}



// 执行 Hook 代码
void ExecuteHookCode(HANDLE hProcess, BYTE* pHookCode, DWORD dwHookCodeSize, LPVOID& pAllocatedMemory)
{
    pAllocatedMemory = VirtualAllocEx(hProcess, NULL, dwHookCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, pAllocatedMemory, pHookCode, dwHookCodeSize, NULL);
}



// 转移执行流程
void RedirectExecutionFlow(HANDLE hProcess, FARPROC pFunction, LPVOID pAllocatedMemory)
{
    DWORD dwJumpOffset = (DWORD)pAllocatedMemory - ((DWORD)pFunction + 5);
    BYTE jumpCode[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
    memcpy(jumpCode + 1, &dwJumpOffset, sizeof(DWORD));
    WriteProcessMemory(hProcess, pFunction, jumpCode, sizeof(jumpCode), NULL);
}



/*============================ 通过直接修改目标进程所调用API函数代码段实现inline Hook（NOT Work） =============================*/

// 具体hook代码 
SIZE_T bytesWritten = 0;
char messageBoxOriginalBytes[6] = {};

int __stdcall HookedMessageBox(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

    // print intercepted values from the MessageBoxA function
    std::cout << "Ohai from the hooked function\n";
    std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << std::endl;
    // SetWindowText(hwndTextBox2, lpText);

    // unpatch MessageBoxA
    WriteProcessMemory(hProcess, (LPVOID)pFunction, messageBoxOriginalBytes, sizeof(messageBoxOriginalBytes), &bytesWritten);
    
    MessageBoxA(NULL, lpText, "GET IT", MB_OK);

    // call the original MessageBoxA
    return MessageBoxA(NULL, lpText, lpCaption, uType);
}



// inline Hook实现
void hookWinAPI(HANDLE hProcess, FARPROC pFunction) {
    SIZE_T bytesRead = 0;

    // save the first 6 bytes of the original MessageBoxA function - will need for unhooking
    ReadProcessMemory(hProcess, pFunction, messageBoxOriginalBytes, 6, &bytesRead);

    // create a patch "push <address of new MessageBoxA); ret"
    void* hookedMessageBoxAddress = &HookedMessageBox;
    char patch[6] = { 0 };
    memcpy_s(patch, 1, "\x68", 1);
    memcpy_s(patch + 1, 4, &hookedMessageBoxAddress, 4);
    memcpy_s(patch + 5, 1, "\xC3", 1);

    // 修改权限
    // 保存原有的字节，需要先把目标函数的虚拟内存设置为可读写
    // VirtualProtect(pFunction, 6, PAGE_EXECUTE_READWRITE, 0);

    // patch the MessageBoxA
    if (!WriteProcessMemory(hProcess, (LPVOID)pFunction, patch, sizeof(patch), &bytesWritten)) {
        DWORD dwError = GetLastError();
        
        // 当dwError为5时，说明写入进程数据的请求被拒绝，即为权限或者安全问题
        // user32.dll通常是由操作系统加载并且具有保护，因此直接修改其中的函数是不被允许的。即使您以管理员权限运行程序，也不能随意修改操作系统内置的DLL文件。
        // 好像通过inline hook实现hook目标进程的API函数。是不行的了
    }

    /* x64架构下的Hook代码
    // show messagebox before hooking
    // MessageBoxW(NULL, L"test_text", L"test_caption", MB_OK);

    SIZE_T bytesRead = 0;

    // 备份原始函数的机器码,装入OldCode数组
    // save the first 12 bytes of the original MessageBoxA function - will need for unhooking
    ReadProcessMemory(hProcess, pFunction, OldCode, 12, &bytesRead);

    // create a patch "push <address of new MessageBoxA); ret"
    void* hookedMessageBoxAddress = &HookedMessageBox;
    *(PINT64)(HookCode + 2) = (UINT64)HookedMessageBox;
    // patch the MessageBoxA
    WriteProcessMemory(hProcess, (LPVOID)pFunction, HookCode, sizeof(HookCode), &bytesWritten);

    // show messagebox after hooking
    // MessageBoxW(NULL, L"test_text", L"test_caption", MB_OK);
    
    */
}



/*=============================== 通过inline Hook代码写入DLL，再用DLL注入的形式实现Hook API ================================*/

// 获取LoadLibraryA函数的地址，用于实现新建远程线程以完成DLL注入
// inline：不会存在对 getLoadLibraryAddress 函数的显式调用，而是直接插入了 getLibraryProcAddress("kernel32.dll", "LoadLibraryA") 的代码
inline FARPROC getLoadLibraryAddress()
{
    return getLibraryProcAddress("kernel32.dll", "LoadLibraryW");
}


// DLL注入hook实现(NOT work)
void injectWithRemoteThread(PROCESS_INFORMATION& pi, const char* dllPath)
{
    //申请dll路径的内存，获取LoadLibraryA地址
    AppendTextToTextBox2(L"Allocating Remote Memory For dll path\r\n=============================\r\n");
    // puts("Allocating Remote Memory For dll path");
    const int bufferSize = strlen(dllPath) + 1;
    
    VirtualMemory dllPathMemory(pi.hProcess, bufferSize, PAGE_READWRITE);
    
    dllPathMemory.copyFromBuffer(dllPath, bufferSize);
    PTHREAD_START_ROUTINE startRoutine = (PTHREAD_START_ROUTINE)pFunction;

    //用dll路径和LoadLibraryA的地址创建远程线程
    // puts("Creatint remote thread");
    AppendTextToTextBox2(L"Creatint remote thread\r\n=============================\r\n");

    HANDLE remoteThreadHandle = CreateRemoteThread(
        pi.hProcess, NULL, NULL, startRoutine, dllPathMemory.getAddress(), CREATE_SUSPENDED, NULL);
    if (remoteThreadHandle == NULL) {
        throw std::runtime_error("[ERROR] Failed to create remote thread!");
    }

    //继续远程线程以执行LoadLibraryA，等待其执行完毕
    // puts("Resume remote thread");
    AppendTextToTextBox2(L"Resume remote thread\r\n=============================\r\n");
    ResumeThread(remoteThreadHandle);
    WaitForSingleObject(remoteThreadHandle, INFINITE);
    CloseHandle(remoteThreadHandle);

    //继续主线程
    puts("Resume main thread");
    AppendTextToTextBox2(L"Resume main thread\r\n=============================\r\n");
    ResumeThread(pi.hThread);
}



// 使用创建远程线程的方式实现DLL注入(Work)
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
        AppendTextToTextBox2(L"[ERROR] 在目标进程中分配内存空间失败\r\n=============================\r\n");
        CloseHandle(hProcess);
        return false;
    }

    // 将DLL路径写入目标进程的内存中
    SIZE_T bytesRead;
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, dllPathLength, &bytesRead) || bytesRead != dllPathLength)
    {
        // 处理写入内存失败的情况
        AppendTextToTextBox2(L"[ERROR] 在目标进程中写入内存空间失败\r\n=============================\r\n");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 获取LoadLibrary函数地址
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    if (hKernel32 == NULL)
    {
        // 处理获取kernel32模块句柄失败的情况
        AppendTextToTextBox2(L"[ERROR] 获取kernel32模块句柄失败\r\n=============================\r\n");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibrary == NULL)
    {
        // 处理获取LoadLibrary函数地址失败的情况
        AppendTextToTextBox2(L"[ERROR] 获取LoadLibrary函数地址失败\r\n=============================\r\n");
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // 在目标进程中创建远程线程执行LoadLibrary函数
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibrary), pRemoteMemory, 0, NULL);
    if (hRemoteThread == NULL)
    {
        // 处理创建远程线程失败的情况
        AppendTextToTextBox2(L"[ERROR] 创建远程线程失败\r\n=============================\r\n");
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


/* ================================================ 管道方式实现进程通信(NOT work) ====================================*/

// 读取管道内数据
int processTransmitByPipe()
{
    HANDLE hPipe;
    DWORD dwRead;
    WCHAR buffer[BUFSIZE];

    // 连接到命名管道
    hPipe = CreateFile(TEXT("\\\\.\\pipe\\MyPipe"), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        AppendTextToTextBox2(L"Failed to connect to named pipe.\r\n=============================\r\n");
        return 1;
    }

    // 从命名管道读取数据
    if (ReadFile(hPipe, buffer, BUFSIZE, &dwRead, NULL))
    {
        printf("Data read from pipe: %ls\n", buffer);
        AppendTextToTextBox2(L"Data read from pipe:");
        AppendTextToTextBox2(buffer);
        AppendTextToTextBox2(L"\r\n=============================\r\n");
    }
    else
    {
        printf("Failed to rea data from pipe. Error code: %d\n", GetLastError());
        AppendTextToTextBox2(L"Failed to read data from pipe.\r\n=============================\r\n");
    }

    // 关闭命名管道句柄
    CloseHandle(hPipe);
}


/* ================================================== 剪切板实现进程间通信(Work) ======================================*/


const WCHAR* GetTextFromClipboard()
{
    const WCHAR* text = nullptr;

    // 打开剪贴板
    if (OpenClipboard(nullptr))
    {
        // 检查剪贴板中是否存在文本数据
        if (IsClipboardFormatAvailable(CF_UNICODETEXT))
        {
            // 获取剪贴板中的数据句柄
            HANDLE hMem = GetClipboardData(CF_UNICODETEXT);
            if (hMem)
            {
                // 锁定内存并读取数据
                WCHAR* pMem = static_cast<WCHAR*>(GlobalLock(hMem));
                if (pMem)
                {
                    text = pMem;
                    GlobalUnlock(hMem);
                }
            }
        }

        // 关闭剪贴板
        CloseClipboard();
    }

    return text;
}



int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: 在此处放置代码。

    // 初始化全局字符串
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_WINDOWSPROJECT3, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // 执行应用程序初始化:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_WINDOWSPROJECT3));


    MSG msg;

    // 主消息循环:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}



//
//  函数: MyRegisterClass()
//
//  目标: 注册窗口类。
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_WINDOWSPROJECT3);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_ICON1));

    return RegisterClassExW(&wcex);
}

//
//   函数: InitInstance(HINSTANCE, int)
//
//   目标: 保存实例句柄并创建主窗口
//
//   注释:
//
//        在此函数中，我们在全局变量中保存实例句柄并
//        创建和显示主程序窗口。
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // 将实例句柄存储在全局变量中

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
       508,
       175,
       1007,
       655,
       nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);
   UpdateWindow(hWnd);

   return TRUE;
}

//
//  函数: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  目标: 处理主窗口的消息。
//
//  WM_COMMAND  - 处理应用程序菜单
//  WM_PAINT    - 绘制主窗口
//  WM_DESTROY  - 发送退出消息并返回
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
        case WM_CREATE:
            {
                // 创建 ListBox 控件
                hListBox = CreateWindowEx(0, L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_AUTOVSCROLL | LBS_NOTIFY,
                    10, 30, 540, 560, hWnd, (HMENU)IDC_LISTBOX, hInst, NULL);
                
                // 获取并显示进程信息
                ListProcesses(hListBox);
                

                // 创建第一个文本框
                hwndTextBox1 = CreateWindowEx(
                    0,
                    L"EDIT",
                    L"",
                    // 文本框可以多行显示和自动垂直滚动
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_MULTILINE | ES_AUTOVSCROLL,
                    565,
                    40,
                    400,
                    150,
                    hWnd,
                    NULL,
                    NULL,
                    NULL
                );


                // 创建第二个文本框
                hwndTextBox2 = CreateWindowEx(
                    0,
                    L"EDIT",
                    L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_MULTILINE | ES_AUTOVSCROLL,
                    565,
                    240,
                    400,
                    340,
                    hWnd,
                    NULL,
                    NULL,
                    NULL
                );


                // 创建按键
                btn = CreateWindowEx(
                    0,
                    L"BUTTON",
                    L"API Hooking!",
                    WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                    835,
                    197, 
                    130, 
                    35,
                    hWnd,
                    (HMENU)ID_BUTTON, //样式设置与否都可以，实际上没有用到
                    GetModuleHandle(NULL),
                    NULL
                );

            }
            break;

        /* ===================================== 接受注入到目标进程的DLL返回的Hooked API数据 ================================*/
        case WM_HOOKED_MESSAGE:
            {
                AppendTextToTextBox2("Hooked API被调用了！\r\n=============================\r\n");

                AppendTextToTextBox2("获取到的文本为：");
                AppendTextToTextBox2(GetTextFromClipboard());
                AppendTextToTextBox2("\r\n=============================\r\n");

                /*  ===================== 通过发送消息实现进程通信(NOT work, 操作系统不允许SendMessage传递指针) ================*/
                /*
                    HWND sourceHwnd = (HWND)wParam;
                    COPYDATASTRUCT* pCds = (COPYDATASTRUCT*)lParam;

                    if (pCds->cbData > 0 && pCds->lpData != nullptr)
                    {
                        const char* lpText = (const char*)pCds->lpData;

                        // 对lpText进行操作，例如输出到控制台
                        MessageBoxA(hWnd, lpText, "Received data", MB_OK);
                        // std::cout << "Received message: " << lpText << std::endl;
                    }

                    if (wParam != NULL) {
                        LPCSTR lpText = static_cast<LPCSTR>(((COPYDATASTRUCT*)lParam)->lpData);
                        // 处理收到的数据(NOT work)，此处接收不到数据，待处理
                        MessageBoxA(hWnd, lpText, "Received data", MB_OK);
                    }
                */
            }
            break;

        /* ===================================== 接收用户对窗口控件的输入，并给出相应的数据处理 ================================*/
        case WM_COMMAND:
            {
                // 处理控件的消息
                if (HIWORD(wParam) == LBN_SELCHANGE) {  // 当选择项改变时
                    HWND hListBox = (HWND)lParam;
                    int selectedIndex = SendMessage(hListBox, LB_GETCURSEL, 0, 0);  // 获取选中项的索引

                    PROCESS_MEMORY_COUNTERS_EX pmc;
                    memset(&pmc, 0, sizeof(pmc));

                    int pid = ProcessIDList[selectedIndex];

                    /* ==================================== 输出进程基本信息到文本框 ===================================== */
                    
                    pmc = PrintProcessMemoryInfo(pid);

                    WCHAR* processInfo = GetProcessInfo(pid);

                    // 获取选中项的文本
                    WCHAR buffer[256];
                    memset(&buffer, 0, sizeof(buffer));
                    SendMessage(hListBox, LB_GETTEXT, (WPARAM)selectedIndex, (LPARAM)buffer);

                    swprintf(
                        buffer,
                        L"选中的进程信息为:\r\nPID:%d\r\n进程执行路径为:%s\r\nWorking Set Size: %llu bytes\r\nPrivate Usage: %llu bytes\r\nPagefile Usage: %llu bytes\r\n",
                        pid,
                        processInfo,
                        pmc.WorkingSetSize,
                        pmc.PrivateUsage,
                        pmc.PagefileUsage
                    );

                    // 输出信息到文本框
                    SetWindowText(hwndTextBox1, buffer);
                }

                int wmId = LOWORD(wParam);
                // 分析菜单选择:
                switch (wmId)
                {
                    /*======================================= 处理按钮点击事件 ===========================================*/

                    case ID_BUTTON:
                        // 按钮被点击
                        // MessageBox(hWnd, L"按钮被点击！", L"提示", MB_OK);
                        if (HIWORD(wParam) == BN_CLICKED)
                        {
                            // 获取 ListBox 中当前选择项的索引
                            int index = SendMessage(hListBox, LB_GETCURSEL, 0, 0);
                            // 通过给ListBox句柄发送消息，以获取用户选择项的索引（即通过消息机制实现控件间的通信）

                            if (index == LB_ERR)
                            {
                                // 如果没有选择任何项，显示一个提示框
                                MessageBox(hWnd, L"请先选择要Hook的进程!", L"提示", MB_OK | MB_ICONINFORMATION);
                                break;
                            }

                            /*======================================= Hook API开始 ======================================*/

                            int pid = ProcessIDList[index];

                            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                            // 这里配置权限可以使用 | (或)运算符来将几个权限叠加起来传递，有更好的可读性

                            if (IsProcessUsingDll(hProcess, "user32.dll")) {
                                // 获取到目标函数所在的模块和地址
                                GetFunctionModuleAndAddress(hProcess, "user32.dll", "MessageBoxA", &hModule, &pFunction);
                            }

                            // 直接使用inline方式hook指定进程(NOT work)
                            // hookWinAPI(hProcess, pFunction);

                            AppendTextToTextBox2("开始将DLL注入指定进程\r\n=============================\r\n");

                            // 注意：注入的DLL文件路径很重要，应该为被注入的可执行文件的相对路径
                            if (RemoteThreadInject(pid, "HookDll.dll"))
                            {
                                AppendTextToTextBox2(L"DLL注入完成\r\n=============================\r\n");
                            }
                            else {
                                AppendTextToTextBox2(L"[ERROR] DLL注入失败\r\n=============================\r\n");
                            }

                            // Find the address of LoadLibrary in target process(same to this process)
                            // LoadLibraryW 函数位于 kernel32.dll 中，并且系统核心 DLL 会加载到固定地址，所以系统中所有进程的 LoadLibraryW 函数地址是相同的。
                            // 用 GetProcAddress 函数获取本地进程 LoadLibraryW 地址即可。


                            //ChildProcess process = ChildProcess::OpenFromHandle(hProcess);
                            //injectWithRemoteThread(process.getProcessInformation(), "HookDll.dll");

                            CloseHandle(hProcess);


                            // 在窗口中显示选中项的文本
                            // MessageBox(hWnd, buffer, L"选中项", MB_OK);

                        }
                        break;
                    case IDM_ABOUT:
                        DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                        break;
                    case IDM_UPDATE:
                        // 更新进程内容

                        // std::fill(std::begin(ProcessIDList), std::end(ProcessIDList), 0);
                        //hListBox = CreateWindowEx(0, L"LISTBOX", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_AUTOVSCROLL | LBS_NOTIFY,
                        //    10, 10, 680, 480, hWnd, (HMENU)IDC_LISTBOX, hInst, NULL);
                        
                        // 清空 ListBox 控件中的内容
                        SendMessage(hListBox, LB_RESETCONTENT, 0, 0);
                        // 获取并显示新的进程信息
                        ListProcesses(hListBox);
                        break;
                    case IDM_EXIT:
                        DestroyWindow(hWnd);
                        break;
                    default:
                        return DefWindowProc(hWnd, message, wParam, lParam);
                }
            }
            break;
        case WM_CLOSE:
            if (MessageBox(hWnd, L"Really quit?", L"Process Listener", MB_OKCANCEL) == IDOK)
            {
                DestroyWindow(hWnd);
            }
            break;
        case WM_PAINT:
            {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hWnd, &ps);
                // 设置文本颜色和字体
                SetTextColor(hdc, RGB(0, 0, 0)); // 黑色
                HFONT hFont = CreateFont(23, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                    CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"楷体");
                SelectObject(hdc, hFont);

                // 绘制文本
                WCHAR textProcessInfo[] = L"进程信息:";
                WCHAR textProcessList[] = L"进程列表:";
                WCHAR textHookInfo[] = L"获取的文本信息:";

                TextOut(hdc, 560, 10, textProcessInfo, ARRAYSIZE(textProcessInfo));
                TextOut(hdc, 5, 5, textProcessList, ARRAYSIZE(textProcessList));
                TextOut(hdc, 560, 200, textHookInfo, ARRAYSIZE(textHookInfo));


                // 清除字体资源
                DeleteObject(hFont);

                EndPaint(hWnd, &ps);
            }
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

// “关于”框的消息处理程序。
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
