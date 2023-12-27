// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <iostream>
#include "HookDll.h"
#include <fstream>

void UnHook();

const UINT WM_HOOKED_MESSAGE = WM_APP + 1; // 自定义消息

/*============================================ 通过写入共享内存数据实现进程通信(NOT Work) =========================================*/

// 共享内存区域的名称
const char* sharedMemoryName = "MySharedMemory";

// 数据结构
struct MyData {
    int value;
    char message[256];
};

void WriteToSharedMemory(LPCSTR lpText) {
    // 创建或打开共享内存区域
    HANDLE hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(MyData), sharedMemoryName);
    if (hMapFile == NULL) {
        std::cout << "Failed to create or open shared memory: " << GetLastError() << std::endl;
        return;
    }

    // 获取共享内存的指针
    LPVOID pSharedMemory = MapViewOfFile(hMapFile, FILE_MAP_WRITE, 0, 0, sizeof(MyData));
    if (pSharedMemory == NULL) {
        std::cout << "Failed to map view of shared memory: " << GetLastError() << std::endl;
        CloseHandle(hMapFile);
        return;
    }

    // 写入数据到共享内存
    MyData* pData = static_cast<MyData*>(pSharedMemory);
    pData->value = 123;
    strcpy_s(pData->message, lpText);

    // 解除映射和关闭句柄
    UnmapViewOfFile(pSharedMemory);
    CloseHandle(hMapFile);
}


/*============================= 通过写入指定文件数据实现进程通信(Work, but actually not been used) ===========================*/

void writeText2File(LPCSTR lpText) {
    std::ofstream myfile("example.txt"); // 新建文件example.txt，以写入模式打开
    if (myfile.is_open()) { // 检查文件是否成功打开
        myfile << "This is a new file." << std::endl; // 向文件中输出字符串
        myfile.close(); // 关闭文件
        std::cout << "File created and text written to it." << std::endl;
    }
    else {
        std::cout << "Failed to create file." << std::endl;
    }
}


/*============================= 通过写入剪切板数据实现进程通信(Work) ===========================*/


void CopyTextToClipboard(const wchar_t* text)
{
    // 打开剪贴板
    if (OpenClipboard(nullptr))
    {
        // 清空剪贴板
        EmptyClipboard();

        // 分配全局内存
        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, (wcslen(text) + 1) * sizeof(wchar_t));
        if (hMem)
        {
            // 锁定内存并写入数据
            wchar_t* pMem = static_cast<wchar_t*>(GlobalLock(hMem));
            wcscpy_s(pMem, wcslen(text) + 1, text);
            GlobalUnlock(hMem);

            // 将数据放入剪贴板
            SetClipboardData(CF_UNICODETEXT, hMem);
        }

        // 关闭剪贴板
        CloseClipboard();
    }
}


/* ============================================ 宽字符与一般字符相互转换(NOT work) ====================================*/

WCHAR* ConvertToWideChar(const char* str)
{
    int length = strlen(str) + 1;

    // 获取所需的缓冲区大小
    int bufferSize = MultiByteToWideChar(CP_UTF8, 0, str, length, nullptr, 0);

    // 分配缓冲区
    WCHAR* wideStr = new WCHAR[bufferSize];

    // 执行转换
    MultiByteToWideChar(CP_UTF8, 0, str, length, wideStr, bufferSize);

    return wideStr;
}


/* ============================================= 向主窗口进程发送消息 ============================================*/

void SendCustomMessage(LPCWSTR lpText)
{
    HWND targetHwnd = FindWindow(NULL, L"ProcessHooker"); // 根据窗口标题查找目标窗口句柄
    if (targetHwnd != NULL) {

        // WCHAR buffer[] = L"Hello world";
        // 将Hook到的数据写入剪切板（x86字符）
        CopyTextToClipboard(lpText);

        COPYDATASTRUCT cds = { 0 };
        cds.dwData = 0; // 自定义数据
        cds.cbData = strlen("test") + 1; // 字符串长度
        cds.lpData = (LPVOID)"test"; // 字符串数据

        SendMessage(targetHwnd, WM_HOOKED_MESSAGE, 0, 0); // 发送消息
        // 发送数据(NOT work)，此处接收不到数据，待处理
        // MessageBoxA(NULL, "发送消息完成", "Hooker", MB_OK);
    }
}


FARPROC pFunction = NULL;
SIZE_T bytesWritten = 0;
char messageBoxOriginalBytes[6] = {};


int __stdcall HookedMessageBox(HWND hwnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {

    // std::cout << "Ohai from the hooked function\n";
    // std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << std::endl;
    
    // SetWindowText(hwndTextBox2, lpText);
    UnHook();
    // MessageBoxA(NULL, lpText, "GET IT", MB_OK);

    /*==================================== 通过向指定窗口进程发送消息实现进程通信(Work) =================================*/
    SendCustomMessage(lpText);

    /*
    HWND targetHwnd = FindWindow(NULL, L"ProcessHooker"); // 根据窗口标题查找目标窗口句柄
    if (targetHwnd != NULL) {

        CopyTextToClipboard((LPCWSTR)lpText);

        COPYDATASTRUCT cds = { 0 };
        cds.dwData = 0; // 自定义数据
        cds.cbData = strlen(lpText) + 1; // 字符串长度
        cds.lpData = (LPVOID)lpText; // 字符串数据

        SendMessage(targetHwnd, WM_HOOKED_MESSAGE, 0, (LPARAM)&cds); // 发送消息
        // 发送数据(NOT work)，此处接收不到数据，待处理
        // MessageBoxA(NULL, "发送消息完成", "Hooker", MB_OK);
    }
    */

    // call the original MessageBoxA
    return MessageBoxW(NULL, lpText, lpCaption, uType);
}


/*
int __stdcall HookedMessageBox(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

    // print intercepted values from the MessageBoxA function
    std::cout << "Ohai from the hooked function\n";
    std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << std::endl;
    // SetWindowText(hwndTextBox2, lpText);

    MessageBoxA(NULL, lpText, "GET IT", MB_OK);

    // call the original MessageBoxA
    return MessageBoxA(NULL, lpText, lpCaption, uType);
}
*/


void HookAPI() {
    pFunction = getLibraryProcAddress("user32.dll", "MessageBoxW");
    SIZE_T bytesRead = 0;

    // save the first 6 bytes of the original MessageBoxA function - will need for unhooking
    ReadProcessMemory(GetCurrentProcess(), pFunction, messageBoxOriginalBytes, 6, &bytesRead);

    // create a patch "push <address of new MessageBoxA); ret"
    // 作用即为jmp &hookedAPI，但直接用jmp需要计算偏移量，所以用堆栈实现
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


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            MessageBoxW(NULL, L"DLL inject success!", L"Congratulations", MB_OK);
            HookAPI();
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

