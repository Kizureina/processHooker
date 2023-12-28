// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

// dll inject demo source code
#include <Windows.h>

// 在DLL中的全局变量，用于标记Hook是否已经初始化
bool g_bHookInitialized = false;

// Hook的函数指针，用于保存原始API函数的地址
typedef int(WINAPI* MessageBoxWPtr)(HWND, LPCWSTR, LPCWSTR, UINT);
MessageBoxWPtr g_pOrigMessageBoxW = nullptr;

// 自定义的Hook函数
int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
    // 在这里执行自定义的Hook操作
    // ...
    g_pOrigMessageBoxW(hWnd, lpText, L"Hooker GET IT!", uType);

    // 调用原始API函数，保持Hook的持续性
    if (g_pOrigMessageBoxW)
    {
        return g_pOrigMessageBoxW(hWnd, lpText, lpCaption, uType);
    }

    // 如果原始API函数指针为空，可能发生了一些错误，你需要处理这种情况
    return 0;
}

// 导出的函数，用于启动或停止Hook
extern "C" __declspec(dllexport) void StartHook()
{
    if (!g_bHookInitialized)
    {
        // 进行API Hook的初始化操作，保存原始API函数地址等
        g_pOrigMessageBoxW = reinterpret_cast<MessageBoxWPtr>(GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxW"));

        // 替换原始API函数地址为你的Hook函数
        if (g_pOrigMessageBoxW)
        {
            DWORD dwOldProtect;
            VirtualProtect(g_pOrigMessageBoxW, sizeof(g_pOrigMessageBoxW), PAGE_EXECUTE_READWRITE, &dwOldProtect);
            g_pOrigMessageBoxW = reinterpret_cast<MessageBoxWPtr>(InterlockedExchangePointer((PVOID*)&g_pOrigMessageBoxW, (PVOID)MyMessageBoxW));
            VirtualProtect(g_pOrigMessageBoxW, sizeof(g_pOrigMessageBoxW), dwOldProtect, &dwOldProtect);
        }

        g_bHookInitialized = true;
    }
}

extern "C" __declspec(dllexport) void StopHook()
{
    if (g_bHookInitialized)
    {
        // 恢复原始API函数地址
        if (g_pOrigMessageBoxW)
        {
            DWORD dwOldProtect;
            VirtualProtect(g_pOrigMessageBoxW, sizeof(g_pOrigMessageBoxW), PAGE_EXECUTE_READWRITE, &dwOldProtect);
            g_pOrigMessageBoxW = reinterpret_cast<MessageBoxWPtr>(InterlockedExchangePointer((PVOID*)&g_pOrigMessageBoxW, (PVOID)g_pOrigMessageBoxW));
            VirtualProtect(g_pOrigMessageBoxW, sizeof(g_pOrigMessageBoxW), dwOldProtect, &dwOldProtect);
        }

        g_bHookInitialized = false;
    }
}

// DllMain 函数
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        // 在DLL加载时，进行初始化
        MessageBoxW(NULL, L"加载成功", L"Hooker GET IT!", MB_OK);

        StartHook();
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH)
    {
        // 在DLL卸载时，进行清理工作
        StopHook();
    }

    return TRUE;
}


