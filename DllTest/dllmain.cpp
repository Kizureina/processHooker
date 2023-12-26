// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

// dll inject demo source code
#include <Windows.h>
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
#ifdef _AMD64_
        // 64-bit dll
        MessageBoxW(NULL, L"x64 dll load ok", L"", MB_OK);
#else
        // 32-bit dll
        MessageBoxW(NULL, L"x86 dll load ok", L"", MB_OK);
#endif
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

