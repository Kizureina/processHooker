#pragma once
#ifdef HOOKDLL_API
#else
#define HOOKDLL_API extern "C" _declspec(dllimport)
#endif
#include "pch.h"
#include <iostream>

FARPROC getLibraryProcAddress(LPCSTR libName, LPCSTR procName)
{
	auto dllModule = LoadLibraryA(libName);
	if (dllModule == NULL) {
		throw std::runtime_error("Unable to load library!");
	}
	auto procAddress = GetProcAddress(dllModule, procName);
	if (procAddress == NULL) {
		throw std::runtime_error("Unable to get proc address!");
	}
	return procAddress;
}

//用于将地址转换为byte数组的类，其实用union也可以办到，
//不过是C++的未定义行为，所以这里写了一个转换类
class Address
{
private:
	enum { SIZE = 4 };
	BYTE bytes[SIZE];
public:
	const BYTE operator[](int i) const
	{
		return bytes[i];
	}
	Address(LPVOID address)
	{
		memcpy(bytes, &address, SIZE);
	}
	Address(DWORD address)
	{
		memcpy(bytes, &address, SIZE);
	}
};


class HookManager
{
	enum { SHELLCODE_SIZE = 5 };
private:
	LPVOID targetFuncAddr;
	LPVOID hookFuncAddr;
	BYTE originalBytes[SHELLCODE_SIZE];
	BYTE shellCode[SHELLCODE_SIZE];
	DWORD oldProtect = 0;
public:
	// 参数是目标函数地址targetFuncAddress，我们自己的hook函数的地址HookFuncAddress
	explicit HookManager(PVOID targetFuncAddress, PVOID hookFuncAddress)
		:targetFuncAddr(targetFuncAddress), hookFuncAddr(hookFuncAddress)
	{
		// 计算相对偏移生成shellcode
		Address offset((DWORD)hookFuncAddress - ((DWORD)targetFuncAddress + 5));
		BYTE tempShellCode[SHELLCODE_SIZE] = {
			0xE9, offset[0], offset[1], offset[2], offset[3],
		};
		memcpy(shellCode, tempShellCode, SHELLCODE_SIZE);

		//保存原有的字节，需要先把目标函数的虚拟内存设置为可读写
		VirtualProtect(targetFuncAddr, SHELLCODE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy(originalBytes, targetFuncAddr, SHELLCODE_SIZE);
	}
	void hook()
	{
		//将shellcode写入目标函数来hook
		memcpy(targetFuncAddr, shellCode, SHELLCODE_SIZE);
	}
	void unhook()
	{
		//恢复原先的字节来unhook
		memcpy(targetFuncAddr, originalBytes, SHELLCODE_SIZE);
	}
	~HookManager()
	{
		//析构时将目标函数的虚拟内存的保护属性恢复
		VirtualProtect(targetFuncAddr, SHELLCODE_SIZE, oldProtect, &oldProtect);
	}
};


/*
HOOKDLL_API int _stdcall HookedMessageBox(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
HOOKDLL_API int _stdcall HookAPI();
HOOKDLL_API int _stdcall UnHook();

*/