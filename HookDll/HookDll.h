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

//���ڽ���ַת��Ϊbyte������࣬��ʵ��unionҲ���԰쵽��
//������C++��δ������Ϊ����������д��һ��ת����
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
	// ������Ŀ�꺯����ַtargetFuncAddress�������Լ���hook�����ĵ�ַHookFuncAddress
	explicit HookManager(PVOID targetFuncAddress, PVOID hookFuncAddress)
		:targetFuncAddr(targetFuncAddress), hookFuncAddr(hookFuncAddress)
	{
		// �������ƫ������shellcode
		Address offset((DWORD)hookFuncAddress - ((DWORD)targetFuncAddress + 5));
		BYTE tempShellCode[SHELLCODE_SIZE] = {
			0xE9, offset[0], offset[1], offset[2], offset[3],
		};
		memcpy(shellCode, tempShellCode, SHELLCODE_SIZE);

		//����ԭ�е��ֽڣ���Ҫ�Ȱ�Ŀ�꺯���������ڴ�����Ϊ�ɶ�д
		VirtualProtect(targetFuncAddr, SHELLCODE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy(originalBytes, targetFuncAddr, SHELLCODE_SIZE);
	}
	void hook()
	{
		//��shellcodeд��Ŀ�꺯����hook
		memcpy(targetFuncAddr, shellCode, SHELLCODE_SIZE);
	}
	void unhook()
	{
		//�ָ�ԭ�ȵ��ֽ���unhook
		memcpy(targetFuncAddr, originalBytes, SHELLCODE_SIZE);
	}
	~HookManager()
	{
		//����ʱ��Ŀ�꺯���������ڴ�ı������Իָ�
		VirtualProtect(targetFuncAddr, SHELLCODE_SIZE, oldProtect, &oldProtect);
	}
};


/*
HOOKDLL_API int _stdcall HookedMessageBox(HWND hwnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
HOOKDLL_API int _stdcall HookAPI();
HOOKDLL_API int _stdcall UnHook();

*/