#pragma once
#include <Windows.h>
#include <iostream>
// 用于注入的DLL与本进程通信
const UINT WM_HOOKED_MESSAGE = WM_APP + 1; // 自定义消息


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


//管理虚拟内存的类
class VirtualMemory
{
private:
	LPVOID address;
public:
	const HANDLE process;
	const SIZE_T size;
	const DWORD protectFlag;
	explicit VirtualMemory(HANDLE hProcess, SIZE_T dwSize, DWORD flProtect) :
		process(hProcess), size(dwSize), protectFlag(flProtect)
	{
		address = VirtualAllocEx(process, NULL, size, MEM_COMMIT, protectFlag);
		if (address == NULL)
			throw std::runtime_error("Failed to allocate virtual memory!");
	}
	~VirtualMemory()
	{
		if (address != NULL)
			VirtualFreeEx(process, address, 0, MEM_RELEASE);
	}
	//将buffer中的内容拷贝到虚拟内存
	BOOL copyFromBuffer(LPCVOID buffer, SIZE_T size)
	{
		if (size > this->size)
			return FALSE;
		return WriteProcessMemory(process, address, buffer, size, NULL);
	}
	LPVOID getAddress()
	{
		return address;
	}
};


//管理子进程的类
class ChildProcess
{
private:
	PROCESS_INFORMATION pi;
public:
	explicit ChildProcess(LPCSTR applicationPath, DWORD creationFlags)
	{
		ZeroMemory(&pi, sizeof(pi));
		if (!CreateProcessA(applicationPath,
			NULL, NULL, NULL, FALSE, creationFlags, NULL, NULL,
			NULL, &pi))
		{
			throw std::runtime_error("Failed to create child process!");
		}
	}

	// 默认构造函数
	ChildProcess()
	{
		ZeroMemory(&pi, sizeof(pi));  // 或者进行其他默认初始化操作
	}


	static ChildProcess OpenFromHandle(HANDLE hProcess)
	{
		ChildProcess cp;
		cp.pi.hProcess = hProcess;
		cp.pi.dwProcessId = GetProcessId(hProcess);
		cp.pi.hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, cp.pi.dwThreadId);
		return cp;
	}

	PROCESS_INFORMATION& getProcessInformation()
	{
		return pi;
	}

	~ChildProcess()
	{
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	// 构造函数和析构函数之外禁止拷贝和移动
	ChildProcess(ChildProcess&&) = default;  // 让编译器生成默认的移动构造函数
	ChildProcess(const ChildProcess&) = delete;
	ChildProcess& operator=(const ChildProcess&) = delete;
	// ChildProcess(ChildProcess&&) = delete;
	ChildProcess& operator=(ChildProcess&&) = delete;
};
