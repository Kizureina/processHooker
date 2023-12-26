#pragma once
#include <Windows.h>
#include <iostream>
// ����ע���DLL�뱾����ͨ��
const UINT WM_HOOKED_MESSAGE = WM_APP + 1; // �Զ�����Ϣ


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


//���������ڴ����
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
	//��buffer�е����ݿ����������ڴ�
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


//�����ӽ��̵���
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

	// Ĭ�Ϲ��캯��
	ChildProcess()
	{
		ZeroMemory(&pi, sizeof(pi));  // ���߽�������Ĭ�ϳ�ʼ������
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

	// ���캯������������֮���ֹ�������ƶ�
	ChildProcess(ChildProcess&&) = default;  // �ñ���������Ĭ�ϵ��ƶ����캯��
	ChildProcess(const ChildProcess&) = delete;
	ChildProcess& operator=(const ChildProcess&) = delete;
	// ChildProcess(ChildProcess&&) = delete;
	ChildProcess& operator=(ChildProcess&&) = delete;
};
