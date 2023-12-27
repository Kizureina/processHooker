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
    std::ofstream myfile("example.txt"); // �½��ļ�example.txt����д��ģʽ��
    if (myfile.is_open()) { // ����ļ��Ƿ�ɹ���
        myfile << lpText << std::endl; // ���ļ�������ַ���
        myfile.close(); // �ر��ļ�
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

    //MessageBoxA(NULL, "д�빲���ڴ�ɹ���", "Hooker GET IT!!", MB_OK);
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
    memcpy_s(patch + 1, 4, &hookedMessageBoxAddress, 4); //32λ��ַΪ4�ֽڳ���
    memcpy_s(patch + 5, 1, "\xC3", 1); //ret

    // patch the MessageBoxA
    if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)pFunction, patch, sizeof(patch), &bytesWritten)) {
        DWORD dwError = GetLastError();
        // ��dwErrorΪ5ʱ��˵��д��������ݵ����󱻾ܾ�����ΪȨ�޻��߰�ȫ����
    }
}


void UnHook() {
    // unpatch MessageBoxA
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)pFunction, messageBoxOriginalBytes, sizeof(messageBoxOriginalBytes), &bytesWritten);
}



/* ================================= ���Զ�ȡ�����ڴ�ռ������ ==================================*/

// �����ڴ����������
const char* sharedMemoryName = "MySharedMemory";

// ���ݽṹ��ʾ����
struct MyData {
    int value;
    char message[256];
};

void ReadFromSharedMemory() {
    // �򿪹����ڴ�����
    HANDLE hMapFile = OpenFileMappingA(FILE_MAP_READ, FALSE, sharedMemoryName);
    if (hMapFile == NULL) {
        std::cout << "Failed to open shared memory: " << GetLastError() << std::endl;
        return;
    }

    // ��ȡ�����ڴ��ָ��
    LPVOID pSharedMemory = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, sizeof(MyData));
    if (pSharedMemory == NULL) {
        std::cout << "Failed to map view of shared memory: " << GetLastError() << std::endl;
        CloseHandle(hMapFile);
        return;
    }

    // ��ȡ���ݴӹ����ڴ�
    MyData* pData = static_cast<MyData*>(pSharedMemory);
    std::cout << "Value: " << pData->value << std::endl;
    std::cout << "Message: " << pData->message << std::endl;

    // ���ӳ��͹رվ��
    UnmapViewOfFile(pSharedMemory);
    CloseHandle(hMapFile);
}

/* ============================================= ����ͨ��Զ���߳�ʵ��DLLע�� ==============================================*/

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
    // ��Ŀ�����
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, targetProcessId);
    if (hProcess == NULL)
    {
        // ����򿪽���ʧ�ܵ����
        return false;
    }

    // ��Ŀ������з����ڴ�
    size_t dllPathLength = strlen(dllPath) + 1;
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, dllPathLength, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteMemory == NULL)
    {
        // �����ڴ����ʧ�ܵ����
        CloseHandle(hProcess);
        return false;
    }

    // ��DLL·��д��Ŀ����̵��ڴ���
    SIZE_T bytesRead;
    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath, dllPathLength, &bytesRead) || bytesRead != dllPathLength)
    {
        // ����д���ڴ�ʧ�ܵ����
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // ��ȡLoadLibrary������ַ
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibrary == NULL)
    {
        // �����ȡLoadLibrary������ַʧ�ܵ����
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // ��Ŀ������д���Զ���߳�ִ��LoadLibrary����
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibrary), pRemoteMemory, 0, NULL);
    if (hRemoteThread == NULL)
    {
        // ������Զ���߳�ʧ�ܵ����
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // �ȴ�Զ���߳̽���
    WaitForSingleObject(hRemoteThread, INFINITE);

    // �رվ��
    CloseHandle(hRemoteThread);

    // �ͷ��ڴ�
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);

    // �رս��̾��
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
        printf("ע��ɹ���\n");
    }
    return 0;
}
