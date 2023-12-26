#define _CRT_SECURE_NO_WARNINGS 1
#include <iostream>
#include <Windows.h>
#include "../HookDll/HookDll.h"
#include <fstream>


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


int main()
{
    ReadFromSharedMemory();
    /*
    MessageBoxA(NULL, "Hi", "test", MB_OK);
    HookAPI();
    MessageBoxA(NULL, "Hi", "test11", MB_OK);
    */
    return 0;
}
