#define _CRT_SECURE_NO_WARNINGS 1
#define _CRT_NON_CONFORMING_SWPRINTFS 1

#include <Windows.h>
#include <iostream>
const UINT WM_HOOKED_MESSAGE = WM_APP + 1; // �Զ�����Ϣ


void SendCustomMessage()
{
    HWND targetHwnd = FindWindow(NULL, L"ProcessHooker"); // ���ݴ��ڱ������Ŀ�괰�ھ��
    if (targetHwnd != NULL) {
        COPYDATASTRUCT cds = { 0 };
        cds.dwData = 0; // �Զ�������
        cds.cbData = strlen("test") + 1; // �ַ�������
        cds.lpData = (LPVOID)"test"; // �ַ�������

        SendMessage(targetHwnd, WM_HOOKED_MESSAGE, 0, 0); // ������Ϣ
        // ��������(NOT work)���˴����ղ������ݣ�������
        // MessageBoxA(NULL, "������Ϣ���", "Hooker", MB_OK);
    }
}

void CALLBACK CompletionRoutine(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped);


#define BUFSIZE 512


int main()
{
    DWORD dwWritten;
    WCHAR buffer[512];

    HANDLE hPipe = CreateNamedPipe(
        L"\\\\.\\pipe\\MyPipe",
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 1024, 1024, 0, NULL);

    if (hPipe == INVALID_HANDLE_VALUE)
    {
        std::cerr << "Failed to create named pipe" << std::endl;
        return 1;
    }

    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    ConnectNamedPipe(hPipe, &overlapped);

    printf("Connected to named pipe.\n");

    SendCustomMessage();

    // �������ܵ�д������
    swprintf(buffer, L"Hello from the pipe!");
    if (WriteFile(hPipe, buffer, BUFSIZE, &dwWritten, NULL))
    {
        printf("Data written to pipe: %s\n", buffer);
    }


    while (true)
    {
        DWORD dwWaitResult = WaitForSingleObject(overlapped.hEvent, INFINITE);
        switch (dwWaitResult)
        {
            case WAIT_OBJECT_0:
                // �����ѽ���
                std::cout << "Client connected" << std::endl;
                break;
            case WAIT_FAILED:
                std::cerr << "WaitForSingleObject failed" << std::endl;
                break;
            default:
                std::cerr << "Unexpected result from WaitForSingleObject" << std::endl;
                break;
        }
        break;
    }

    CloseHandle(hPipe);
    CloseHandle(overlapped.hEvent);

    return 0;
}

void CALLBACK CompletionRoutine(DWORD dwErrorCode, DWORD dwNumberOfBytesTransfered, LPOVERLAPPED lpOverlapped)
{
    if (dwErrorCode == 0)
    {
        // �����ѽ���
        std::cout << "Client connected" << std::endl;
    }
    else
    {
        std::cerr << "Asynchronous connection failed with error code: " << dwErrorCode << std::endl;
    }
}
