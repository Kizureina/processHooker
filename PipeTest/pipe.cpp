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

int main1()
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

#include <windows.h>
#include <iostream>

// ���ڱ���Ŀ�괰�ھ����ȫ�ֱ���
HWND targetWindowHandle = NULL;

// �ص���������ö�ٴ���
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
    // ��ȡ�����������̵�PID
    DWORD processId;
    GetWindowThreadProcessId(hWnd, &processId);

    // �Ƚ�PID�Ƿ�ƥ��
    if (processId == (DWORD)lParam)
    {
        // �ҵ�Ŀ�괰�ڣ���������ֹͣö��
        targetWindowHandle = hWnd;
        return FALSE;
    }

    return TRUE;
}

// ���ݽ���PID��ȡĿ�괰�ھ��
HWND GetTargetWindowHandleByPID(DWORD targetPID)
{
    targetWindowHandle = NULL;
    EnumWindows(EnumWindowsProc, (LPARAM)targetPID);
    return targetWindowHandle;
}

// ���ͻس�����Ϣ
void SendEnterKeyMessage(HWND hWnd)
{
    SendMessage(hWnd, WM_KEYDOWN, VK_RETURN, 0);  // ģ�ⰴ�»س���
    SendMessage(hWnd, WM_KEYUP, VK_RETURN, 0);    // ģ���ͷŻس���
}

// ���������������Ϣ
void SendMouseLeftClick(HWND hWnd, int x, int y)
{
    LPARAM lParam = MAKELPARAM(x, y);  // ��������������

    // ģ����갴�º��ͷŵ���Ϣ
    PostMessage(hWnd, WM_LBUTTONDOWN, MK_LBUTTON, lParam);
    PostMessage(hWnd, WM_LBUTTONUP, 0, lParam);
}

int main()
{
    DWORD targetPID = 24028; // Ŀ����̵�PID���滻Ϊʵ�ʵ�PID

    // ��ȡĿ�괰�ھ��
    HWND targetWindowHandle = GetTargetWindowHandleByPID(targetPID);

    if (targetWindowHandle != NULL)
    {
        SendEnterKeyMessage(targetWindowHandle);
        SendMouseLeftClick(targetWindowHandle, 50, 50);
        std::cout << "���ͳɹ�!" << std::endl;
    }
    else
    {
        std::cout << "δ�ҵ�Ŀ�괰��" << std::endl;
    }

    return 0;
}
