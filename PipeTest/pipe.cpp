#define _CRT_SECURE_NO_WARNINGS 1
#define _CRT_NON_CONFORMING_SWPRINTFS 1

#include <Windows.h>
#include <iostream>
const UINT WM_HOOKED_MESSAGE = WM_APP + 1; // 自定义消息


void SendCustomMessage()
{
    HWND targetHwnd = FindWindow(NULL, L"ProcessHooker"); // 根据窗口标题查找目标窗口句柄
    if (targetHwnd != NULL) {
        COPYDATASTRUCT cds = { 0 };
        cds.dwData = 0; // 自定义数据
        cds.cbData = strlen("test") + 1; // 字符串长度
        cds.lpData = (LPVOID)"test"; // 字符串数据

        SendMessage(targetHwnd, WM_HOOKED_MESSAGE, 0, 0); // 发送消息
        // 发送数据(NOT work)，此处接收不到数据，待处理
        // MessageBoxA(NULL, "发送消息完成", "Hooker", MB_OK);
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

    // 向命名管道写入数据
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
                // 连接已建立
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
        // 连接已建立
        std::cout << "Client connected" << std::endl;
    }
    else
    {
        std::cerr << "Asynchronous connection failed with error code: " << dwErrorCode << std::endl;
    }
}

#include <windows.h>
#include <iostream>

// 用于保存目标窗口句柄的全局变量
HWND targetWindowHandle = NULL;

// 回调函数用于枚举窗口
BOOL CALLBACK EnumWindowsProc(HWND hWnd, LPARAM lParam)
{
    // 获取窗口所属进程的PID
    DWORD processId;
    GetWindowThreadProcessId(hWnd, &processId);

    // 比较PID是否匹配
    if (processId == (DWORD)lParam)
    {
        // 找到目标窗口，保存句柄并停止枚举
        targetWindowHandle = hWnd;
        return FALSE;
    }

    return TRUE;
}

// 根据进程PID获取目标窗口句柄
HWND GetTargetWindowHandleByPID(DWORD targetPID)
{
    targetWindowHandle = NULL;
    EnumWindows(EnumWindowsProc, (LPARAM)targetPID);
    return targetWindowHandle;
}

// 发送回车键消息
void SendEnterKeyMessage(HWND hWnd)
{
    SendMessage(hWnd, WM_KEYDOWN, VK_RETURN, 0);  // 模拟按下回车键
    SendMessage(hWnd, WM_KEYUP, VK_RETURN, 0);    // 模拟释放回车键
}

// 发送鼠标左键点击消息
void SendMouseLeftClick(HWND hWnd, int x, int y)
{
    LPARAM lParam = MAKELPARAM(x, y);  // 构造鼠标坐标参数

    // 模拟鼠标按下和释放的消息
    PostMessage(hWnd, WM_LBUTTONDOWN, MK_LBUTTON, lParam);
    PostMessage(hWnd, WM_LBUTTONUP, 0, lParam);
}

int main()
{
    DWORD targetPID = 24028; // 目标进程的PID，替换为实际的PID

    // 获取目标窗口句柄
    HWND targetWindowHandle = GetTargetWindowHandleByPID(targetPID);

    if (targetWindowHandle != NULL)
    {
        SendEnterKeyMessage(targetWindowHandle);
        SendMouseLeftClick(targetWindowHandle, 50, 50);
        std::cout << "发送成功!" << std::endl;
    }
    else
    {
        std::cout << "未找到目标窗口" << std::endl;
    }

    return 0;
}
