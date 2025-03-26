#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <string>

HWND FindREPOGameWindow() {
    HWND hWnd = NULL;
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        wchar_t title[256];
        GetWindowTextW(hwnd, title, sizeof(title) / sizeof(wchar_t));
        if (wcslen(title) == 0) return TRUE;

        if (wcscmp(title, L"R.E.P.O.") == 0) {
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);

            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (hProc) {
                wchar_t exeName[MAX_PATH] = { 0 };
                GetModuleBaseNameW(hProc, NULL, exeName, MAX_PATH);
                CloseHandle(hProc);

                if (_wcsicmp(exeName, L"REPO.exe") == 0) {
                    *((HWND*)lParam) = hwnd;
                    return FALSE;
                }
            }
        }
        return TRUE;
        }, (LPARAM)&hWnd);
    return hWnd;
}

int main() {
    std::wcout << L"[+] Searching for game window titled: R.E.P.O." << std::endl;

    HWND hWnd = FindREPOGameWindow();
    if (!hWnd) {
        std::wcerr << L"[!] Game window not found or not owned by REPO.exe." << std::endl;
        return 1;
    }

    DWORD targetThreadId = GetWindowThreadProcessId(hWnd, NULL);
    if (!targetThreadId) {
        std::wcerr << L"[!] Failed to get thread ID from game window." << std::endl;
        return 1;
    }

    std::wcout << L"[+] Found target thread ID: " << targetThreadId << std::endl;

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    std::wstring fullPath(exePath);
    size_t lastSlash = fullPath.find_last_of(L"\\/");
    std::wstring folder = fullPath.substr(0, lastSlash);
    std::wstring dllPath = folder + L"\\MonoLoader.dll";

    std::wcout << L"[+] MonoLoader.dll path: " << dllPath << std::endl;

    HMODULE hLocalDll = LoadLibraryW(dllPath.c_str());
    if (!hLocalDll) {
        std::wcerr << L"[!] Failed to load MonoLoader.dll. Error: " << GetLastError() << std::endl;
        return 1;
    }

    HOOKPROC hookProc = (HOOKPROC)GetProcAddress(hLocalDll, "HookProc");
    if (!hookProc) {
        std::wcerr << L"[!] Failed to find HookProc. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::wcout << L"[+] Setting WH_GETMESSAGE hook..." << std::endl;

    HHOOK hook = SetWindowsHookExW(WH_GETMESSAGE, hookProc, hLocalDll, targetThreadId);
    if (!hook) {
        std::wcerr << L"[!] Failed to set hook. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::wcout << L"[+] Hook set successfully. Triggering message..." << std::endl;

    PostThreadMessageW(targetThreadId, WM_NULL, 0, 0);

    Sleep(1000);

    std::wcout << L"[+] Unhooking and exiting." << std::endl;
    UnhookWindowsHookEx(hook);
    return 0;
}
