#include <windows.h>
#include <tlhelp32.h>

#include "process_operations.h"
#include "common.h"
#include "privilege_guard.h"
#include <iostream>

namespace {

bool SetProcessAcl(HANDLE handle) {
    return SetRestrictiveAcl(handle, SE_KERNEL_OBJECT, PROCESS_ALL_ACCESS, PROCESS_QUERY_INFORMATION);
}

}  // namespace

DWORD FindProcessByName(const std::wstring& processName) {
    // Add .exe extension if not present
    std::wstring searchName = processName;
    if (searchName.length() < 4 || 
        _wcsicmp(searchName.substr(searchName.length() - 4).c_str(), L".exe") != 0) {
        searchName += L".exe";
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        PrintLastError(L"CreateToolhelp32Snapshot");
        return 0;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    DWORD foundPid = 0;
    int matchCount = 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, searchName.c_str()) == 0) {
                foundPid = entry.th32ProcessID;
                matchCount++;
                if (matchCount > 1) {
                    std::wcerr << L"Multiple processes found with name: " << searchName << L"\n";
                    std::wcerr << L"Please specify a process ID instead\n";
                    CloseHandle(snapshot);
                    return 0;
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);

    if (matchCount == 0) {
        std::wcerr << L"Process not found: " << searchName << L"\n";
        return 0;
    }

    std::wcout << L"Found process: " << searchName << L" (PID: " << foundPid << L")\n";
    return foundPid;
}

int ProcessProcessCommand(DWORD processId, const std::wstring& command) {
    DWORD desiredAccess = 0;
    bool requiresRestorePrivilege = false;
    
    if (command == L"terminate") {
        desiredAccess = PROCESS_TERMINATE;
    } else if (command == L"harden") {
        desiredAccess = WRITE_DAC | WRITE_OWNER;
        requiresRestorePrivilege = true; // Needed to set the owner to SYSTEM
    } else if (command == L"takeown") {
        desiredAccess = WRITE_OWNER;
    } else if (command == L"weaken") {
        desiredAccess = WRITE_DAC;
    } else {
        std::wcerr << L"Unknown process command: " << command << L"\n";
        std::wcerr << L"Valid commands: terminate, harden, takeown, weaken\n";
        return 1;
    }

    // Enable SE_DEBUG_NAME privilege for process access -- this ignoresthe DACL for the process.
    // However, it doesn't bypass integrity level, or PPL level etc.
    PrivilegeGuard debugPrivilegeGuard(SE_DEBUG_NAME);
    if (debugPrivilegeGuard.IsValid() && !debugPrivilegeGuard.IsEnabled()) {
        return 1;  // Error message already printed by PrivilegeGuard
    }

    // Enable SE_RESTORE_NAME privilege if setting owner (allows setting arbitrary owners)
    PrivilegeGuard restorePrivilegeGuard(requiresRestorePrivilege ? SE_RESTORE_NAME : nullptr);
    if (restorePrivilegeGuard.IsValid() && !restorePrivilegeGuard.IsEnabled()) {
        return 1;  // Error message already printed by PrivilegeGuard
    }

    std::wcout << L"Opening process: " << processId << L" with permissions: 0x" << std::hex << desiredAccess << std::dec << L"\n";

    HANDLE processHandle = OpenProcess(desiredAccess, FALSE, processId);
    if (!processHandle || processHandle == INVALID_HANDLE_VALUE) {
        PrintLastError(L"OpenProcess");
        return 1;
    }

    bool success = false;
    if (command == L"terminate") {
        success = TerminateProcess(processHandle, 1) != 0;
        if (success) {
            std::wcout << L"Process terminated successfully\n";
        } else {
            PrintLastError(L"TerminateProcess");
        }
    } else if (command == L"harden") {
        success = SetProcessAcl(processHandle);
        if (success) {
            std::wcout << L"Process ACL hardened successfully\n";
        }
    } else if (command == L"takeown") {
        DWORD result = TakeOwnership(processHandle, SE_KERNEL_OBJECT);
        success = (result == ERROR_SUCCESS);
        if (success) {
            std::wcout << L"Process ownership transferred to Administrators\n";
        }
    } else if (command == L"weaken") {
        success = WeakenAcl(processHandle, SE_KERNEL_OBJECT, PROCESS_ALL_ACCESS);
        if (success) {
            std::wcout << L"Process ACL weakened successfully (Everyone has full access)\n";
        }
    }

    CloseHandle(processHandle);
    return success ? 0 : 1;
}
