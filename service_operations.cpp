#include "service_operations.h"
#include "common.h"
#include "privilege_guard.h"
#include <windows.h>
#include <iostream>

namespace {

bool SetServiceAcl(SC_HANDLE serviceHandle) {
    return SetRestrictiveAcl(serviceHandle, SE_SERVICE, SERVICE_ALL_ACCESS, GENERIC_READ);
}

bool QueryServiceState(SC_HANDLE serviceHandle) {
    SERVICE_STATUS_PROCESS statusInfo = {};
    DWORD bytesNeeded = 0;

    if (!QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, 
                             reinterpret_cast<LPBYTE>(&statusInfo), 
                             sizeof(statusInfo), &bytesNeeded)) {
        PrintLastError(L"QueryServiceStatusEx");
        return false;
    }

    std::wcout << L"Service state: ";
    switch (statusInfo.dwCurrentState) {
        case SERVICE_STOPPED:
            std::wcout << L"Stopped\n";
            break;
        case SERVICE_START_PENDING:
            std::wcout << L"Starting...\n";
            break;
        case SERVICE_STOP_PENDING:
            std::wcout << L"Stopping...\n";
            break;
        case SERVICE_RUNNING:
            std::wcout << L"Running\n";
            break;
        case SERVICE_CONTINUE_PENDING:
            std::wcout << L"Continue pending...\n";
            break;
        case SERVICE_PAUSE_PENDING:
            std::wcout << L"Pause pending...\n";
            break;
        case SERVICE_PAUSED:
            std::wcout << L"Paused\n";
            break;
        default:
            std::wcout << L"Unknown (0x" << std::hex << statusInfo.dwCurrentState << std::dec << L")\n";
            break;
    }

    return true;
}

}  // namespace

int ProcessServiceCommand(const std::wstring& serviceName, const std::wstring& command) {
    bool requiresTakeOwnership = false;
    bool requiresRestorePrivilege = false;
    DWORD desiredAccess = 0;
    
    if (command == L"start" || command == L"stop") {
        desiredAccess = SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS;
    } else if (command == L"harden") {
        desiredAccess = WRITE_DAC | WRITE_OWNER;
        requiresRestorePrivilege = true;  // Needed to set the owner to SYSTEM
        requiresTakeOwnership = true; // Needed for WRITE_DAC
    } else if (command == L"takeown") {
        desiredAccess = WRITE_OWNER;
        requiresTakeOwnership = true;
    } else if (command == L"query") {
        desiredAccess = SERVICE_QUERY_STATUS;
    } else if (command == L"weaken") {
        desiredAccess = WRITE_DAC;
    } else {
        std::wcerr << L"Unknown service command: " << command << L"\n";
        std::wcerr << L"Valid commands: start, stop, query, harden, takeown, weaken\n";
        return 1;
    }

    // Enable SE_TAKE_OWNERSHIP_NAME privilege for WRITE_OWNER access
    PrivilegeGuard takeownPrivilegeGuard(requiresTakeOwnership ? SE_TAKE_OWNERSHIP_NAME : nullptr);
    if (takeownPrivilegeGuard.IsValid() && !takeownPrivilegeGuard.IsEnabled()) {
        return 1;  // Error message already printed by PrivilegeGuard
    }

    // Enable SE_RESTORE_NAME privilege if setting owner to another user
    PrivilegeGuard restorePrivilegeGuard(requiresRestorePrivilege ? SE_RESTORE_NAME : nullptr);
    if (restorePrivilegeGuard.IsValid() && !restorePrivilegeGuard.IsEnabled()) {
        return 1;  // Error message already printed by PrivilegeGuard
    }

    std::wcout << L"Opening service: " << serviceName << L" with permissions: 0x" << std::hex << desiredAccess << std::dec << L"\n";

    SC_HANDLE scmHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scmHandle) {
        PrintLastError(L"OpenSCManager");
        return 1;
    }

    SC_HANDLE serviceHandle = OpenServiceW(scmHandle, serviceName.c_str(), desiredAccess);
    if (!serviceHandle) {
        PrintLastError(L"OpenService");
        CloseServiceHandle(scmHandle);
        return 1;
    }

    bool success = false;
    if (command == L"start") {
        std::wcout << L"Starting service...\n";
        success = StartServiceW(serviceHandle, 0, nullptr) != 0;
        if (success) {
            std::wcout << L"Service started successfully\n";
        } else {
            PrintLastError(L"StartService");
        }
    } else if (command == L"stop") {
        SERVICE_STATUS status;
        std::wcout << L"Stopping service...\n";
        success = ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status) != 0;
        if (success) {
            std::wcout << L"Service stopped successfully\n";
        } else {
            PrintLastError(L"ControlService");
        }
    } else if (command == L"harden") {
        success = SetServiceAcl(serviceHandle);
        if (success) {
            std::wcout << L"Service ACL hardened successfully\n";
        }
    } else if (command == L"takeown") {
        DWORD result = TakeOwnership(serviceHandle, SE_SERVICE);
        success = (result == ERROR_SUCCESS);
        if (success) {
            std::wcout << L"Service ownership transferred to Administrators\n";
        }
    } else if (command == L"weaken") {
        success = WeakenAcl(serviceHandle, SE_SERVICE, SERVICE_ALL_ACCESS);
        if (success) {
            std::wcout << L"Service ACL weakened successfully (Everyone has full access)\n";
        }
    } else if (command == L"query") {
        success = QueryServiceState(serviceHandle);
    }

    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);
    return success ? 0 : 1;
}
