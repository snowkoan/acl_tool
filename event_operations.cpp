#include "event_operations.h"
#include "common.h"
#include "privilege_guard.h"
#include <windows.h>
#include <iostream>

namespace {

bool SetEventAcl(HANDLE handle) {
    return SetRestrictiveAcl(handle, SE_KERNEL_OBJECT, EVENT_ALL_ACCESS, SYNCHRONIZE);
}

bool QueryEventState(HANDLE handle) {
    DWORD result = WaitForSingleObject(handle, 0);
    
    if (result == WAIT_OBJECT_0) {
        std::wcout << L"Event state  : Signaled\n";
        return true;
    } else if (result == WAIT_TIMEOUT) {
        std::wcout << L"Event state  : Not signaled\n";
        return true;
    } else {
        PrintLastError(L"WaitForSingleObject");
        return false;
    }
}

}  // namespace

int ProcessEventCommand(const std::wstring& eventName, const std::wstring& command) {
    // Prepend "Global\" if the event name doesn't contain a backslash
    std::wstring fullEventName = eventName;
    if (fullEventName.find(L'\\') == std::wstring::npos) {
        fullEventName = L"Global\\" + fullEventName;
    }

    bool requiresTakeOwnership = false;
    DWORD desiredAccess = 0;
    
    if (command == L"set" || command == L"unset") {
        desiredAccess = EVENT_MODIFY_STATE;
    } else if (command == L"harden") {
        desiredAccess = READ_CONTROL | WRITE_DAC;
    } else if (command == L"query") {
        desiredAccess = SYNCHRONIZE;
    } else if (command == L"takeown") {
        desiredAccess = WRITE_OWNER;
        requiresTakeOwnership = true;
    } else if (command == L"weaken") {
        desiredAccess = WRITE_OWNER | WRITE_DAC;
        requiresTakeOwnership = true;
    } else {
        std::wcerr << L"Unknown event command: " << command << L"\n";
        std::wcerr << L"Valid commands: set, unset, harden, query, takeown, weaken\n";
        return 1;
    }

    // Enable SE_TAKE_OWNERSHIP_NAME privilege if taking ownership
    // PrivilegeGuard will automatically disable on scope exit
    PrivilegeGuard privilegeGuard(requiresTakeOwnership ? SE_TAKE_OWNERSHIP_NAME : nullptr);
    
    if (privilegeGuard.IsValid() && !privilegeGuard.IsEnabled()) {
        return 1;  // Error message already printed by PrivilegeGuard
    }

    std::wcout << L"Opening event: " << fullEventName << L" with permissions: 0x" << std::hex << desiredAccess << std::dec << L"\n";

    HANDLE eventHandle = OpenEventW(desiredAccess, FALSE, fullEventName.c_str());
    if (!eventHandle || eventHandle == INVALID_HANDLE_VALUE) {
        PrintLastError(L"OpenEvent");
        return 1;
    }

    bool success = false;
    if (command == L"set") {
        success = SetEvent(eventHandle) != 0;
        if (success) {
            std::wcout << L"Event set successfully\n";
        } else {
            PrintLastError(L"SetEvent");
        }
    } else if (command == L"unset") {
        success = ResetEvent(eventHandle) != 0;
        if (success) {
            std::wcout << L"Event reset successfully\n";
        } else {
            PrintLastError(L"ResetEvent");
        }
    } else if (command == L"harden") {
        success = SetEventAcl(eventHandle);
        if (success) {
            std::wcout << L"Event ACL hardened successfully\n";
        }
    } else if (command == L"takeown") {
        DWORD result = TakeOwnership(eventHandle, SE_KERNEL_OBJECT);
        success = (result == ERROR_SUCCESS);
        if (success) {
            std::wcout << L"Event ownership transferred to Administrators\n";
        }
    } else if (command == L"weaken") {
        DWORD result = TakeOwnership(eventHandle, SE_KERNEL_OBJECT);
        if (result == ERROR_SUCCESS) {
            success = WeakenAcl(eventHandle, SE_KERNEL_OBJECT, EVENT_ALL_ACCESS);
            if (success) {
                std::wcout << L"Event ACL weakened successfully (Everyone has full access)\n";
            }
        } else {
            success = false;
        }
    } else {  // query
        success = QueryEventState(eventHandle);
    }

    CloseHandle(eventHandle);
    return success ? 0 : 1;
}
