#include "file_operations.h"
#include "common.h"
#include "privilege_guard.h"
#include <windows.h>
#include <iostream>

namespace {

bool SetFileAcl(HANDLE handle) {
    return SetRestrictiveAcl(handle, SE_FILE_OBJECT, FILE_ALL_ACCESS, FILE_GENERIC_READ);
}

}  // namespace

int ProcessFileCommand(const std::wstring& filePath, const std::wstring& command) {
    bool requiresTakeOwnership = false;
    bool requiresRestorePrivilege = false;
    DWORD desiredAccess = 0;
    
    if (command == L"harden") {
        desiredAccess = WRITE_DAC | WRITE_OWNER;
        requiresRestorePrivilege = true;  // Needed to set owner to SYSTEM
        requiresTakeOwnership = true;     // Needed for WRITE_OWNER access
    } else if (command == L"takeown") {
        desiredAccess = WRITE_OWNER;
        requiresTakeOwnership = true;
        requiresRestorePrivilege = true;  // Needed to set owner to Administrators
    } else if (command == L"weaken") {
        desiredAccess = WRITE_DAC;
        requiresTakeOwnership = true;     // Needed to bypass restrictive DACLs when opening
        requiresRestorePrivilege = true;  // Needed to modify DACL when you don't have WRITE_DAC access
    } else {
        std::wcerr << L"Unknown file command: " << command << L"\n";
        std::wcerr << L"Valid commands: harden, takeown, weaken\n";
        return 1;
    }

    // Enable SE_TAKE_OWNERSHIP_NAME privilege for WRITE_OWNER access
    PrivilegeGuard takeownPrivilegeGuard(requiresTakeOwnership ? SE_TAKE_OWNERSHIP_NAME : nullptr);
    
    if (takeownPrivilegeGuard.IsValid() && !takeownPrivilegeGuard.IsEnabled()) {
        return 1;  // Error message already printed by PrivilegeGuard
    }

    // Enable SE_RESTORE_NAME privilege if setting owner to SYSTEM/Administrators
    PrivilegeGuard restorePrivilegeGuard(requiresRestorePrivilege ? SE_RESTORE_NAME : nullptr);
    
    if (restorePrivilegeGuard.IsValid() && !restorePrivilegeGuard.IsEnabled()) {
        return 1;  // Error message already printed by PrivilegeGuard
    }

    std::wcout << L"Opening file: " << filePath << L" with permissions: 0x" << std::hex << desiredAccess << std::dec << L"\n";

    HANDLE fileHandle = CreateFileW(
        filePath.c_str(),
        desiredAccess,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,  // Allows opening directories
        nullptr
    );

    if (!fileHandle || fileHandle == INVALID_HANDLE_VALUE) {
        PrintLastError(L"CreateFile");
        return 1;
    }

    bool success = false;
    if (command == L"harden") {
        success = SetFileAcl(fileHandle);
        if (success) {
            std::wcout << L"File ACL hardened successfully\n";
        }
        CloseHandle(fileHandle);
    } else if (command == L"takeown") {
        DWORD result = TakeOwnership(fileHandle, SE_FILE_OBJECT);
        success = (result == ERROR_SUCCESS);
        if (success) {
            std::wcout << L"File ownership transferred to Administrators\n";
        }
        CloseHandle(fileHandle);
    } else if (command == L"weaken") {
        // Close the handle and use SetNamedSecurityInfo instead
        // This works with privileges rather than handle access rights
        CloseHandle(fileHandle);
        success = WeakenAclByName(filePath.c_str(), SE_FILE_OBJECT, FILE_ALL_ACCESS);
        if (success) {
            std::wcout << L"File ACL weakened successfully (Everyone has full access)\n";
        }
    }

    return success ? 0 : 1;
}
