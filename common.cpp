#include "common.h"
#include <sddl.h>
#include <iostream>

void PrintLastError(const wchar_t* context) {
    DWORD err = GetLastError();
    LPWSTR buffer = nullptr;
    DWORD result = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    
    // Security: Check if FormatMessageW succeeded before dereferencing buffer
    if (result > 0 && buffer != nullptr) {
        // Remove trailing newlines from the error message
        size_t len = wcslen(buffer);
        while (len > 0 && (buffer[len - 1] == L'\n' || buffer[len - 1] == L'\r')) {
            buffer[len - 1] = L'\0';
            len--;
        }
        std::wcerr << context << L" failed: 0x" << std::hex << err << L" (" << buffer << L")\n";
        LocalFree(buffer);
    } else {
        // Fallback if FormatMessageW fails
        std::wcerr << context << L" failed: 0x" << std::hex << err << L"\n";
    }
}

void PrintDacl(PACL dacl) {
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE);
    
    LPWSTR daclSddl = nullptr;
    if (ConvertSecurityDescriptorToStringSecurityDescriptorW(
            &sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, 
            &daclSddl, nullptr)) {
        std::wcout << L"Setting DACL: " << daclSddl << L"\n";
        LocalFree(daclSddl);
    }
    else {
        PrintLastError(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
    }
}

bool SetRestrictiveAcl(HANDLE handle, SE_OBJECT_TYPE objectType, DWORD systemAccessMask, DWORD everyoneAccessMask) {
    BYTE systemSidBuffer[SECURITY_MAX_SID_SIZE];
    BYTE interactiveSidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD systemSidSize = sizeof(systemSidBuffer);
    DWORD interactiveSidSize = sizeof(interactiveSidBuffer);

    if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSidBuffer, &systemSidSize)) {
        PrintLastError(L"CreateWellKnownSid(WinLocalSystemSid)");
        return false;
    }
    if (!CreateWellKnownSid(WinInteractiveSid, nullptr, interactiveSidBuffer, &interactiveSidSize)) {
        PrintLastError(L"CreateWellKnownSid(WinInteractiveSid)");
        return false;
    }

    PSID systemSid      = systemSidBuffer;
    PSID interactiveSid = interactiveSidBuffer;

    EXPLICIT_ACCESSW ea[2] = {};
    // SYSTEM gets full control
    ea[0].grfAccessPermissions = systemAccessMask;
    ea[0].grfAccessMode        = SET_ACCESS;
    ea[0].grfInheritance       = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType  = TRUSTEE_IS_USER;
    ea[0].Trustee.ptstrName    = static_cast<LPWSTR>(systemSid);

    // NT AUTHORITY\INTERACTIVE gets limited access
    ea[1].grfAccessPermissions = everyoneAccessMask;
    ea[1].grfAccessMode        = SET_ACCESS;
    ea[1].grfInheritance       = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName    = static_cast<LPWSTR>(interactiveSid);

    PACL newDacl = nullptr;
    DWORD result = SetEntriesInAclW(2, ea, nullptr, &newDacl);
    if (result != ERROR_SUCCESS) {
        SetLastError(result);
        PrintLastError(L"SetEntriesInAcl");
        return false;
    }

    PrintDacl(newDacl);

    result = SetSecurityInfo(handle, objectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl, nullptr);
    LocalFree(newDacl);

    if (result != ERROR_SUCCESS) {
        SetLastError(result);
        PrintLastError(L"SetSecurityInfo (DACL)");
        return false;
    }

    // Convert owner SID to SDDL and print it
    LPWSTR ownerSddl = nullptr;
    if (ConvertSidToStringSidW(systemSid, &ownerSddl)) {
        std::wcout << L"Setting Owner: " << ownerSddl << L"\n";
        LocalFree(ownerSddl);
    }

    // Set owner to LOCAL SYSTEM
    // Requires SE_RESTORE_NAME privilege (must be enabled before calling this function)
    result = SetSecurityInfo(handle, objectType, OWNER_SECURITY_INFORMATION, systemSid, nullptr, nullptr, nullptr);
    if (result != ERROR_SUCCESS) {
        SetLastError(result);
        PrintLastError(L"SetSecurityInfo (Owner)");
        return false;
    }

    return true;
}

bool WeakenAcl(HANDLE handle, SE_OBJECT_TYPE objectType, DWORD fullAccessMask) {
    BYTE everyoneSidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD everyoneSidSize = sizeof(everyoneSidBuffer);

    if (!CreateWellKnownSid(WinWorldSid, nullptr, everyoneSidBuffer, &everyoneSidSize)) {
        PrintLastError(L"CreateWellKnownSid(WinWorldSid)");
        return false;
    }

    PSID everyoneSid = everyoneSidBuffer;

    EXPLICIT_ACCESSW ea = {};
    // Everyone gets full control
    ea.grfAccessPermissions = fullAccessMask;
    ea.grfAccessMode        = SET_ACCESS;
    ea.grfInheritance       = NO_INHERITANCE;
    ea.Trustee.TrusteeForm  = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType  = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName    = static_cast<LPWSTR>(everyoneSid);

    PACL newDacl = nullptr;
    DWORD result = SetEntriesInAclW(1, &ea, nullptr, &newDacl);
    if (result != ERROR_SUCCESS) {
        SetLastError(result);
        PrintLastError(L"SetEntriesInAcl");
        return false;
    }

    PrintDacl(newDacl);

    result = SetSecurityInfo(handle, objectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, newDacl, nullptr);
    LocalFree(newDacl);

    if (result != ERROR_SUCCESS) {
        SetLastError(result);
        PrintLastError(L"SetSecurityInfo");
        return false;
    }
    return true;
}

DWORD SetPrivilege(LPCWSTR privilegeName, bool enable) {
    HANDLE tokenHandle;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle)) {
        DWORD err = GetLastError();
        PrintLastError(L"OpenProcessToken");
        return err;
    }

    TOKEN_PRIVILEGES tp = {};
    if (!LookupPrivilegeValueW(nullptr, privilegeName, &tp.Privileges[0].Luid)) {
        DWORD err = GetLastError();
        PrintLastError(L"LookupPrivilegeValue");
        CloseHandle(tokenHandle);
        return err;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tp, 0, nullptr, nullptr)) {
        DWORD err = GetLastError();
        PrintLastError(L"AdjustTokenPrivileges");
        CloseHandle(tokenHandle);
        return err;
    }

    CloseHandle(tokenHandle);
    return ERROR_SUCCESS;
}

DWORD TakeOwnership(HANDLE handle, SE_OBJECT_TYPE objectType) {
    BYTE adminsSidBuffer[SECURITY_MAX_SID_SIZE];
    DWORD adminsSidSize = sizeof(adminsSidBuffer);

    if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminsSidBuffer, &adminsSidSize)) {
        DWORD result = GetLastError();
        PrintLastError(L"CreateWellKnownSid(WinBuiltinAdministratorsSid)");
        return result;
    }

    PSID adminsSid = adminsSidBuffer;

    // Set owner to Administrators group
    // Requires SE_TAKE_OWNERSHIP_NAME privilege (must be enabled before calling this function)
    DWORD result = SetSecurityInfo(handle, objectType, OWNER_SECURITY_INFORMATION, 
                                   adminsSid, nullptr, nullptr, nullptr);
    if (result != ERROR_SUCCESS) {
        SetLastError(result);
        PrintLastError(L"SetSecurityInfo (Owner)");
    }

    return result;
}
