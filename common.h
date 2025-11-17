#pragma once
#include <windows.h>
#include <aclapi.h>

// Common utility functions
void PrintLastError(const wchar_t* context);
bool SetRestrictiveAcl(HANDLE handle, SE_OBJECT_TYPE objectType, DWORD systemAccessMask, DWORD everyoneAccessMask);
bool WeakenAcl(HANDLE handle, SE_OBJECT_TYPE objectType, DWORD fullAccessMask);
DWORD SetPrivilege(LPCWSTR privilegeName, bool enable);
DWORD TakeOwnership(HANDLE handle, SE_OBJECT_TYPE objectType);
