#pragma once
#include <string>
#include <windows.h>

// Find process ID by name. Returns 0 if not found or multiple matches exist.
DWORD FindProcessByName(const std::wstring& processName);

int ProcessProcessCommand(DWORD processId, const std::wstring& command);
