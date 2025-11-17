#pragma once
#include <windows.h>
#include <iostream>

// Forward declaration
DWORD SetPrivilege(LPCWSTR privilegeName, bool enable);

// RAII class for managing privileges
class PrivilegeGuard {
public:
    explicit PrivilegeGuard(LPCWSTR privilegeName) 
        : privilegeName_(privilegeName), enabled_(false) {
        if (privilegeName_ == nullptr) {
            return;  // No privilege to enable
        }
        
        DWORD result = SetPrivilege(privilegeName_, true);
        if (result == ERROR_SUCCESS) {
            enabled_ = true;
        } else {
            std::wcerr << L"Failed to enable privilege: " << privilegeName_ << L"\n";
        }
    }

    ~PrivilegeGuard() {
        if (enabled_ && privilegeName_ != nullptr) {
            SetPrivilege(privilegeName_, false);
        }
    }
    
    // Non-copyable
    PrivilegeGuard(const PrivilegeGuard&) = delete;
    PrivilegeGuard& operator=(const PrivilegeGuard&) = delete;
    
    bool IsEnabled() const { return enabled_; }
    bool IsValid() const { return privilegeName_ != nullptr; }

private:
    LPCWSTR privilegeName_;
    bool enabled_;
};
