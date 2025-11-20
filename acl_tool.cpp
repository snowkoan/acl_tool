// AclTool.cpp
#include <windows.h>
#include <string>
#include <iostream>

#include "common.h"
#include "event_operations.h"
#include "service_operations.h"
#include "process_operations.h"

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 4) {
        std::wcerr << L"Usage: AclTool.exe [event <event-name>|--service <service-name>|--process> PID|process-name] <command>\n\n";
        std::wcerr << L"Event commands:\n";
        std::wcerr << L"  set      : Set the event to signaled state\n";
        std::wcerr << L"  unset    : Reset the event to non-signaled state\n";
        std::wcerr << L"  harden   : Apply restrictive ACL (SYSTEM full, INTERACTIVE wait)\n";
        std::wcerr << L"  query    : Query the event state\n";
        std::wcerr << L"  takeown  : Transfer ownership to Administrators\n";
        std::wcerr << L"  weaken   : Grant Everyone full access\n\n";
        std::wcerr << L"Service commands:\n";
        std::wcerr << L"  start    : Start the service\n";
        std::wcerr << L"  stop     : Stop the service\n";
        std::wcerr << L"  query    : Query the service status\n";
        std::wcerr << L"  harden   : Apply restrictive ACL (SYSTEM full, INTERACTIVE query)\n";
        std::wcerr << L"  takeown  : Transfer ownership to Administrators\n";
        std::wcerr << L"  weaken   : Grant Everyone full access\n\n";
        std::wcerr << L"Process commands:\n";
        std::wcerr << L"  terminate: Terminate the process\n";
        std::wcerr << L"  harden   : Apply restrictive ACL (SYSTEM full, INTERACTIVE query)\n";
        std::wcerr << L"  takeown  : Transfer ownership to Administrators\n";
        std::wcerr << L"  weaken   : Grant Everyone full access\n";
        return 1;
    }

    std::wstring objectType = argv[1];
    std::wstring objectName = argv[2];
    std::wstring command    = argv[3];

    if (objectType == L"--event") {
        return ProcessEventCommand(objectName, command);
    } else if (objectType == L"--service") {
        return ProcessServiceCommand(objectName, command);
    } else if (objectType == L"--process") {
        // Try to parse as process ID first
        wchar_t* endPtr = nullptr;
        DWORD processId = wcstoul(objectName.c_str(), &endPtr, 10);
        
        // If not a valid number, treat as process name
        if (*endPtr != L'\0' || processId == 0) {
            processId = FindProcessByName(objectName);
            if (processId == 0) {
                return 1;  // Error already printed by FindProcessByName
            }
        }
        
        return ProcessProcessCommand(processId, command);
    } else {
        std::wcerr << L"Unknown object type: " << objectType << L"\n";
        std::wcerr << L"Valid types: --event, --service, --process\n";
        return 1;
    }
}
