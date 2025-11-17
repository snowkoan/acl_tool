// AclTool.cpp
#include "common.h"
#include "event_operations.h"
#include "service_operations.h"
#include <windows.h>
#include <string>
#include <iostream>

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 4) {
        std::wcerr << L"Usage: AclTool.exe <--event|--service> <object-name> <command>\n\n";
        std::wcerr << L"Event commands:\n";
        std::wcerr << L"  set      : Set the event to signaled state\n";
        std::wcerr << L"  unset    : Reset the event to non-signaled state\n";
        std::wcerr << L"  harden   : Apply restrictive ACL (SYSTEM full, INTERACTIVE wait)\n";
        std::wcerr << L"  query    : Query the event state\n";
        std::wcerr << L"  takeown  : Transfer ownership to Administrators\n";
        std::wcerr << L"  weaken   : Take ownership and grant Everyone full access\n\n";
        std::wcerr << L"Service commands:\n";
        std::wcerr << L"  start    : Start the service\n";
        std::wcerr << L"  stop     : Stop the service\n";
        std::wcerr << L"  query    : Query the service status\n";
        std::wcerr << L"  harden   : Apply restrictive ACL (SYSTEM full, INTERACTIVE query)\n";
        std::wcerr << L"  takeown  : Transfer ownership to Administrators\n";
        std::wcerr << L"  weaken   : Take ownership and grant Everyone full access\n";
        return 1;
    }

    std::wstring objectType = argv[1];
    std::wstring objectName = argv[2];
    std::wstring command    = argv[3];

    if (objectType == L"--event") {
        return ProcessEventCommand(objectName, command);
    } else if (objectType == L"--service") {
        return ProcessServiceCommand(objectName, command);
    } else {
        std::wcerr << L"Unknown object type: " << objectType << L"\n";
        std::wcerr << L"Valid types: --event, --service\n";
        return 1;
    }
}
