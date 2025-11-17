cmake_minimum_required(VERSION 3.20)
project(AclTool LANGUAGES CXX)

add_executable(AclTool 
    acl_tool.cpp
    common.cpp
    event_operations.cpp
    service_operations.cpp
)
target_compile_features(AclTool PRIVATE cxx_std_17)
target_compile_definitions(AclTool PRIVATE UNICODE _UNICODE)

if(MSVC)
    target_compile_options(AclTool PRIVATE /W4 /WX /permissive- /MT /GS /sdl)
else()
    # For MinGW/GCC, ensure console subsystem
    target_link_options(AclTool PRIVATE -mconsole)
endif()

target_link_libraries(AclTool PRIVATE advapi32)