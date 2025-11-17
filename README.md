# acl_tool
Tool for playing with securable objects on Windows. This has been almost completley vibe coded with Claude Sonet and I'm pleasantly surprised at the results.

# Building

I'm building against VS2022 using cmake. I know Windows but I do not know CMake. Your mileage may vary when running build.bat

```
cmake --version
cmake version 4.1.2
```
# Running

The point of this tool is to point out that ACLs are inherently not much of a barrier once someone has Admin access on a box. In particular, even a service that is locked down to only allow LOCAL SYSTEM to stop it, can still be taken over by an Admin. The Admin need only take ownership of the security descriptor and then weaken it.

ex:

```
AclTool.exe --service my_hardened_service takeown
AclTool.exe --service my_hardened_service weaken
sc stop my_hardened_service
```
