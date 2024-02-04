# RDM
 Module load event for unknown process

well known bug in DBGENG.DLL (used by windbg ) and msvsmon.exe (used by MSVC)

if we map executable (SEC_IMAGE) section in remote process, which is under debugger - the debug event DbgLoadDllStateChange
is sent to debugger. 

but (!) ClientId belong to thread which call ZwMapViewOfSection in another (!!) process, which is usually not debugged (most debuggers can debug only single process at time)

as resulut debugger is confused - he got debug event from process which he not debug !

the msvsmon.exe silently do nothing at this point. as result both processes is hang ( process which call ZwMapViewOfSection and debugged process)

the DBGENG.DLL is output the next lines:

ERROR: Unable to find system process <process-id>
ERROR: The process being debugged has either exited or cannot be accessed
ERROR: Many commands will not work properly
ERROR: Module load event for unknown process

but also not handle this (not call DbgUiContinue ) and again both processes is hang forever

however some debuggers can correct handle this situation

the exactly same will be on remote section unmap via ZwUnmapViewOfSection

again most debuggers wron handle (not handle) DbgUnloadDllStateChange for unknown process 


then code demonstrate how we can detect name of debugger process, if we under debugger, and detach debugger. however debugger (man, not program) of course can prevent this, if want :)

