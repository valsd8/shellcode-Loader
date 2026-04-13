#pragma once
#include "def.h"
#include <string>

#include "helper.hpp"
#include "syscall.hpp"
#include "syscall_global.hpp"
#include "injector.hpp"


 
class apc {

public:
    VOID mySuspendThread(HANDLE thread);
    VOID myThreadContext(HANDLE thread, PCONTEXT context);
    VOID myNtSetContextThread(HANDLE thread, PCONTEXT context);
    VOID myNtResumeThread(HANDLE thread);
    HANDLE myNtOpenThread(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD target_tId, DWORD process_id);
    HANDLE findThread(DWORD process_pid);

};

extern apc apcInjector;

