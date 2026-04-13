

EXTERN wsysNtCreateThreadEx:QWORD
EXTERN ssnsysNtCreateThreadEx:DWORD

EXTERN wsysNtOpenProcess:QWORD
EXTERN ssnsysNtOpenProcess:DWORD

EXTERN wsysNtAllocateVirtualMemory:QWORD
EXTERN ssnsysNtAllocateVirtualMemory:DWORD

EXTERN wsysNtWriteVirtualMemory:QWORD
EXTERN ssnsysNtWriteVirtualMemory:DWORD

EXTERN wsysNtProtectVirtualMemory:QWORD
EXTERN ssnsysNtProtectVirtualMemory:DWORD



EXTERN wsysSuspendThread:QWORD
EXTERN ssnsysSuspendThread:DWORD

EXTERN wsysNtGetContextThread:QWORD
EXTERN ssnsysNtGetContextThread:DWORD

EXTERN wsysNtSetContextThread:QWORD
EXTERN ssnsysNtSetContextThread:DWORD

EXTERN wsysNtResumeThread:QWORD
EXTERn ssnsysNtResumeThread:DWORD

EXTERN wsysNtQueryInfoProcess:QWORD
EXTERN ssnsysNtQueryInfoProcess:DWORD

EXTERN wsysNtOpenThread:QWORD
EXTERN ssnsysNtOpenThread:DWORD

EXTERN wsysNtFreeVirtualMemory:QWORD
EXTERN ssnsysNtFreeVirtualMemory:DWORD

EXTERN wsysNtWaitForSingleObject:QWORD
EXTERN ssnsysNtWaitForSingleObject:DWORD

EXTERN wsysNtQuerySystemInformation:QWORD
EXTERN ssnsysNtQuerySystemInformation:DWORD

EXTERN wsysNtReadVirtualMemory:QWORD
EXTERN ssnsysNtReadVirtualMemory:DWORD


.code





sysNtReadVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtReadVirtualMemory]
    jmp qword ptr [wsysNtReadVirtualMemory]
sysNtReadVirtualMemory ENDP

sysNtQuerySystemInformation PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtQuerySystemInformation]
    jmp qword ptr [wsysNtQuerySystemInformation]
sysNtQuerySystemInformation ENDP


sysNtWaitForSingleObject PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtWaitForSingleObject]
    jmp qword ptr [wsysNtWaitForSingleObject]
sysNtWaitForSingleObject ENDP

sysNtCreateThreadEx PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtCreateThreadEx]
    jmp qword ptr [wsysNtCreateThreadEx]
sysNtCreateThreadEx ENDP

sysNtOpenProcess PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtOpenProcess]
    jmp qword ptr [wsysNtOpenProcess]
sysNtOpenProcess ENDP

sysNtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtAllocateVirtualMemory]
    jmp qword ptr [wsysNtAllocateVirtualMemory]
sysNtAllocateVirtualMemory ENDP

sysNtWriteVirtualMemory PROC 
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtWriteVirtualMemory]
    jmp qword ptr [wsysNtWriteVirtualMemory]
sysNtWriteVirtualMemory ENDP

sysNtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtProtectVirtualMemory]
    jmp qword ptr [wsysNtProtectVirtualMemory]
sysNtProtectVirtualMemory ENDP




sysSuspendThread PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysSuspendThread]
    jmp qword ptr [wsysSuspendThread]
sysSuspendThread ENDP


sysNtGetContextThread PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtGetContextThread]
    jmp qword ptr [wsysNtGetContextThread]
sysNtGetContextThread ENDP

sysNtSetContextThread PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtSetContextThread]
    jmp qword ptr [wsysNtSetContextThread]
sysNtSetContextThread ENDP

sysNtResumeThread PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtResumeThread]
    jmp qword ptr [wsysNtResumeThread]
sysNtResumeThread ENDP

sysNtQueryInfoProcess PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtQueryInfoProcess]
    jmp qword ptr [wsysNtQueryInfoProcess]
sysNtQueryInfoProcess ENDP


sysNtOpenThread PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtOpenThread]
    jmp qword ptr [wsysNtOpenThread]
sysNtOpenThread ENDP

sysNtFreeVirtualMemory PROC
    mov r10, rcx
    mov eax, dword ptr [ssnsysNtFreeVirtualMemory]
    jmp qword ptr [wsysNtFreeVirtualMemory]
sysNtFreeVirtualMemory ENDP
END