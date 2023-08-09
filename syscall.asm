.data
 wSystemCall DWORD 0h
.code
 Gate PROC
 mov wSystemCall, 0h
 mov wSystemCall, ecx
 ret
 Gate ENDP
 Halo PROC
 mov r10, rcx
 mov eax, wSystemCall
 syscall
 ret
 Halo ENDP
end