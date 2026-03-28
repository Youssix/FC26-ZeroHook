; ntclose_syscall(uint64_t magic_handle, void* request_ptr)
; rcx = magic HANDLE, rdx = request pointer
; NtClose syscall number = 0x0F (stable Win10/Win11)
.code
ntclose_syscall proc
    mov r10, rcx
    mov eax, 0Fh
    syscall
    ret
ntclose_syscall endp
END
