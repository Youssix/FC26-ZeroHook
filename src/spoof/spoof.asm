; spoof_call assembly stubs — return address spoofing
; Routes calls through a trampoline gadget so the return address
; on the call stack points to a legitimate module, not our DLL.

PUBLIC _spoofer_stub

.code

_spoofer_stub PROC
        pop r11                     ; pop return address (caller site in our code)
        add rsp, 8                  ; skip callee reserved space
        mov rax, [rsp + 24]         ; dereference shell_param (5th arg slot)

        mov r10, [rax]              ; load shell_param.trampoline
        mov [rsp], r10              ; store trampoline as return address

        mov r10, [rax + 8]          ; load shell_param.function
        mov [rax + 8], r11          ; store original return address in shell_param.function

        mov [rax + 16], rbx         ; preserve rbx in shell_param.rbx
        lea rbx, fixup
        mov [rax], rbx              ; store fixup label in shell_param.trampoline
        mov rbx, rax                ; preserve shell_param ptr in rbx

        jmp r10                     ; call shell_param.function

    fixup:
        sub rsp, 16
        mov rcx, rbx                ; restore shell_param ptr
        mov rbx, [rcx + 16]         ; restore rbx from shell_param.rbx
        jmp QWORD PTR [rcx + 8]    ; jmp to original return address

_spoofer_stub ENDP

END
