[bits 32]
asm2:
    push ebp
    mov ebp, esp
    sub esp, 0x10
    mov eax, dword [ebp+0xc]
    mov dword [ebp-0x4], eax
    mov eax, dword [ebp+0x8]
    mov dword [ebp-0x8], eax
    jmp loc_31
loc_20:
    add dword [ebp-0x4], 0x1
    add dword [ebp-0x8], 0xe7
loc_31:
    cmp dword [ebp-0x8], 0x5ed6
    jle loc_20
    mov eax, dword [ebp-0x4]
    leave
    ret
