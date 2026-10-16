.intel_syntax noprefix
.global asm4
asm4:
label_0:
    push   ebp
label_1:
    mov    ebp,esp
label_3:
    push   ebx
label_4:
    sub    esp,0x10
label_7:
    mov    DWORD PTR [ebp-0x10],0x26d
label_14:
    mov    DWORD PTR [ebp-0xc],0x0
label_21:
    jmp    label_27
label_23:
    add    DWORD PTR [ebp-0xc],0x1
label_27:
    mov    edx,DWORD PTR [ebp-0xc]
label_30:
    mov    eax,DWORD PTR [ebp+0x8]
label_33:
    add    eax,edx
label_35:
    movzx  eax,BYTE PTR [eax]
label_38:
    test   al,al
label_40:
    jne    label_23
label_42:
    mov    DWORD PTR [ebp-0x8],0x1
label_49:
    jmp    label_134
label_51:
    mov    edx,DWORD PTR [ebp-0x8]
label_54:
    mov    eax,DWORD PTR [ebp+0x8]
label_57:
    add    eax,edx
label_59:
    movzx  eax,BYTE PTR [eax]
label_62:
    movsx  edx,al
label_65:
    mov    eax,DWORD PTR [ebp-0x8]
label_68:
    lea    ecx,[eax-0x1]
label_71:
    mov    eax,DWORD PTR [ebp+0x8]
label_74:
    add    eax,ecx
label_76:
    movzx  eax,BYTE PTR [eax]
label_79:
    movsx  eax,al
label_82:
    sub    edx,eax
label_84:
    mov    eax,DWORD PTR [ebp-0x10]
label_87:
    lea    ebx,[edx+eax*1]
label_90:
    mov    eax,DWORD PTR [ebp-0x8]
label_93:
    lea    edx,[eax+0x1]
label_96:
    mov    eax,DWORD PTR [ebp+0x8]
label_99:
    add    eax,edx
label_101:
    movzx  eax,BYTE PTR [eax]
label_104:
    movsx  edx,al
label_107:
    mov    ecx,DWORD PTR [ebp-0x8]
label_110:
    mov    eax,DWORD PTR [ebp+0x8]
label_113:
    add    eax,ecx
label_115:
    movzx  eax,BYTE PTR [eax]
label_118:
    movsx  eax,al
label_121:
    sub    edx,eax
label_123:
    mov    eax,edx
label_125:
    add    eax,ebx
label_127:
    mov    DWORD PTR [ebp-0x10],eax
label_130:
    add    DWORD PTR [ebp-0x8],0x1
label_134:
    mov    eax,DWORD PTR [ebp-0xc]
label_137:
    sub    eax,0x1
label_140:
    cmp    DWORD PTR [ebp-0x8],eax
label_143:
    jl     label_51
label_145:
    mov    eax,DWORD PTR [ebp-0x10]
label_148:
    mov    ebx,DWORD PTR [ebp-0x4]
label_151:
    leave
label_152:
    ret
