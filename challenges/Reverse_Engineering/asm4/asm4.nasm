BITS 32
asm4:
	push   ebp
	mov    ebp,esp
	push   ebx
	sub    esp,0x10
	mov    DWORD [ebp-0x10],0x26d
	mov    DWORD [ebp-0xc],0x0
	jmp    loc_27
loc_23:
	add    DWORD [ebp-0xc],0x1
loc_27:
	mov    edx,DWORD [ebp-0xc]
	mov    eax,DWORD [ebp+0x8]
	add    eax,edx
	movzx  eax,BYTE [eax]
	test   al,al
	jne    loc_23
	mov    DWORD [ebp-0x8],0x1
	jmp    loc_134
loc_51:
	mov    edx,DWORD [ebp-0x8]
	mov    eax,DWORD [ebp+0x8]
	add    eax,edx
	movzx  eax,BYTE [eax]
	movsx  edx,al
	mov    eax,DWORD [ebp-0x8]
	lea    ecx,[eax-0x1]
	mov    eax,DWORD [ebp+0x8]
	add    eax,ecx
	movzx  eax,BYTE [eax]
	movsx  eax,al
	sub    edx,eax
	mov    eax,DWORD [ebp-0x10]
	lea    ebx,[edx+eax*1]
	mov    eax,DWORD [ebp-0x8]
	lea    edx,[eax+0x1]
	mov    eax,DWORD [ebp+0x8]
	add    eax,edx
	movzx  eax,BYTE [eax]
	movsx  edx,al
	mov    ecx,DWORD [ebp-0x8]
	mov    eax,DWORD [ebp+0x8]
	add    eax,ecx
	movzx  eax,BYTE [eax]
	movsx  eax,al
	sub    edx,eax
	mov    eax,edx
	add    eax,ebx
	mov    DWORD [ebp-0x10],eax
	add    DWORD [ebp-0x8],0x1
loc_134:
	mov    eax,DWORD [ebp-0xc]
	sub    eax,0x1
	cmp    DWORD [ebp-0x8],eax
	jl     loc_51
	mov    eax,DWORD [ebp-0x10]
	mov    ebx,DWORD [ebp-0x4]
	leave
	ret
