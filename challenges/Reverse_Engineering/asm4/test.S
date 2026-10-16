asm4:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	push   ebx
	<+4>:	sub    esp,0x10
	<+7>:	mov    DWORD PTR [ebp-0x10],0x26d
	<+14>:	mov    DWORD PTR [ebp-0xc],0x0
	<+21>:	jmp    0x1198 <asm4+27>
	<+23>:	add    DWORD PTR [ebp-0xc],0x1
	<+27>:	mov    edx,DWORD PTR [ebp-0xc]
	<+30>:	mov    eax,DWORD PTR [ebp+0x8]
	<+33>:	add    eax,edx
	<+35>:	movzx  eax,BYTE PTR [eax]
	<+38>:	test   al,al
	<+40>:	jne    0x1194 <asm4+23>
	<+42>:	mov    DWORD PTR [ebp-0x8],0x1
	<+49>:	jmp    0x1203 <asm4+134>
	<+51>:	mov    edx,DWORD PTR [ebp-0x8]
	<+54>:	mov    eax,DWORD PTR [ebp+0x8]
	<+57>:	add    eax,edx
	<+59>:	movzx  eax,BYTE PTR [eax]
	<+62>:	movsx  edx,al
	<+65>:	mov    eax,DWORD PTR [ebp-0x8]
	<+68>:	lea    ecx,[eax-0x1]
	<+71>:	mov    eax,DWORD PTR [ebp+0x8]
	<+74>:	add    eax,ecx
	<+76>:	movzx  eax,BYTE PTR [eax]
	<+79>:	movsx  eax,al
	<+82>:	sub    edx,eax
	<+84>:	mov    eax,DWORD PTR [ebp-0x10]
	<+87>:	lea    ebx,[edx+eax*1]
	<+90>:	mov    eax,DWORD PTR [ebp-0x8]
	<+93>:	lea    edx,[eax+0x1]
	<+96>:	mov    eax,DWORD PTR [ebp+0x8]
	<+99>:	add    eax,edx
	<+101>:	movzx  eax,BYTE PTR [eax]
	<+104>:	movsx  edx,al
	<+107>:	mov    ecx,DWORD PTR [ebp-0x8]
	<+110>:	mov    eax,DWORD PTR [ebp+0x8]
	<+113>:	add    eax,ecx
	<+115>:	movzx  eax,BYTE PTR [eax]
	<+118>:	movsx  eax,al
	<+121>:	sub    edx,eax
	<+123>:	mov    eax,edx
	<+125>:	add    eax,ebx
	<+127>:	mov    DWORD PTR [ebp-0x10],eax
	<+130>:	add    DWORD PTR [ebp-0x8],0x1
	<+134>:	mov    eax,DWORD PTR [ebp-0xc]
	<+137>:	sub    eax,0x1
	<+140>:	cmp    DWORD PTR [ebp-0x8],eax
	<+143>:	jl     0x11b0 <asm4+51>
	<+145>:	mov    eax,DWORD PTR [ebp-0x10]
	<+148>:	mov    ebx,DWORD PTR [ebp-0x4]
	<+151>:	leave
	<+152>:	ret

