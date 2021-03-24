includelib legacy_stdio_definitions.lib
EXTERN printf:PROC
EXTERN fprintf:PROC
EXTERN puts:PROC

sdata SEGMENT read write shared
return_jump_addr dq 0
file_pointer dq 0

format:
BYTE "[decrypt] string: %s, bytes: %016llx",13,10,0 ;str,cr,lf,null
sdata ends


.code

write_new_file_pointer proc
	mov file_pointer, rax
	ret
write_new_file_pointer endp

write_new_ret_addr proc
	mov return_jump_addr, rcx
	ret
write_new_ret_addr endp

hook_decrypt_func_under_xor proc
	;save every register to avoid annoying bugs later
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	



	;get values
	mov rdx, [r15+98h]	;get hash string ptr
	mov r8, [rbx+88h]	;get data ptr
	mov r8, [r8]		;get first 8 bytes of data

	;save values, since these registers are volatile
	push rdx			;hash string ptr
	push r8				;first bytes

	;do printf
	mov rcx, format		;setup format string
	;					;first arg (hash string) is in rdx
	;					;second arg (first 8 bytes) is in r8
	mov al, 2			;tell it we're using 2 arguments
	sub rsp, 32			;add shadowspace
	call printf
	add rsp, 32			;remove shadowspace

	;grab our values back from the stack
	pop r9				;first bytes
	pop r8				;hash string ptr

	;do printf
	mov rcx, file_pointer
	mov rdx, format
	;					;first arg (hash string) is in r8
	;					;second arg (first 8 bytes) is in r9
	mov al, 2			;set arg count again, as it was destroyed too
	sub rsp, 32			;add shadowspace
	call fprintf
	add rsp, 32			;remove shadowspace



	;move back registers that we saved
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	;execute overwritten instruction
	mov edi, [rbx+90h]

	jmp return_jump_addr ;since the patch function does a long jump here, we shouldn't ret
hook_decrypt_func_under_xor endp

;kinda useless now
hook_decrypt_func_on_keyload proc
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	;nothing:
	;nop
	;jmp nothing

	sub rsp, 32

	;hash already in rdi
	;rbp contains data*
	mov rcx, format	;string as first arg
	mov rdx, rdi	;hash string* as second arg
	mov r8, [rbp]	;first 8 bytes as third arg
	mov al, 2		;amount of arguments (excluding format string)
	call printf

	mov rcx, file_pointer
	mov rdx, format
	mov r8, rdi
	mov r9, [rbp]
	mov al, 2
	call fprintf

	add rsp, 32

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	;execute overwritten instruction
	mov rcx, 0A1B34F58CAD705B2h
	;mov rcx, 0B205D7CA584FB3A1h

	jmp return_jump_addr
hook_decrypt_func_on_keyload endp


;also kinda useless
do_thing proc
	push rax
	push rbx
	push rcx
	push rdx
	push rsi
	push rdi
	push rbp
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15

	nothing1:
	;nop
	;jmp nothing1

	;get hash thing
	mov rbx, rcx
	mov rax, [rbx+0A0h]
	mov r15, [rax+80h]
	lea rdi, [r15+98h]
	mov rdi, [rdi]

	;get data ptr (r15 still set up correctly from getting hash)
	;mov rax, [r15+90h]
	;mov rbp, [rax+8h]
	;mov r9, [rbp]

	mov rax, [r15+90h]
	mov rax, [rax+8h]
	mov rbx, [rax]
	mov rax, rbx
	
	;print hash
	mov rcx, format	;string as first arg
	mov rdx, rdi	;hash as second arg
	mov r8, rbx		;first 8 bytes as third arg
	mov al, 2		;amount of arguments (excluding format string)
	call printf

	mov rcx, file_pointer
	mov rdx, format
	mov r8, rdi
	mov r9, rbx
	mov al, 2
	call fprintf

	nothing2:
	;nop
	;jmp nothing2

	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rbp
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax

	;execute overwritten instructions
	push rbp
	push rsi
	push rdi
	push r14

	jmp return_jump_addr
do_thing endp

END