includelib legacy_stdio_definitions.lib
EXTERN printf:PROC
EXTERN fprintf:PROC
EXTERN puts:PROC

sdata SEGMENT read write shared
return_jump_addr dq 0
file_pointer dq 0

reg_backup:
;array; db ;2048; dup(?)
;BYTE "loliloliloliloliloliloliloliloliloliloliloliloliloliloliloliloliloliloliloliloliloli",0
format:
BYTE "[decrypt] string: %s, bytes: %016llx",13,10,0 ;str,cr,lf,null
formathello:
BYTE "working",0

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

	push rdx
	push r8

	;do printf
	mov rcx, format		;setup format string
	;					;first arg (hash string) is in rdx
	;					;second arg (first 8 bytes) is in r8
	mov al, 2			;tell it we're using 2 arguments
	sub rsp, 32
	call printf
	add rsp, 32

	pop r9
	pop r8

	;get values again (as registers were destroyed by printf)
	;mov r8, [r15+98h]	;get hash string ptr
	;mov r9, [r8+88h]	;get data ptr
	;mov r9, [r9]		;get first 8 bytes of data

	;do printf
	mov rcx, file_pointer
	mov rdx, format
	;					;first arg (hash string) is in r8
	;					;second arg (first 8 bytes) is in r9
	mov al, 2			;set arg count again, as it was destroyed too
	sub rsp, 32
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
	mov edi, [rbx+90h]

	jmp return_jump_addr
hook_decrypt_func_under_xor endp

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





; backup rax, then rcx, then do the rest
backup_rax proc
mov rax, rax
ret
backup_rax endp

backup_rcx proc
mov rax, rcx
ret
backup_rcx endp

backup_rest proc
mov rax, [rsp+69h]
mov [rcx], rax
mov [rcx+8], rdi
ret
backup_rest endp

read_reg_rsp proc
mov rax, rsp
ret
read_reg_rsp endp

get_correct_rbp proc
lea rax, QWORD PTR [rsp-91C0h]
ret
get_correct_rbp endp

read_reg_rax proc
mov rax, rax
ret
read_reg_rax endp

read_reg_rbx proc
mov rax, rbx
ret
read_reg_rbx endp

read_reg_rcx proc
mov rax, rcx
ret
read_reg_rcx endp

read_reg_rdx proc
mov rax, rdx
ret
read_reg_rdx endp

end