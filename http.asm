%include "common.inc"
default rel

global http_parse
global parse_uint, url_decode, form_field

section .rodata
header_content_length: db 'content-length:'

section .text

; rdi=request, rsi=length; rax=0 or -1. Clobbers caller-saved registers.
http_parse:
    push rbx
    push rbp
    push r12
    push r13
    mov rbp, [fs:TLS_SELF]
    mov rbx, rdi
    lea r12, [rdi+rsi]
    xor eax, eax
    lea rdi, [rbp+TLS_PATH]
    push 5
    pop rcx
    rep stosq                      ; Clear the five contiguous pointer/length slots.
    mov rdi, rbx
    push M_OTHER
    pop rax
    mov [rbp+TLS_METHOD], rax

    cmp rsi, 4
    jb .find_space
    cmp dword [rdi], 'GET '
    jne .check_post
    xor eax, eax                  ; M_GET, including the upper half of the qword.
    mov [rbp+TLS_METHOD], rax
    jmp .find_space
.check_post:
    cmp rsi, 5
    jb .find_space
    cmp dword [rdi], 'POST'
    jne .find_space
    cmp byte [rdi+4], ' '
    jne .find_space
    push M_POST
    pop rax
    mov [rbp+TLS_METHOD], rax

.find_space:
    cmp rbx, r12
    jae .invalid
    mov al, [rbx]
    cmp al, ' '
    je .path_start
    cmp al, 13
    je .invalid
    cmp al, 10
    je .invalid
    inc rbx
    jmp .find_space
.path_start:
    cmp rbx, rdi
    je .invalid
    inc rbx
    mov r13, rbx
.path_scan:
    cmp rbx, r12
    jae .path_end
    mov al, [rbx]
    cmp al, ' '
    je .path_end
    cmp al, 13
    je .path_end
    cmp al, 10
    je .path_end
    cmp al, '?'
    je .path_end
    inc rbx
    jmp .path_scan
.path_end:
    mov rax, rbx
    sub rax, r13
    jz .invalid
    mov [rbp+TLS_PATH], r13
    mov [rbp+TLS_PATHLEN], rax

    ; Ignore the query/version and start headers after the request line's LF.
.request_end:
    cmp rbx, r12
    jae .ok
    cmp byte [rbx], 10
    je .headers_start
    inc rbx
    jmp .request_end
.headers_start:
    inc rbx
.header:
    cmp rbx, r12
    jae .ok
    cmp byte [rbx], 10
    je .body_lf
    cmp byte [rbx], 13
    jne .header_line
    lea rax, [rbx+1]
    cmp rax, r12
    jae .ok
    cmp byte [rbx+1], 10
    je .body_crlf
.header_line:
    mov r13, rbx
.header_end:
    cmp r13, r12
    jae .header_name
    cmp byte [r13], 10
    je .header_name
    inc r13
    jmp .header_end
.header_name:
    mov rax, r13
    sub rax, rbx
    cmp rax, 15
    jb .next_header
    xor ecx, ecx
.header_compare:
    mov al, [rbx+rcx]
    cmp al, 0x20                   ; Folding must not turn CR into '-' or SUB into ':'.
    jb .next_header
    or al, 0x20
.header_compare_byte:
    cmp al, [header_content_length+rcx]
    jne .next_header
    inc ecx
    cmp ecx, 15
    jb .header_compare
    lea rdi, [rbx+15]
.header_whitespace:
    cmp rdi, r13
    jae .header_number
    cmp byte [rdi], ' '
    je .skip_whitespace
    cmp byte [rdi], 9
    jne .header_number
.skip_whitespace:
    inc rdi
    jmp .header_whitespace
.header_number:
    mov rsi, r13
    sub rsi, rdi
    call parse_uint
    mov [rbp+TLS_CLEN], rax
.next_header:
    mov rbx, r13
    cmp rbx, r12
    jae .ok
    inc rbx
    jmp .header

.body_crlf:
    inc rbx
.body_lf:
    inc rbx
    mov [rbp+TLS_BODY], rbx
    mov rax, r12
    sub rax, rbx
    mov [rbp+TLS_BODYLEN], rax
.ok:
    xor eax, eax
    jmp .return
.invalid:
    push -1
    pop rax
.return:
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; rdi=digits, rsi=max length; rax=saturated uint32, rdx=digits. Clobbers rcx,r9.
parse_uint:
    xor eax, eax
    xor edx, edx
    or r9d, byte -1
.next:
    cmp rdx, rsi
    jae .done
    movzx ecx, byte [rdi+rdx]
    sub ecx, '0'
    cmp ecx, 9
    ja .done
    imul rax, rax, 10
    add rax, rcx
    cmp rax, r9
    cmova rax, r9
    inc rdx
    jmp .next
.done:
    ret

; rdi=dest, rsi=src, rdx=length, rcx=capacity; rax=written. Clobbers caller-saved.
url_decode:
    mov r11, rdi
.next:
    test rcx, rcx
    jz .done
    test rdx, rdx
    jz .done
    lodsb
    dec rdx
    cmp al, '+'
    je .space
    cmp al, '%'
    jne .emit
    cmp rdx, 2
    jb .emit
    mov al, [rsi]
    call .hex_value
    jc .literal_percent
    mov ah, al
    mov al, [rsi+1]
    call .hex_value
    jc .literal_percent
    shl ah, 4
    or al, ah
    add rsi, 2
    sub rdx, 2
    jmp .emit
.literal_percent:
    mov al, '%'
    jmp .emit
.space:
    mov al, ' '
.emit:
    stosb
    dec rcx
    jmp .next
.done:
    mov rax, rdi
    sub rax, r11
    ret

; al=ASCII hex; al=nibble with CF clear, or CF set for invalid input. Preserves ah.
.hex_value:
    sub al, '0'
    cmp al, 9
    jbe .hex_decimal
    or al, 0x20
    sub al, 'a'-'0'
    cmp al, 5
    ja .hex_invalid
    add al, 10                     ; 0..5 + 10 also clears CF.
    ret
.hex_decimal:
    clc
    ret
.hex_invalid:
    stc
    ret

; rdi=body, rsi=length, rdx=key, rcx=dest, r8=capacity; rax=written. Clobbers caller-saved.
form_field:
    lea r9, [rdi+rsi]
    mov r10, rdx
    mov r11, rcx
.field:
    cmp rdi, r9
    jae .absent
    mov rsi, rdi
    mov rdx, r10
.compare:
    mov al, [rdx]
    test al, al
    jz .key_end
    cmp rsi, r9
    jae .absent
    cmp byte [rsi], '&'
    je .next_field
    cmp al, [rsi]
    jne .next_field
    inc rsi
    inc rdx
    jmp .compare
.key_end:
    cmp rsi, r9
    jae .absent
    cmp byte [rsi], '='
    jne .next_field
    inc rsi
    mov rdx, rsi
.value_end:
    cmp rdx, r9
    jae .decode
    cmp byte [rdx], '&'
    je .decode
    inc rdx
    jmp .value_end
.decode:
    sub rdx, rsi
    mov rdi, r11
    mov rcx, r8
    jmp url_decode
.next_field:
    cmp rdi, r9
    jae .absent
    cmp byte [rdi], '&'
    je .after_separator
    inc rdi
    jmp .next_field
.after_separator:
    inc rdi
    jmp .field
.absent:
    xor eax, eax
    ret
