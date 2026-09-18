%include "common.inc"
default rel

extern inv_base, inv_count, inv_rec, inv_reserve, inv_commit
global auth_init, admin_key, auth_check_admin
global invite_find, invite_create, invite_consume, invite_revoke, gen_hex
global cookie_get, session_resolve

section .rodata
key_path: db "geektaco.key", 0
key_label: db "Admin key: "
key_label_len equ $ - key_label
key_newline: db 10
hex_digits: db "0123456789abcdef"
ck_hdr:   db "cookie:"
ck_hdr_len equ $ - ck_hdr
ck_member: db "gt", 0
ck_admin:  db "ga", 0

section .bss
; Written only during startup, before any workers exist; read-only thereafter.
admin_key: resb KEY_LEN

section .text

; rdi=destination, rsi=even hex character count. Returns 0 or -1.
; Fixed stack storage keeps concurrent callers independent, including long output.
gen_hex:
    sub rsp, KEY_RAW
    mov r8, rdi
    mov r9, rsi
.chunk:
    test r9, r9
    jz .ok
    mov rsi, r9
    shr rsi, 1
    cmp rsi, KEY_RAW
    jbe .fill
    mov esi, KEY_RAW
.fill:
    mov r10, rsi
    mov rdi, rsp
    xor edx, edx
.random:
    mov eax, SYS_getrandom
    syscall
    test rax, rax
    jle .fail                     ; No weak fallback, or spin on zero progress.
    add rdi, rax
    sub rsi, rax
    jnz .random                   ; A short result leaves bytes still to fill.
    mov rdi, rsp
    mov ecx, r10d
.hex:
    movzx eax, byte [rdi]
    mov edx, eax
    shr eax, 4
    and edx, 15
    mov al, [hex_digits + rax]
    mov dl, [hex_digits + rdx]
    mov [r8], al
    mov [r8 + 1], dl
    inc rdi
    add r8, 2
    dec ecx
    jnz .hex
    shl r10, 1
    sub r9, r10
    jmp .chunk
.ok:
    xor eax, eax
    jmp .out
.fail:
    mov rax, -1
.out:
    add rsp, KEY_RAW
    ret

; Load the existing key, or exclusively create and announce a fresh one once.
; Returns 0 or -1; missing is the only existing-file error allowing creation.
auth_init:
    push rbx
    xor ebx, ebx                  ; SYS_read; changes to SYS_write on creation.
    mov edi, key_path
    xor esi, esi
    mov eax, SYS_open
    syscall
    test eax, eax
    jns .transfer
    cmp eax, -2                   ; ENOENT, not an unreadable/stale key.
    jne .fail
    mov edi, admin_key
    mov esi, KEY_LEN
    call gen_hex
    test eax, eax
    js .fail
    mov edi, key_path
    mov esi, O_WRONLY | O_CREAT | O_EXCL
    mov edx, KEY_MODE
    mov eax, SYS_open
    syscall
    test eax, eax
    js .fail                      ; Never adopt a key created by a racing process.
    mov ebx, SYS_write
.transfer:
    mov edi, eax
    mov esi, admin_key
    mov edx, KEY_LEN
    mov eax, ebx
    call key_io
    test eax, eax
    js .close_fail
    mov eax, SYS_close
    syscall
    test eax, eax
    js .fail
    test ebx, ebx
    jz .ok
    mov edi, 1
    mov esi, key_label
    mov edx, key_label_len
    mov eax, SYS_write
    call key_io
    test eax, eax
    js .fail
    mov esi, admin_key
    mov edx, KEY_LEN
    mov eax, SYS_write
    call key_io
    test eax, eax
    js .fail
    mov esi, key_newline
    mov edx, 1
    mov eax, SYS_write
    call key_io
    jmp .out
.ok:
    xor eax, eax
    jmp .out
.close_fail:
    mov eax, SYS_close
    syscall
.fail:
    mov rax, -1
.out:
    pop rbx
    ret

; Exact key I/O: eax=read/write, rdi=fd, rsi=buffer, rdx=nonzero length.
; Keeps rdi intact so the caller can close its fd even after a partial failure.
key_io:
    mov r8d, eax
.loop:
    mov eax, r8d
    syscall
    test rax, rax
    jle .fail
    add rsi, rax
    sub rdx, rax
    jnz .loop
    xor eax, eax
    ret
.fail:
    mov rax, -1
    ret

; rdi=candidate, rsi=length. Returns 1 for the admin key, otherwise 0.
auth_check_admin:
    xor eax, eax
    cmp rsi, KEY_LEN
    jne .out
    mov ecx, KEY_LEN
    ; Never exit on a differing byte: request timing can reveal this 32-char
    ; key one byte at a time. Every byte contributes before the branchless result.
.compare:
    mov dl, [rdi + rcx - 1]
    xor dl, [admin_key + rcx - 1]
    or al, dl
    dec ecx
    jnz .compare
    test al, al
    setz al
.out:
    ret

; rdi=code, rsi=length. Returns the first committed, unrevoked match or -1.
invite_find:
    cmp rsi, CODE_LEN
    jne .bad_length
    push rbx
    push rbp
    push r12
    mov rbx, rdi
    call inv_count
    mov rbp, rax
    xor r12d, r12d
.scan:
    cmp r12, rbp
    jae .missing
    mov rdi, r12
    call inv_rec
    cmp dword [rax + I_TIME], 0
    je .next                      ; Reserved slots are invisible until committed.
    test dword [rax + I_FLAGS], INV_FLAG_REVOKED
    jnz .next
    lea rdi, [rax + I_CODE]
    xor eax, eax
    mov ecx, CODE_LEN
.compare:
    mov dl, [rbx + rcx - 1]
    xor dl, [rdi + rcx - 1]
    or al, dl                     ; No byte-dependent branch within comparison.
    dec ecx
    jnz .compare
    test al, al
    jz .found
.next:
    inc r12
    jmp .scan
.found:
    mov rax, r12
    jmp .out
.missing:
    mov rax, -1
.out:
    pop r12
    pop rbp
    pop rbx
    ret
.bad_length:
    mov rax, -1
    ret

; Returns a new invite index or -1. A failed fill/commit leaves a skippable hole.
invite_create:
    push rbx
    call inv_reserve
    test rax, rax
    js .out
    mov rbx, rax
    mov rdi, rax
    call inv_rec
    mov rdi, rax
    xor eax, eax
    mov ecx, INV_SIZE / 8
    rep stosq
    sub rdi, INV_SIZE - I_CODE
    mov esi, CODE_LEN
    call gen_hex
    test eax, eax
    js .out
    mov rdi, rbx
    ; Publish only after the code/body is complete. inv_commit stores I_TIME last;
    ; x86-64 store ordering makes it visible last without an mfence.
    call inv_commit
    test eax, eax
    js .out
    mov rax, rbx
.out:
    pop rbx
    ret

; rdi=invite index, rsi=post index. Returns 1 for the sole winner, otherwise 0.
invite_consume:
    push rbx
    push rbp
    sub rsp, 8
    mov rbx, rdi
    lea rbp, [rsi + 1]             ; Zero is the unused sentinel.
    call inv_count
    cmp rbx, rax
    jae .bad
    mov rdi, rbx
    call inv_rec
    mov rdx, rax
    xor eax, eax
    ; A load followed by a store would let two concurrent redeemers both win.
    lock cmpxchg [rdx + I_USED], ebp
    setz dl
    movzx eax, dl
    jmp .out
.bad:
    xor eax, eax
.out:
    add rsp, 8
    pop rbp
    pop rbx
    ret

; rdi=invite index. Returns 0 or -1. Flag updates must coexist with worker reads.
invite_revoke:
    push rbx
    mov rbx, rdi
    call inv_count
    cmp rbx, rax
    jae .bad
    mov rdi, rbx
    call inv_rec
    lock or dword [rax + I_FLAGS], INV_FLAG_REVOKED
    xor eax, eax
    jmp .out
.bad:
    mov rax, -1
.out:
    pop rbx
    ret

; ---------------------------------------------------------------------------
; cookie_get(rdi=request buf, rsi=buf len, rdx=NUL-terminated name,
;            rcx=dest, r8=dest cap) -> rax = bytes copied, 0 if absent.
;
; Scans ONLY the header region: a "Cookie:" appearing after the blank line is
; request body, not a header, and honouring it would let a poster forge a
; session. The name must match at a separator boundary and be followed by '=',
; so "gt" does not match "gtx=" or the tail of "xgt=".
; ---------------------------------------------------------------------------
cookie_get:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov rbx, rdi                    ; cursor
    lea r12, [rdi + rsi]            ; end of buffer
    mov r13, rdx                    ; wanted name
    mov r14, rcx                    ; dest
    mov r15, r8                     ; dest capacity

.line:
    cmp rbx, r12
    jae .absent
    ; A bare CRLF or LF here ends the headers; stop before the body.
    cmp byte [rbx], 10
    je .absent
    cmp byte [rbx], 13
    je .absent
    ; Case-insensitive compare against "cookie:".
    lea rax, [rbx + ck_hdr_len]
    cmp rax, r12
    ja .next_line
    xor ecx, ecx
.hdr_cmp:
    cmp ecx, ck_hdr_len
    jae .found_hdr
    movzx eax, byte [rbx + rcx]
    or al, 0x20                     ; fold to lowercase
    cmp al, [ck_hdr + rcx]
    jne .next_line
    inc ecx
    jmp .hdr_cmp

.next_line:
    ; Advance past this header line.
    cmp rbx, r12
    jae .absent
    cmp byte [rbx], 10
    je .eol
    inc rbx
    jmp .next_line
.eol:
    inc rbx
    jmp .line

.found_hdr:
    add rbx, ck_hdr_len             ; rbx -> cookie list
.pair:
    ; Skip spaces and separators before a name.
    cmp rbx, r12
    jae .absent
    movzx eax, byte [rbx]
    cmp al, ' '
    je .skip1
    cmp al, ';'
    je .skip1
    cmp al, 9
    jne .try_name
.skip1:
    inc rbx
    jmp .pair

.try_name:
    cmp al, 13
    je .absent
    cmp al, 10
    je .absent
    ; Compare the wanted name at this boundary.
    xor ecx, ecx
.name_cmp:
    movzx eax, byte [r13 + rcx]
    test al, al
    jz .name_end
    lea rdx, [rbx + rcx]
    cmp rdx, r12
    jae .absent
    cmp al, [rbx + rcx]
    jne .skip_pair
    inc ecx
    jmp .name_cmp
.name_end:
    ; Full name matched; it only counts if the next byte is '='.
    lea rdx, [rbx + rcx]
    cmp rdx, r12
    jae .absent
    cmp byte [rdx], '='
    jne .skip_pair
    inc rdx                         ; rdx -> value
    ; Copy the value up to ';', CR, LF, end of buffer, or capacity.
    xor eax, eax                    ; bytes copied
.copy:
    cmp rdx, r12
    jae .done
    cmp eax, r15d
    jae .done
    movzx ecx, byte [rdx]
    cmp cl, ';'
    je .done
    cmp cl, 13
    je .done
    cmp cl, 10
    je .done
    mov [r14 + rax], cl
    inc rax
    inc rdx
    jmp .copy
.done:
    jmp .out

.skip_pair:
    ; Advance to the next ';' within this header line.
    cmp rbx, r12
    jae .absent
    movzx eax, byte [rbx]
    cmp al, 13
    je .absent
    cmp al, 10
    je .absent
    inc rbx
    cmp al, ';'
    jne .skip_pair
    jmp .pair

.absent:
    xor eax, eax
.out:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ---------------------------------------------------------------------------
; session_resolve(rdi=request buf, rsi=buf len)
;
; Resolves the caller's identity exactly once per request and caches it in
; TLS, so no handler or page builder ever re-parses a cookie. Writes:
;   [rbx+TLS_INVITE] = invite index, or sign-extended -1
;   [rbx+TLS_ADMIN]  = 1 or 0
; invite_find already rejects uncommitted and revoked invites.
; ---------------------------------------------------------------------------
session_resolve:
    push rbx
    push r12
    push r13
    sub rsp, 48                     ; scratch for the extracted cookie value
    mov r12, rdi
    mov r13, rsi
    mov rbx, [fs:TLS_SELF]
    mov qword [rbx + TLS_INVITE], -1
    mov qword [rbx + TLS_ADMIN], 0

    ; --- member token -------------------------------------------------------
    mov rdi, r12
    mov rsi, r13
    mov edx, ck_member
    mov rcx, rsp
    mov r8d, CODE_LEN
    call cookie_get
    cmp rax, CODE_LEN               ; a short or over-long value is not a code
    jne .admin
    mov rdi, rsp
    mov esi, CODE_LEN
    call invite_find
    movsx rax, eax                  ; keep -1 sign-extended for signed tests
    mov [rbx + TLS_INVITE], rax

.admin:
    ; --- admin token --------------------------------------------------------
    mov rdi, r12
    mov rsi, r13
    mov edx, ck_admin
    mov rcx, rsp
    mov r8d, KEY_LEN
    call cookie_get
    cmp rax, KEY_LEN
    jne .out
    mov rdi, rsp
    mov esi, KEY_LEN
    call auth_check_admin
    mov [rbx + TLS_ADMIN], rax

.out:
    add rsp, 48
    pop r13
    pop r12
    pop rbx
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
