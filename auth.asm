%include "common.inc"
default rel

extern inv_base, inv_count, inv_rec, inv_reserve, inv_commit
extern map_file, record_ptr, record_reserve, record_commit, now_secs
global auth_init, admin_key, auth_check_admin
global invite_find, invite_create, invite_consume, invite_revoke, gen_hex
global cookie_get, session_resolve
global user_init, usr_count, usr_rec, user_find, user_create, user_check
global session_make, session_verify, sha256

section .rodata
key_path: db "geektaco.key", 0
usr_path: db "geektaco.usr", 0
; sockaddr_alg for the kernel hash socket: family, type[14], feat, mask,
; name[64]. 88 bytes, and the kernel rejects a shorter addrlen.
align 8
alg_addr: dw AF_ALG
          db "hash", 0,0,0,0,0,0,0,0,0,0
          dd 0, 0
          db "sha256"
          times 58 db 0
alg_addr_len equ $ - alg_addr
key_label: db "Admin key: "
key_label_len equ $ - key_label
key_newline: db 10
hex_digits: db "0123456789abcdef"
ck_hdr:   db "cookie:"
ck_hdr_len equ $ - ck_hdr
ck_sess:   db "gs", 0
ck_admin:  db "ga", 0

section .bss
; Written only during startup, before any workers exist; read-only thereafter.
admin_key: resb KEY_LEN
; Session secret: generated once at startup before any worker exists, then
; read-only. Regenerating per boot is why cookies do not survive a restart.
sess_secret: resb SECRET_LEN
usr_base: resq 1

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
    push KEY_RAW
    pop rsi
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
    push -1
    pop rax
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
    push SYS_open
    pop rax
    syscall
    test eax, eax
    jns .transfer
    cmp eax, -2                   ; ENOENT, not an unreadable/stale key.
    jne .fail
    mov edi, admin_key
    push KEY_LEN
    pop rsi
    call gen_hex
    test eax, eax
    js .fail
    mov edi, key_path
    mov esi, O_WRONLY | O_CREAT | O_EXCL
    mov edx, KEY_MODE
    push SYS_open
    pop rax
    syscall
    test eax, eax
    js .fail                      ; Never adopt a key created by a racing process.
    push SYS_write
    pop rbx
.transfer:
    mov edi, eax
    mov esi, admin_key
    push KEY_LEN
    pop rdx
    mov eax, ebx
    call key_io
    test eax, eax
    js .close_fail
    push SYS_close
    pop rax
    syscall
    test eax, eax
    js .fail
    test ebx, ebx
    jz .ok
    push 1
    pop rdi
    mov esi, key_label
    push key_label_len
    pop rdx
    push SYS_write
    pop rax
    call key_io
    test eax, eax
    js .fail
    mov esi, admin_key
    push KEY_LEN
    pop rdx
    push SYS_write
    pop rax
    call key_io
    test eax, eax
    js .fail
    mov esi, key_newline
    push 1
    pop rdx
    push SYS_write
    pop rax
    call key_io
    jmp .out
.ok:
    xor eax, eax
    jmp .out
.close_fail:
    push SYS_close
    pop rax
    syscall
.fail:
    push -1
    pop rax
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
    push -1
    pop rax
    ret

; rdi=candidate, rsi=length. Returns 1 for the admin key, otherwise 0.
auth_check_admin:
    xor eax, eax
    cmp rsi, KEY_LEN
    jne .out
    push KEY_LEN
    pop rcx
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
    push CODE_LEN
    pop rcx
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
    push -1
    pop rax
.out:
    pop r12
    pop rbp
    pop rbx
    ret
.bad_length:
    push -1
    pop rax
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
    push INV_SIZE / 8
    pop rcx
    rep stosq
    sub rdi, INV_SIZE - I_CODE
    push CODE_LEN
    pop rsi
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
    push -1
    pop rax
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
    mov qword [rbx + TLS_USER], -1
    mov qword [rbx + TLS_ADMIN], 0

    ; --- session cookie -----------------------------------------------------
    ; The invite is no longer a session: it is a one-shot ticket spent at
    ; registration. Identity now comes from the signed session cookie.
    mov rdi, r12
    mov rsi, r13
    mov edx, ck_sess
    mov rcx, rsp
    push SESS_LEN
    pop r8
    call cookie_get
    cmp rax, SESS_LEN
    jne .admin
    mov rdi, rsp
    push SESS_LEN
    pop rsi
    call session_verify
    movsx rax, eax                  ; keep -1 sign-extended for signed tests
    mov [rbx + TLS_USER], rax

.admin:
    ; --- admin token --------------------------------------------------------
    mov rdi, r12
    mov rsi, r13
    mov edx, ck_admin
    mov rcx, rsp
    push KEY_LEN
    pop r8
    call cookie_get
    cmp rax, KEY_LEN
    jne .out
    mov rdi, rsp
    push KEY_LEN
    pop rsi
    call auth_check_admin
    mov [rbx + TLS_ADMIN], rax

.out:
    add rsp, 48
    pop r13
    pop r12
    pop rbx
    ret

; ---------------------------------------------------------------------------
; sha256(rdi=data, rsi=len, rdx=dest32) -> rax = 0 ok, -1 fail.
;
; Hashing through AF_ALG rather than a hand-rolled SHA-256: the kernel already
; has a correct one, and 400 bytes of hand-written crypto in a 12 KB forum is
; the last thing anyone should be asked to audit.
;
; NOTE ON STRENGTH: this is salted SHA-256, not a password KDF. A real
; deployment wants argon2 or bcrypt. The threat model here is casual
; credential reuse on an invite-gated board, not an offline attack on a
; stolen database. Saying so plainly beats implying otherwise.
;
; The operation fd is closed on every path: four workers leaking one fd per
; login attempt would exhaust the table, and that is a denial of service
; anyone who can reach /login could trigger.
; clobbers: caller-saved; preserves rbx, r12-r14.
sha256:
        push    rbx
        push    r12
        push    r13
        push    r14
        mov     r12, rdi                ; data
        mov     r13, rsi                ; len
        mov     r14, rdx                ; dest
        ; socket(AF_ALG, SOCK_SEQPACKET, 0)
        push     SYS_socket
        pop     rax
        push     AF_ALG
        pop     rdi
        push     SOCK_SEQPACKET
        pop     rsi
        xor     edx, edx
        syscall
        test    eax, eax
        js      .fail
        mov     ebx, eax                ; bound socket
        push     SYS_bind
        pop     rax
        mov     edi, ebx
        mov     esi, alg_addr
        push     alg_addr_len
        pop     rdx
        syscall
        test    eax, eax
        js      .close_bound
        push     SYS_accept
        pop     rax
        mov     edi, ebx
        xor     esi, esi
        xor     edx, edx
        syscall
        test    eax, eax
        js      .close_bound
        push    rax                     ; operation fd
        push     SYS_write
        pop     rax
        mov     edi, [rsp]
        mov     rsi, r12
        mov     rdx, r13
        syscall
        test    eax, eax
        js      .close_both
        push     SYS_read
        pop     rax
        mov     edi, [rsp]
        mov     rsi, r14
        push     HASH_LEN
        pop     rdx
        syscall
        cmp     eax, HASH_LEN
        jne     .close_both
        push     SYS_close
        pop     rax
        mov     edi, [rsp]
        syscall
        add     rsp, 8
        push     SYS_close
        pop     rax
        mov     edi, ebx
        syscall
        xor     eax, eax
        jmp     .out
.close_both:
        push     SYS_close
        pop     rax
        mov     edi, [rsp]
        syscall
        add     rsp, 8
.close_bound:
        push     SYS_close
        pop     rax
        mov     edi, ebx
        syscall
.fail:
        push     -1
        pop     rax
.out:
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        ret

; ---------------------------------------------------------------------------
; user_init() -> 0 / -1. Maps the user file and draws the session secret.
; Startup only, before any worker exists.
user_init:
        mov     edi, usr_path
        mov     rsi, USR_MAGIC
        mov     edx, USR_BYTES
        call    map_file
        cmp     rax, -1
        je      .fail
        mov     [usr_base], rax
        mov     edx, MAX_USERS
        cmp     [rax + H_COUNT], edx
        jbe     .secret
        mov     [rax + H_COUNT], edx    ; clamp a corrupt cursor
.secret:
        mov     eax, SYS_getrandom
        mov     edi, sess_secret
        push     SECRET_LEN
        pop     rsi
        xor     edx, edx
        syscall
        cmp     eax, SECRET_LEN
        jne     .fail
        xor     eax, eax
        ret
.fail:
        push     -1
        pop     rax
        ret

; usr_count() -> rax = clamped cursor.
usr_count:
        mov     rsi, [usr_base]
        mov     eax, [rsi + H_COUNT]
        cmp     eax, MAX_USERS
        jbe     .ok
        mov     eax, MAX_USERS
.ok:
        ret

; usr_rec(rdi=index) -> pointer, or 0.
usr_rec:
        mov     rsi, [usr_base]
        mov     edx, MAX_USERS
        push     USR_SHIFT
        pop     rcx
        jmp     record_ptr

; usr_reserve() -> index, or -1.
usr_reserve:
        mov     rsi, [usr_base]
        mov     edx, MAX_USERS
        jmp     record_reserve

; usr_commit(rdi=index) -> 0 / -1. Stamps U_TIME last: that is the publish.
usr_commit:
        push    rdx
        call    usr_rec
        push     U_TIME
        pop     rdx
        jmp     record_commit

; ---------------------------------------------------------------------------
; user_find(rdi=name, rsi=len) -> index or -1. Names are stored lowercased,
; and the caller lowercases before calling, so this is a plain compare.
user_find:
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        mov     r12, rdi
        mov     r13, rsi
        cmp     r13, NAME_MAX
        jae     .none
        test    r13, r13
        jz      .none
        call    usr_count
        mov     r14, rax
        xor     ebx, ebx
.scan:
        cmp     rbx, r14
        jae     .none
        mov     rdi, rbx
        call    usr_rec
        test    rax, rax
        jz      .none
        cmp     dword [rax + U_TIME], 0
        je      .next                   ; reserved, not yet published
        mov     rbp, rax
        ; length must match exactly: the field is NUL padded
        cmp     byte [rbp + U_NAME + r13], 0
        jne     .next
        xor     ecx, ecx
.cmp:
        cmp     rcx, r13
        jae     .hit
        mov     dl, [r12 + rcx]
        cmp     dl, [rbp + U_NAME + rcx]
        jne     .next
        inc     rcx
        jmp     .cmp
.hit:
        mov     rax, rbx
        jmp     .out
.next:
        inc     rbx
        jmp     .scan
.none:
        push     -1
        pop     rax
.out:
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        ret

; name_ok(rdi=ptr, rsi=len) -> 1 if every byte is [a-z0-9_-]. The caller has
; already lowercased, so uppercase is not accepted here by design.
name_ok:
        test    rsi, rsi
        jz      .no
        cmp     rsi, NAME_MAX
        jae     .no
        xor     ecx, ecx
.loop:
        cmp     rcx, rsi
        jae     .yes
        movzx   eax, byte [rdi + rcx]
        cmp     al, 'a'
        jb      .digit
        cmp     al, 'z'
        jbe     .ok1
        jmp     .no
.digit:
        cmp     al, '0'
        jb      .punct
        cmp     al, '9'
        jbe     .ok1
        jmp     .no
.punct:
        cmp     al, '_'
        je      .ok1
        cmp     al, '-'
        jne     .no
.ok1:
        inc     rcx
        jmp     .loop
.yes:
        push     1
        pop     rax
        ret
.no:
        xor     eax, eax
        ret

; hash_pw(rdi=salt16, rsi=pass, rdx=passlen, rcx=dest32) -> 0 / -1.
; Hashes SALT_LEN + passlen bytes as one buffer: one write, one read.
hash_pw:
        push    rbx
        push    r12
        sub     rsp, 96                 ; salt(16) + password(64) + slack
        mov     rbx, rcx                ; dest
        mov     r12, rdx                ; passlen
        cmp     r12, PASS_MAX
        ja      .fail
        mov     rcx, SALT_LEN / 8
        mov     rax, rdi
        mov     rdx, rsp
.cp_salt:
        mov     r8, [rax]
        mov     [rdx], r8
        add     rax, 8
        add     rdx, 8
        dec     rcx
        jnz     .cp_salt
        xor     ecx, ecx
.cp_pass:
        cmp     rcx, r12
        jae     .hash
        mov     al, [rsi + rcx]
        mov     [rsp + SALT_LEN + rcx], al
        inc     rcx
        jmp     .cp_pass
.hash:
        mov     rdi, rsp
        lea     rsi, [r12 + SALT_LEN]
        mov     rdx, rbx
        call    sha256
        jmp     .out
.fail:
        push     -1
        pop     rax
.out:
        add     rsp, 96
        pop     r12
        pop     rbx
        ret

; user_create(rdi=name, rsi=namelen, rdx=pass, rcx=passlen, r8=invite index)
;   -> index, or a negative error: -4 malformed name, -5 short password,
;      -3 name taken, -2 invite unusable, -1 storage failure.
; The error codes match the page builders' error argument.
user_create:
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        push    r15
        mov     rbx, rdi
        mov     r12, rsi
        mov     r13, rdx
        mov     r14, rcx
        mov     r15, r8
        call    name_ok
        test    eax, eax
        jz      .bad_name
        cmp     r14, PASS_MIN
        jb      .short_pw
        cmp     r14, PASS_MAX
        ja      .short_pw
        mov     rdi, rbx
        mov     rsi, r12
        call    user_find
        test    rax, rax
        jns     .taken
        ; Claim the invite BEFORE writing anything: the cmpxchg inside is what
        ; makes two simultaneous registrations resolve to exactly one winner.
        mov     rdi, r15
        xor     esi, esi                ; no post index yet; 1 marks it used
        call    invite_consume
        test    eax, eax
        jz      .bad_invite
        call    usr_reserve
        test    eax, eax
        js      .fail
        mov     rbp, rax                ; new index
        mov     rdi, rbp
        call    usr_rec
        test    rax, rax
        jz      .fail
        push    rax                     ; record pointer
        ; zero the record so unused bytes stay NUL
        mov     rdi, rax
        xor     eax, eax
        push     USR_SIZE / 8
        pop     rcx
        rep     stosq
        mov     rax, [rsp]
        mov     [rax + U_INVITE], r15d
        ; name
        xor     ecx, ecx
.cp_name:
        cmp     rcx, r12
        jae     .salt
        mov     dl, [rbx + rcx]
        mov     [rax + U_NAME + rcx], dl
        inc     rcx
        jmp     .cp_name
.salt:
        lea     rdi, [rax + U_SALT]
        push     SALT_LEN
        pop     rsi
        xor     edx, edx
        push    rax
        mov     eax, SYS_getrandom
        syscall
        pop     rdi                     ; record pointer back
        cmp     eax, SALT_LEN
        jne     .fail_pop
        lea     rdi, [rdi + U_SALT]
        mov     rsi, r13
        mov     rdx, r14
        mov     rcx, [rsp]
        add     rcx, U_HASH
        call    hash_pw
        test    rax, rax
        js      .fail_pop
        add     rsp, 8
        mov     rdi, rbp
        call    usr_commit              ; publishes: U_TIME written last
        mov     rax, rbp
        jmp     .out
.fail_pop:
        add     rsp, 8
.fail:
        push     -1
        pop     rax
        jmp     .out
.bad_name:
        mov     rax, -4
        jmp     .out
.short_pw:
        mov     rax, -5
        jmp     .out
.taken:
        mov     rax, -3
        jmp     .out
.bad_invite:
        mov     rax, -2
.out:
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        ret

; user_check(rdi=name, rsi=len, rdx=pass, rcx=passlen) -> index or -1.
; Constant-time hash comparison; banned accounts are rejected.
user_check:
        push    rbx
        push    rbp
        push    r12
        push    r13
        sub     rsp, 40                 ; room for the candidate digest
        mov     r12, rdx                ; pass
        mov     r13, rcx                ; passlen
        call    user_find
        test    rax, rax
        js      .no
        mov     rbx, rax
        mov     rdi, rbx
        call    usr_rec
        test    rax, rax
        jz      .no
        test    byte [rax + U_FLAGS], USR_FLAG_BANNED
        jnz     .no
        mov     rbp, rax
        lea     rdi, [rbp + U_SALT]
        mov     rsi, r12
        mov     rdx, r13
        mov     rcx, rsp
        call    hash_pw
        test    rax, rax
        js      .no
        ; Accumulate differences across all 32 bytes. An early exit on the
        ; first mismatch leaks the stored hash a byte at a time to anyone who
        ; can time the request.
        xor     eax, eax
        xor     ecx, ecx
.cmp:
        cmp     ecx, HASH_LEN
        jae     .verdict
        mov     dl, [rsp + rcx]
        xor     dl, [rbp + U_HASH + rcx]
        or      al, dl
        inc     ecx
        jmp     .cmp
.verdict:
        test    al, al
        jnz     .no
        mov     rax, rbx
        jmp     .out
.no:
        push     -1
        pop     rax
.out:
        add     rsp, 40
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        ret

; ---------------------------------------------------------------------------
; Stateless sessions. The cookie is "<index-hex8><mac-hex16>", where the MAC
; is the first 8 bytes of SHA-256(secret || index-hex8). Unforgeable without
; the secret, and because the secret is drawn fresh at every startup, a
; restart invalidates every outstanding cookie -- which is the right default
; and costs nothing.

; sess_mac(rdi=idxhex8, rsi=dest16hex) -- write the MAC as 16 hex chars.
sess_mac:
        push    rbx
        push    r12
        sub     rsp, 80                 ; secret||idx buffer + digest
        mov     rbx, rsi
        mov     r12, rdi
        push     SECRET_LEN / 8
        pop     rcx
        mov     esi, sess_secret
        mov     rdx, rsp
.cp:
        mov     rax, [rsi]
        mov     [rdx], rax
        add     rsi, 8
        add     rdx, 8
        dec     ecx
        jnz     .cp
        mov     rax, [r12]              ; the 8 index hex chars
        mov     [rsp + SECRET_LEN], rax
        mov     rdi, rsp
        push     SECRET_LEN + SESS_IDXLEN
        pop     rsi
        lea     rdx, [rsp + 40]
        call    sha256
        test    rax, rax
        js      .out
        ; first 8 digest bytes -> 16 lowercase hex chars
        xor     ecx, ecx
.hex:
        cmp     ecx, 8
        jae     .out
        movzx   eax, byte [rsp + 40 + rcx]
        mov     edx, eax
        shr     eax, 4
        and     edx, 15
        mov     al, [hex_digits + rax]
        mov     [rbx + rcx*2], al
        mov     dl, [hex_digits + rdx]
        mov     [rbx + rcx*2 + 1], dl
        inc     ecx
        jmp     .hex
.out:
        add     rsp, 80
        pop     r12
        pop     rbx
        ret

; idx_hex(rdi=value, rsi=dest8) -- 8 lowercase hex chars, zero padded.
idx_hex:
        push     8
        pop     rcx
.loop:
        dec     ecx
        mov     eax, edi
        and     eax, 15
        mov     al, [hex_digits + rax]
        mov     [rsi + rcx], al
        shr     edi, 4
        test    ecx, ecx
        jnz     .loop
        ret

; session_make(rdi=user index, rsi=dest) -- writes SESS_LEN chars.
session_make:
        push    rbx
        mov     rbx, rsi
        mov     rsi, rbx
        call    idx_hex
        mov     rdi, rbx
        lea     rsi, [rbx + SESS_IDXLEN]
        call    sess_mac
        pop     rbx
        ret

; session_verify(rdi=cookie, rsi=len) -> user index, or -1.
session_verify:
        push    rbx
        push    r12
        sub     rsp, 24                 ; recomputed MAC
        cmp     rsi, SESS_LEN
        jne     .no
        mov     rbx, rdi
        mov     rdi, rbx
        mov     rsi, rsp
        call    sess_mac
        ; Constant-time: compare all 16 MAC chars, accumulating differences.
        ; A byte-at-a-time early exit would let an attacker forge a session
        ; by timing, one hex char at a time.
        xor     eax, eax
        xor     ecx, ecx
.cmp:
        cmp     ecx, SESS_MACLEN
        jae     .verdict
        mov     dl, [rsp + rcx]
        xor     dl, [rbx + SESS_IDXLEN + rcx]
        or      al, dl
        inc     ecx
        jmp     .cmp
.verdict:
        test    al, al
        jnz     .no
        ; MAC is good, so the index is authentic. Parse it and bounds-check.
        xor     r12d, r12d
        xor     ecx, ecx
.parse:
        cmp     ecx, SESS_IDXLEN
        jae     .bounds
        movzx   eax, byte [rbx + rcx]
        sub     eax, '0'
        cmp     eax, 9
        jbe     .digit
        sub     eax, 'a' - '0' - 10
        cmp     eax, 15
        ja      .no
        cmp     eax, 10
        jb      .no
.digit:
        shl     r12d, 4
        or      r12d, eax
        inc     ecx
        jmp     .parse
.bounds:
        call    usr_count
        cmp     r12, rax
        jae     .no
        mov     rdi, r12
        call    usr_rec
        test    rax, rax
        jz      .no
        cmp     dword [rax + U_TIME], 0
        je      .no                     ; never honour an unpublished record
        test    byte [rax + U_FLAGS], USR_FLAG_BANNED
        jnz     .no                     ; a ban takes effect on the next request
        mov     rax, r12
        jmp     .out
.no:
        push     -1
        pop     rax
.out:
        add     rsp, 24
        pop     r12
        pop     rbx
        ret

section .note.GNU-stack noalloc noexec nowrite progbits
