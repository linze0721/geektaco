%include "common.inc"
default rel

; Linux signal constants omitted from the frozen shared include.
SIGPIPE          equ 13
SIG_IGN          equ 1

global _start
extern db_init, db_reserve, db_rec, db_commit, auth_init, user_init
extern session_resolve, invite_create, invite_revoke, invite_find
extern user_create, user_check, usr_rec, session_make
extern http_parse, parse_uint, form_field
extern render_index, render_thread, render_404, render_redirect
extern render_login, render_register, render_admin, render_403, render_head_cookie

section .text

; _start: no args; never returns. Owns all registers and the server lifetime.
_start:
    cld
    push SYS_rt_sigaction
    pop rax
    push SIGPIPE
    pop rdi
    mov esi, ignore_sigpipe
    xor edx, edx
    push 8
    pop r10
    syscall                         ; Best effort: dead clients must not kill us.

    call db_init
    test eax, eax
    js .database_error
    call auth_init
    test rax, rax
    js .auth_error
    call user_init
    test eax, eax
    js .auth_error

    push SYS_socket
    pop rax
    push AF_INET
    pop rdi
    push SOCK_STREAM
    pop rsi
    xor edx, edx
    syscall
    test eax, eax
    js .socket_error
    mov r12d, eax                    ; Listening fd survives calls and syscalls.

    push SYS_setsockopt
    pop rax
    mov edi, r12d
    push SOL_SOCKET
    pop rsi
    push SO_REUSEADDR
    pop rdx
    mov r10d, ignore_sigpipe         ; SIG_IGN's low word is also integer one.
    push 4
    pop r8
    syscall
    test eax, eax
    js .socket_error

    push SYS_bind
    pop rax
    mov edi, r12d
    mov esi, listen_address
    push 16
    pop rdx
    syscall
    test eax, eax
    js .socket_error

    push SYS_listen
    pop rax
    mov edi, r12d
    push BACKLOG
    pop rsi
    syscall
    test eax, eax
    js .socket_error

    call .tls_setup
    test rax, rax
    js .thread_error
    push THREADS - 1
    pop r14
.spawn:
    call .spawn_worker
    dec r14d                       ; Failed spawns leave the other workers alive.
    jnz .spawn

    push SYS_write
    pop rax
    push 1
    pop rdi
    mov esi, banner
    push banner_len
    pop rdx
    syscall

.accept:
    ; Linux wakes one accept waiter per connection: no queue or scheduler.
    push SYS_accept
    pop rax
    mov edi, r12d
    xor esi, esi
    xor edx, edx
    syscall
    test eax, eax
    js .accept
    mov r13d, eax                    ; Current client fd.
    mov rbx, [fs:TLS_SELF]          ; Per-request base; every callee preserves it.

    xor eax, eax                    ; SYS_read
    mov edi, r13d
    mov rsi, [rbx + TLS_REQ]
    mov edx, REQ_SIZE
    syscall
    test eax, eax
    jle .close_client
    mov r14d, eax                   ; Total bytes received, not the last read.

    mov rdi, [rbx + TLS_REQ]
    mov esi, r14d
    call http_parse
    test eax, eax
    js .early_404
    ; http_parse stores M_GET/M_POST/M_OTHER as a zero-extended qword.
    cmp byte [rbx + TLS_METHOD], M_POST
    jne .resolve                    ; GET carries cookies too: /admin needs them
    mov rax, [rbx + TLS_CLEN]
    cmp [rbx + TLS_BODYLEN], rax
    jae .resolve
    cmp qword [rbx + TLS_BODY], 0
    je .early_404

.read_body:
    cmp r14d, REQ_SIZE
    jae .early_404                  ; Never persist an incomplete POST body.
    xor eax, eax                    ; SYS_read
    mov edi, r13d
    mov rsi, [rbx + TLS_REQ]
    add rsi, r14
    mov edx, REQ_SIZE
    sub edx, r14d
    syscall
    test eax, eax
    jle .early_404
    add r14d, eax

    mov rax, [rbx + TLS_BODY]
    sub rax, [rbx + TLS_REQ]
    mov edx, r14d
    sub rdx, rax
    mov [rbx + TLS_BODYLEN], rdx
    cmp rdx, [rbx + TLS_CLEN]
    jb .read_body

.resolve:
; Identity is resolved exactly once per request, after any body is complete so
; a split POST cannot be routed on a half-read header block. Handlers and page
; builders read TLS_USER/TLS_ADMIN; nothing else parses a cookie.
    mov rdi, [rbx + TLS_REQ]
    mov esi, r14d
    call session_resolve
    ; Every route handler ends by tail-jumping into a page builder, whose ret
    ; lands on .respond. Handlers keep the stack balanced within this frame.
    call .route

.respond:
    mov r15, [rbx + TLS_OBUF]
    mov r14, [rbx + TLS_OBLEN]
.write_response:
    test r14, r14
    jz .close_client
    push SYS_write
    pop rax
    mov edi, r13d
    mov rsi, r15
    mov rdx, r14
    syscall
    test eax, eax
    jle .close_client               ; Includes EPIPE; abandon only this client.
    add r15, rax
    sub r14, rax
    jmp .write_response

.close_client:
    push SYS_shutdown
    pop rax
    mov edi, r13d
    push 1                         ; SHUT_WR
    pop rsi
    syscall
    push SYS_close
    pop rax
    syscall
    jmp .accept

; Rejected before routing: no identity is resolved for a malformed request.
.early_404:
    call render_404
    jmp .respond

; Called with rbx = TLS base; returns through a page builder's ret.
.route:
    mov rdi, [rbx + TLS_PATH]
    mov rcx, [rbx + TLS_PATHLEN]
    mov eax, [rbx + TLS_METHOD]
    dec eax                         ; M_GET -> -1, M_POST -> 0, M_OTHER -> 1
    jz .post
    jns .not_found

.get:
    cmp ecx, 1
    jne .get_page
    cmp byte [rdi], '/'
    jne .not_found
    xor edi, edi                    ; page 0
    jmp render_index

.get_page:
    cmp ecx, 4                      ; "/p/" + at least one digit
    jb .get_login
    cmp word [rdi], '/p'
    jne .get_login
    cmp byte [rdi + 2], '/'
    jne .get_login
    add rdi, 3
    lea esi, [rcx - 3]
    call parse_uint
    test edx, edx
    jz .not_found                   ; "/p/abc" is malformed, not page 0
    xchg eax, edi
    jmp render_index

; A non-matching path of the same length MUST fall through, not 404: "/t/60"
; is also 5 bytes, and "/t/123" is also 6.
.get_login:
    cmp ecx, 6
    jne .get_register
    cmp dword [rdi], '/log'
    jne .get_register
    cmp word [rdi + 4], 'in'
    jne .get_register
    xor edi, edi                    ; no error yet
    jmp render_login

.get_register:
    cmp ecx, 9
    jne .get_admin
    cmp dword [rdi], '/reg'
    jne .get_admin
    cmp dword [rdi + 4], 'iste'
    jne .get_admin
    cmp byte [rdi + 8], 'r'
    jne .get_admin
    xor edi, edi
    jmp render_register

.get_admin:
    cmp ecx, 6
    jne .get_thread
    cmp dword [rdi], '/adm'
    jne .get_thread
    cmp word [rdi + 4], 'in'
    jne .get_thread
    ; TLS_ADMIN is always the qword 0 or 1, so its low byte decides.
    cmp byte [rbx + TLS_ADMIN], 1
    jne .not_found              ; 404 not 403: do not confirm the panel exists.
    jmp render_admin

; /t/<n> and /t/<n>/<m>. The trailing segment, when present, must parse: a
; malformed "/t/0/abc" is a bad URL, not silently page 0.
.get_thread:
    cmp ecx, 3
    jb .not_found
    cmp word [rdi], '/t'
    jne .not_found
    cmp byte [rdi + 2], '/'
    jne .not_found
    add rdi, 3
    lea esi, [rcx - 3]
    ; parse_uint leaves rdi/rsi intact; the root index goes in rbp.
    call parse_uint
    test edx, edx
    jz .not_found
    mov ebp, eax                    ; root index
    sub esi, edx                    ; bytes after the index digits
    jz .thread_go                   ; esi = 0: first reply page
    add rdi, rdx                    ; advance past the digits
    cmp byte [rdi], '/'
    jne .not_found
    inc rdi
    dec esi
    jz .not_found                   ; "/t/<n>/" with no page number
    call parse_uint
    test edx, edx
    jz .not_found
    cmp edx, esi
    jne .not_found                  ; trailing junk after the page number
    xchg eax, esi
.thread_go:
    mov edi, ebp
    jmp render_thread

.forbidden:
    jmp render_403

.post:
    cmp ecx, 4
    jne .post_login
    cmp dword [rdi], '/new'
    jne .not_found
    cmp qword [rbx + TLS_USER], 0
    jl .forbidden               ; signed: TLS_USER is a sign-extended -1.
    jmp .new

.not_found:
    jmp render_404

; Same-length paths must fall through to the next candidate, never 404:
; "/login" and "/reply" are both 6 bytes.
.post_login:
    cmp ecx, 6
    jne .post_logout
    cmp dword [rdi], '/log'
    jne .post_reply
    cmp word [rdi + 4], 'in'
    je .login

.post_reply:
    cmp dword [rdi], '/rep'
    jne .not_found
    cmp word [rdi + 4], 'ly'
    jne .not_found
    cmp qword [rbx + TLS_USER], 0
    jl .forbidden               ; signed: TLS_USER is a sign-extended -1.
    jmp .reply

.post_logout:
    cmp ecx, 7
    jne .post_register
    cmp dword [rdi], '/log'
    jne .not_found
    cmp word [rdi + 4], 'ou'
    jne .not_found
    cmp byte [rdi + 6], 't'
    jne .not_found
; --- POST /logout ---------------------------------------------------------
; Clearing the cookie is enough: the server keeps no session state, so an
; expired cookie is simply one that no longer verifies.
    mov edi, ck_gs
    mov rsi, [rbx + TLS_SCRATCH]
    mov byte [rsi], 0
    xor edx, edx                    ; empty value
    jmp render_head_cookie

.post_register:
    cmp ecx, 9
    jne .post_admin
    cmp dword [rdi], '/reg'
    jne .not_found
    cmp dword [rdi + 4], 'iste'
    jne .not_found
    cmp byte [rdi + 8], 'r'
    je .register
.not_found2:
    jmp render_404

; "/admin/inv", "/admin/rev", "/admin/del". Any other 10-byte path is a 404
; with or without the key, so the key is checked once for all three.
.post_admin:
    cmp ecx, 10
    jne .not_found2
    cmp dword [rdi], '/adm'
    jne .not_found2
    cmp word [rdi + 4], 'in'
    jne .not_found2
    cmp byte [rbx + TLS_ADMIN], 1
    jne .not_found2             ; 404 not 403: do not confirm the panel exists.
    mov eax, [rdi + 6]
    cmp eax, '/inv'
    je .admin_inv
    cmp eax, '/del'
    je .admin_del
    cmp eax, '/rev'
    jne .not_found2

; --- admin actions --------------------------------------------------------
.admin_rev:
    mov edx, key_index
    call .num_field
    jz .admin_done
    xchg eax, edi
    call invite_revoke
    jmp .admin_done

.admin_del:
    mov edx, key_index
    call .num_field
    jz .admin_done
    xchg eax, edi
    call db_rec
    test rax, rax
    jz .admin_done
    ; lock: a worker may be rendering this record right now, and a plain
    ; read-modify-write could drop a concurrent flag update.
    lock or dword [rax + R_FLAGS], FLAG_DELETED
    jmp .admin_done

.admin_inv:
    call invite_create              ; -1 (table full) just skips creation
.admin_done:
    mov edi, admin_path
    jmp render_redirect

.new:
    call .prepare_record
    mov r14d, eax                  ; Keep body length without replacing TLS base.
    mov edx, key_title
    mov rcx, [rbx + TLS_REC]
    add rcx, R_TITLE
    push TITLE_MAX - 1
    pop r8
    call .field
    test eax, eax
    jnz .new_append
    test r14d, r14d
    jz .new_redirect                ; Reject only when both title and body are empty.
    mov rdi, [rbx + TLS_REC]
    add rdi, R_TITLE
    mov esi, untitled
    push untitled_len
    pop rcx
    rep movsb
.new_append:
    or r15d, -1                    ; Root parent becomes its own reserved index.
    call .append_record
    test eax, eax
    js .not_found2
.new_redirect:
    mov edi, root_path
    jmp render_redirect

.reply:
    mov edx, key_parent
    call .num_field
    jz .not_found2
    mov r15d, eax
    xchg eax, edi
    call db_rec
    test rax, rax
    jz .not_found2
    cmp dword [rax + R_TIME], 0
    je .not_found2                 ; Reserved slots are not yet readable.
    cmp [rax + R_PARENT], r15d
    jne .not_found2                ; Replies must target a root, not a reply.
    test byte [rax + R_FLAGS], FLAG_DELETED
    jnz .not_found2
    mov rbp, rax                   ; Keep the full mapped root address.

    call .prepare_record
    test eax, eax
    jz .reply_redirect
    call .append_record
    test eax, eax
    js .not_found2
    ; Count AFTER commit: a crash cannot leave a count with no published reply.
    ; Readers may briefly see a low count; the following increment resolves it.
    lock inc dword [rbp + R_NREPLY]
.reply_redirect:
    ; "/t/<root>" in scratch: digits are pushed low-first and popped in order.
    ; The root index is below MAX_POSTS, so cdq zeroes edx for the division.
    mov rdi, [rbx + TLS_SCRATCH]
    push rdi
    mov dword [rdi], '/t/'
    add rdi, 3
    xchg eax, r15d
    push 10
    pop rcx
    xor esi, esi
.utoa_digit:
    cdq
    div ecx
    push rdx
    inc esi
    test eax, eax
    jnz .utoa_digit
.utoa_emit:
    pop rax
    add al, '0'
    stosb
    dec esi
    jnz .utoa_emit
    xchg eax, esi                   ; al = 0: NUL terminator
    stosb
    pop rdi
    jmp render_redirect

; --- POST /register ------------------------------------------------------
; An invite is a one-shot ticket to create an account, spent here rather than
; at first post: the account is the durable identity from this point on.
.register:
    call .name_field
    jz .reg_bad_name
    mov r15d, eax                   ; name length
    ; password into the record scratch, which is free until a post is built
    call .pass_field
    jz .reg_short
    mov r14d, eax                   ; password length
    ; invite code into the second half of scratch
    mov edx, key_code
    mov rcx, [rbx + TLS_SCRATCH]
    add rcx, 64
    push CODE_LEN
    pop r8
    call .field
    cmp eax, CODE_LEN
    jne .reg_bad_invite
    mov rdi, [rbx + TLS_SCRATCH]
    add rdi, 64
    push CODE_LEN
    pop rsi
    call invite_find
    test eax, eax
    js .reg_bad_invite
    xchg eax, r8d                   ; invite index; r13 is the client fd
    mov rdi, [rbx + TLS_SCRATCH]
    mov esi, r15d
    mov rdx, [rbx + TLS_REC]
    mov ecx, r14d
    call user_create
    test eax, eax
    jns .login_ok                   ; account made: hand out a session
    neg eax                         ; -3 taken, -4 malformed, -5 short
    push rax
    jmp .reg_render
.reg_bad_name:
    push 4
    jmp .reg_render
.reg_short:
    push 5
    jmp .reg_render
.reg_bad_invite:
    push 2
.reg_render:
    pop rdi
    jmp render_register

; --- POST /login ----------------------------------------------------------
.login:
    call .name_field
    jz .login_bad
    mov r15d, eax
    call .pass_field
    jz .login_bad
    mov rdi, [rbx + TLS_SCRATCH]
    mov esi, r15d
    mov rdx, [rbx + TLS_REC]
    xchg eax, ecx
    call user_check
    test eax, eax
    js .login_bad
.login_ok:
    ; eax holds the user index; mint a signed cookie for it
    xchg eax, edi
    mov rsi, [rbx + TLS_SCRATCH]
    sub rsi, -128
    mov rbp, rsi
    call session_make
    mov edi, ck_gs
    mov rsi, rbp
    push SESS_LEN
    pop rdx
    jmp render_head_cookie
.login_bad:
    push 1
    pop rdi
    jmp render_login

; edx=key. Parses a decimal form field via scratch: eax=value, ZF set when the
; field has no leading digits.
.num_field:
    mov rcx, [rbx + TLS_SCRATCH]
    push 32
    pop r8
    call .field
    xchg eax, esi
    mov rdi, [rbx + TLS_SCRATCH]
    call parse_uint
    test edx, edx
    ret

; Name field into scratch, lowercased in place (names are stored and compared
; lowercased). Returns length in eax, ZF set when empty.
.name_field:
    mov edx, key_name
    mov rcx, [rbx + TLS_SCRATCH]
    push NAME_MAX - 1
    pop r8
    call .field
    mov rdi, [rbx + TLS_SCRATCH]
    xor ecx, ecx
.lower:
    cmp ecx, eax
    jae .lower_done
    mov dl, [rdi + rcx]
    sub dl, 'A'
    cmp dl, 'Z' - 'A'
    ja .lower_next
    or byte [rdi + rcx], 0x20
.lower_next:
    inc ecx
    jmp .lower
.lower_done:
    test eax, eax
    ret

; Password field into the record scratch. Returns length, ZF set when empty.
.pass_field:
    mov edx, key_pass
    mov rcx, [rbx + TLS_REC]
    push PASS_MAX
    pop r8
    call .field
    test eax, eax
    ret

.database_error:
    mov esi, database_error
    push database_error_len
    pop rdx
    jmp .startup_error
.auth_error:
    mov esi, auth_error
    push auth_error_len
    pop rdx
    jmp .startup_error
.thread_error:
    mov esi, thread_error
    push thread_error_len
    pop rdx
    jmp .startup_error
.socket_error:
    mov esi, socket_error
    push socket_error_len
    pop rdx
.startup_error:
    push SYS_write
    pop rax
    push 2
    pop rdi
    syscall
    mov eax, SYS_exit_group
    push 1
    pop rdi
    syscall

; esi=length; returns a full-width anonymous mapping or a negative errno.
; Preserves all callee-saved registers. Used once per TLS block or stack.
.anon_map:
    xor edi, edi
    push PROT_READ | PROT_WRITE
    pop rdx
    push MAP_PRIVATE | MAP_ANONYMOUS
    pop r10
    push -1
    pop r8
    xor r9d, r9d
    push SYS_mmap
    pop rax
    syscall
    ret

; Returns 0 or a negative errno; caller chooses startup failure vs thread exit.
.tls_setup:
    mov esi, TLS_SIZE + SCRATCH_SIZE + REC_SIZE + REQ_SIZE + OBUF_SIZE
    call .anon_map
    test rax, rax
    js .tls_done
    mov rsi, rax
    mov [rsi + TLS_SELF], rsi
    lea rax, [rsi + TLS_SIZE]
    mov [rsi + TLS_SCRATCH], rax
    add rax, SCRATCH_SIZE
    mov [rsi + TLS_REC], rax
    add rax, REC_SIZE
    mov [rsi + TLS_REQ], rax
    add rax, REQ_SIZE
    mov [rsi + TLS_OBUF], rax
    ; Anonymous mmap zeroes TLS_OBLEN and TLS_ADMIN, along with other fields.
    mov qword [rsi + TLS_USER], -1
    mov edi, ARCH_SET_FS
    mov eax, SYS_arch_prctl
    syscall
.tls_done:
    ret

; Parent returns child tid or a negative errno. Child NEVER returns on its
; empty cloned stack; it installs independent TLS and joins the accept loop.
.spawn_worker:
    mov esi, STACK_SIZE
    call .anon_map
    test rax, rax
    js .spawn_done
    lea rsi, [rax + STACK_SIZE]     ; Page-aligned TOP; stacks grow downward.
    mov edi, CLONE_FLAGS
    xor edx, edx                    ; ptid
    xor r10d, r10d                  ; ctid (syscall argument four)
    xor r8d, r8d                    ; No CLONE_SETTLS; child sets FS itself.
    push SYS_clone
    pop rax
    syscall
    test rax, rax
    jz .child
    jns .spawn_done
    push rax                       ; Release a stack when clone failed.
    lea rdi, [rsi - STACK_SIZE]
    mov esi, STACK_SIZE
    push SYS_munmap
    pop rax
    syscall
    pop rax
.spawn_done:
    ret
.child:
    call .tls_setup
    test rax, rax
    jns .accept
    push SYS_exit                  ; A failed worker never kills its siblings.
    pop rax
    push 1
    pop rdi
    syscall

; rdx=key, rcx=destination, r8=capacity; returns decoded length in rax.
; Tail call with only the declared, received body extent; caller-saved clobbers.
.field:
    mov rdi, [rbx + TLS_BODY]
    mov rsi, [rbx + TLS_BODYLEN]
    mov rax, [rbx + TLS_CLEN]
    cmp rsi, rax
    cmova rsi, rax
    jmp form_field

; Clears the record, defaults its author, and returns its decoded body length.
; Preserves callee-saved registers; body/title emptiness is checked by callers.
.prepare_record:
    mov rdi, [rbx + TLS_REC]
    xor eax, eax
    push REC_SIZE / 8
    pop rcx
    rep stosq
    ; The author is the signed-in account, never a form field: a member must
    ; not be able to post under someone else's name.
    push r14
    mov rdi, [rbx + TLS_USER]
    call usr_rec
    pop r14
    test rax, rax
    jz .record_body
    mov rsi, rax
    add rsi, U_NAME
    mov rdi, [rbx + TLS_REC]
    add rdi, R_AUTHOR
    push AUTHOR_MAX / 8
    pop rcx
.cp_author:
    mov rax, [rsi]
    mov [rdi], rax
    add rsi, 8
    add rdi, 8
    dec rcx
    jnz .cp_author
.record_body:
    mov edx, key_body
    mov rcx, [rbx + TLS_REC]
    add rcx, R_BODY
    mov r8d, BODY_MAX - 1
    jmp .field

; Reserve an exclusive index, fill its mapped record, then publish R_TIME last.
; r15d=-1 for roots, otherwise the validated root index. Returns commit status.
.append_record:
    call db_reserve
    test eax, eax
    js .append_done
    push rax
    mov rsi, [rbx + TLS_REC]
    mov edx, r15d
    test edx, edx
    cmovs edx, eax
    mov [rsi + R_PARENT], edx
    ; Audit trail: which invite authored this record.
    mov ecx, [rbx + TLS_USER]
    mov [rsi + R_USER], ecx
    mov edi, eax
    call db_rec
    mov rdi, rax
    mov rsi, [rbx + TLS_REC]
    mov ecx, REC_SIZE / 8
    rep movsq                      ; Scratch R_TIME is zero: still unpublished.
    ; Claim the invite for its FIRST post only; the cmpxchg inside makes a
    ; later post a no-op. Either outcome is fine -- a member posts many times.
    ; The invite was spent at registration; what a post bumps is the
    ; author's own counter.
    mov rdi, [rbx + TLS_USER]
    call usr_rec
    test rax, rax
    jz .no_bump
    lock inc dword [rax + U_POSTS]
.no_bump:
    pop rdi
    jmp db_commit                  ; Publish: R_TIME is the last store (x86 TSO).
.append_done:
    ret

section .data
align 8
ignore_sigpipe: dq SIG_IGN, 0, 0, 0
listen_address:
    dw AF_INET, PORT_BE
    dd 0
    dq 0
banner: db 'geektaco http://0.0.0.0:8090', 10
banner_len equ $ - banner
database_error: db 'database failed', 10
database_error_len equ $ - database_error
auth_error: db 'authentication failed', 10
auth_error_len equ $ - auth_error
thread_error: db 'thread setup failed', 10
thread_error_len equ $ - thread_error
socket_error: db 'socket failed', 10
socket_error_len equ $ - socket_error
root_path: db '/', 0
key_title: db 't', 0
key_body: db 'b', 0
key_parent: db 'p', 0
key_code:   db 'c', 0
key_name:   db 'n', 0
key_pass:   db 'w', 0
key_index:  db 'i', 0
admin_path: db '/admin', 0
ck_gs:      db 'gs', 0
untitled: db '(untitled)'
untitled_len equ $ - untitled
