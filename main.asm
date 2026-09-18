%include "common.inc"
default rel

; Linux signal constants omitted from the frozen shared include.
SIGPIPE          equ 13
SIG_IGN          equ 1

global _start
extern db_init, db_reserve, db_rec, db_commit, auth_init
extern session_resolve, invite_find, invite_create, invite_revoke, invite_consume
extern http_parse, parse_uint, form_field
extern render_index, render_thread, render_404, render_redirect
extern render_join, render_admin, render_403, render_head_cookie

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
    js .not_found
    cmp qword [rbx + TLS_METHOD], M_POST
    jne .resolve                    ; GET carries cookies too: /admin needs them
    mov rax, [rbx + TLS_CLEN]
    cmp [rbx + TLS_BODYLEN], rax
    jae .resolve
    cmp qword [rbx + TLS_BODY], 0
    je .not_found

.read_body:
    cmp r14d, REQ_SIZE
    jae .not_found                  ; Never persist an incomplete POST body.
    xor eax, eax                    ; SYS_read
    mov edi, r13d
    mov rsi, [rbx + TLS_REQ]
    add rsi, r14
    mov edx, REQ_SIZE
    sub edx, r14d
    syscall
    test eax, eax
    jle .not_found
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
; builders read TLS_INVITE/TLS_ADMIN; nothing else parses a cookie.
    mov rdi, [rbx + TLS_REQ]
    mov esi, r14d
    call session_resolve

.route:
    mov rdi, [rbx + TLS_PATH]
    mov rcx, [rbx + TLS_PATHLEN]
    cmp qword [rbx + TLS_METHOD], M_GET
    je .get
    cmp qword [rbx + TLS_METHOD], M_POST
    je .post
    jmp .not_found

.get:
    cmp ecx, 1
    jne .get_page
    cmp byte [rdi], '/'
    jne .not_found
    xor edi, edi                    ; page 0
    call render_index
    jmp .respond

.get_page:
    cmp ecx, 4                      ; "/p/" + at least one digit
    jb .get_join
    cmp word [rdi], '/p'
    jne .get_join
    cmp byte [rdi + 2], '/'
    jne .get_join
    add rdi, 3
    lea esi, [rcx - 3]
    call parse_uint
    test edx, edx
    jz .not_found                   ; "/p/abc" is malformed, not page 0
    mov edi, eax
    call render_index
    jmp .respond

; A non-matching path of the same length MUST fall through, not 404: "/t/60"
; is also 5 bytes, and "/t/123" is also 6.
.get_join:
    cmp ecx, 5
    jne .get_admin
    cmp dword [rdi], '/joi'
    jne .get_admin
    cmp byte [rdi + 4], 'n'
    jne .get_admin
    xor edi, edi                    ; no error yet
    call render_join
    jmp .respond

.get_admin:
    cmp ecx, 6
    jne .get_thread
    cmp dword [rdi], '/adm'
    jne .get_thread
    cmp word [rdi + 4], 'in'
    jne .get_thread
    cmp qword [rbx + TLS_ADMIN], 1
    jne .not_found              ; 404 not 403: do not confirm the panel exists.
    call render_admin
    jmp .respond

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
    ; parse_uint clobbers every caller-saved register, so the cursor and the
    ; remaining length are spilled; the root index goes in rbp, which is
    ; callee-saved and therefore survives the second parse without a push
    ; that the .not_found exits would have to unwind.
    push rsi
    push rdi
    call parse_uint
    pop rdi
    pop rsi
    test edx, edx
    jz .not_found
    mov ebp, eax                    ; root index
    sub esi, edx                    ; bytes after the index digits
    jz .thread_p0
    add rdi, rdx                    ; advance past the digits
    cmp byte [rdi], '/'
    jne .not_found
    inc rdi
    dec esi
    jz .not_found                   ; "/t/<n>/" with no page number
    push rsi
    call parse_uint
    pop rsi
    test edx, edx
    jz .not_found
    cmp edx, esi
    jne .not_found                  ; trailing junk after the page number
    mov esi, eax
    mov edi, ebp
    call render_thread
    jmp .respond
.thread_p0:
    mov edi, ebp
    xor esi, esi
    call render_thread
    jmp .respond

.post:
    cmp ecx, 4
    jne .post_join
    cmp dword [rdi], '/new'
    jne .not_found
    cmp qword [rbx + TLS_INVITE], 0
    jl .forbidden               ; signed: TLS_INVITE is a sign-extended -1.
    jmp .new

.post_join:
    cmp ecx, 5
    jne .post_reply
    cmp dword [rdi], '/joi'
    jne .not_found
    cmp byte [rdi + 4], 'n'
    jne .not_found
    jmp .join

.post_reply:
    cmp ecx, 6
    jne .post_admin
    cmp dword [rdi], '/rep'
    jne .post_admin
    cmp word [rdi + 4], 'ly'
    jne .post_admin
    cmp qword [rbx + TLS_INVITE], 0
    jl .forbidden               ; signed: TLS_INVITE is a sign-extended -1.
    jmp .reply

.post_admin:
    cmp ecx, 10
    jne .not_found
    cmp dword [rdi], '/adm'
    jne .not_found
    cmp dword [rdi + 4], 'in/i'     ; "/admin/inv"
    je .admin_inv_check
    cmp dword [rdi + 4], 'in/r'     ; "/admin/rev"
    je .admin_rev_check
    cmp dword [rdi + 4], 'in/d'     ; "/admin/del"
    je .admin_del_check
    jmp .not_found
.admin_inv_check:
    cmp word [rdi + 8], 'nv'
    jne .not_found
    cmp qword [rbx + TLS_ADMIN], 1
    jne .not_found              ; 404 not 403: do not confirm the panel exists.
    jmp .admin_inv
.admin_rev_check:
    cmp word [rdi + 8], 'ev'
    jne .not_found
    cmp qword [rbx + TLS_ADMIN], 1
    jne .not_found              ; 404 not 403: do not confirm the panel exists.
    jmp .admin_rev
.admin_del_check:
    cmp word [rdi + 8], 'el'
    jne .not_found
    cmp qword [rbx + TLS_ADMIN], 1
    jne .not_found              ; 404 not 403: do not confirm the panel exists.
    jmp .admin_del

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
    mov r15d, -1                   ; Root parent becomes its own reserved index.
    call .append_record
    test eax, eax
    js .not_found
.new_redirect:
    mov edi, root_path
    call render_redirect
    jmp .respond

.reply:
    mov edx, key_parent
    mov rcx, [rbx + TLS_SCRATCH]
    push 32
    pop r8
    call .field
    mov esi, eax
    mov rdi, [rbx + TLS_SCRATCH]
    call parse_uint
    test edx, edx
    jz .not_found
    mov r15d, eax
    mov edi, eax
    call db_rec
    test rax, rax
    jz .not_found
    cmp dword [rax + R_TIME], 0
    je .not_found                  ; Reserved slots are not yet readable.
    cmp [rax + R_PARENT], r15d
    jne .not_found                 ; Replies must target a root, not a reply.
    test byte [rax + R_FLAGS], FLAG_DELETED
    jnz .not_found
    mov rbp, rax                   ; Keep the full mapped root address.

    call .prepare_record
    test eax, eax
    jz .reply_redirect
    call .append_record
    test eax, eax
    js .not_found
    ; Count AFTER commit: a crash cannot leave a count with no published reply.
    ; Readers may briefly see a low count; the following increment resolves it.
    lock inc dword [rbp + R_NREPLY]
.reply_redirect:
    mov rsi, [rbx + TLS_SCRATCH]
    mov dword [rsi], '/t/'
    mov edi, r15d
    add rsi, 3
    call .utoa
    mov rdi, [rbx + TLS_SCRATCH]
    call render_redirect
    jmp .respond

; --- POST /join: redeem a code -------------------------------------------
; Redeeming does NOT consume the invite. Consumption happens on first post, so
; a code that is handed out but never used stays usable by its recipient.
.join:
    mov edx, key_code
    mov rcx, [rbx + TLS_SCRATCH]
    push CODE_LEN
    pop r8
    call .field
    cmp eax, CODE_LEN
    jne .join_bad                   ; wrong length is never a valid code
    mov rdi, [rbx + TLS_SCRATCH]
    push CODE_LEN
    pop rsi
    call invite_find
    test eax, eax
    js .join_bad
    mov edi, ck_gt
    mov rsi, [rbx + TLS_SCRATCH]
    push CODE_LEN
    pop rdx
    call render_head_cookie
    jmp .respond
.join_bad:
    push 1
    pop rdi
    call render_join
    jmp .respond

; --- admin actions --------------------------------------------------------
.admin_inv:
    call invite_create              ; -1 (table full) just skips creation
    jmp .admin_done

.admin_rev:
    call .admin_index
    js .admin_done
    mov edi, eax
    call invite_revoke
    jmp .admin_done

.admin_del:
    call .admin_index
    js .admin_done
    mov r15d, eax
    mov edi, eax
    call db_rec
    test rax, rax
    jz .admin_done
    ; lock: a worker may be rendering this record right now, and a plain
    ; read-modify-write could drop a concurrent flag update.
    lock or dword [rax + R_FLAGS], FLAG_DELETED

.admin_done:
    mov edi, admin_path
    call render_redirect
    jmp .respond

; Parse the `i` form field. Returns the index in eax, or sets SF on failure.
.admin_index:
    mov edx, key_index
    mov rcx, [rbx + TLS_SCRATCH]
    push 32
    pop r8
    call .field
    mov esi, eax
    mov rdi, [rbx + TLS_SCRATCH]
    call parse_uint
    test edx, edx
    jz .admin_index_bad
    test eax, eax                   ; clears SF for a valid index
    ret
.admin_index_bad:
    mov eax, -1
    test eax, eax                   ; sets SF
    ret

.forbidden:
    call render_403
    jmp .respond

.not_found:
    call render_404
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
    mov qword [rsi + TLS_INVITE], -1
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
    mov edx, key_author
    mov rcx, [rbx + TLS_REC]
    add rcx, R_AUTHOR
    push AUTHOR_MAX - 1
    pop r8
    call .field
    test eax, eax
    jnz .record_body
    mov rax, [rbx + TLS_REC]
    mov dword [rax + R_AUTHOR], 'anon'
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
    mov ecx, [rbx + TLS_INVITE]
    mov [rsi + R_INVITE], ecx
    mov edi, eax
    call db_rec
    mov rdi, rax
    mov rsi, [rbx + TLS_REC]
    mov ecx, REC_SIZE / 8
    rep movsq                      ; Scratch R_TIME is zero: still unpublished.
    ; Claim the invite for its FIRST post only; the cmpxchg inside makes a
    ; later post a no-op. Either outcome is fine -- a member posts many times.
    mov rdi, [rbx + TLS_INVITE]
    mov rsi, [rsp]
    call invite_consume
    pop rdi
    jmp db_commit                  ; Publish: R_TIME is the last store (x86 TSO).
.append_done:
    ret

; edi=parent index (<MAX_POSTS), rsi=destination (21 bytes); decimal plus NUL.
; Leaf routine uses the red zone; clobbers caller-saved registers only.
.utoa:
    mov r9, rsp
    mov eax, edi
    push 10
    pop r8
    xor ecx, ecx
.utoa_digit:
    xor edx, edx
    div r8d
    add dl, '0'
    dec r9
    mov [r9], dl
    inc ecx
    test eax, eax
    jnz .utoa_digit
    mov rdi, rsi
    mov rsi, r9
    rep movsb
    mov byte [rdi], 0
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
key_author: db 'a', 0
key_title: db 't', 0
key_body: db 'b', 0
key_parent: db 'p', 0
key_code:   db 'c', 0
key_index:  db 'i', 0
admin_path: db '/admin', 0
ck_gt:      db 'gt', 0
untitled: db '(untitled)'
untitled_len equ $ - untitled
