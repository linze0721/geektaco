; ============================================================================
; geektaco -- render.asm
; Output buffer primitives + HTML page builders.
; No I/O happens here: every byte goes through the bounds-checked obuf
; appenders; main.asm flushes obuf to the socket.
; ============================================================================
%include "common.inc"
default rel

global ob_reset
global ob_put
global ob_puts
global ob_putc
global ob_putu
global ob_put_esc
global ob_put_esc_z
global render_index
global render_thread
global render_404
global render_redirect
global render_join, render_admin, render_403, render_head_cookie

extern db_count
extern db_rec
extern inv_count, inv_rec

section .rodata

s_200:   db 'HTTP/1.0 200 OK', 13, 10, 0
s_404a:  db 'HTTP/1.0 404 Not Found', 13, 10, 0
s_302a:  db 'HTTP/1.0 302 Found', 13, 10, 'Location: ', 0
s_crlf:  db 13, 10, 0
s_hdr:   db 'Content-Type: text/html; charset=utf-8', 13, 10
         db 'Connection: close', 13, 10, 13, 10, 0

e_amp:   db '&amp;', 0
e_lt:    db '&lt;', 0
e_gt:    db '&gt;', 0
e_quot:  db '&quot;', 0
e_apos:  db '&#39;', 0

; Dark brutalist terminal theme: near-black bg, soft green text, amber accent.
; <html><head><body> open tags are omitted: the HTML parser infers them.
s_head:  db '<!doctype html><meta charset=utf-8>'
         db '<meta name=viewport content="width=device-width,initial-scale=1">'
         db '<title>geektaco</title><style>'
         db 'body{font:16px/1.5 monospace;background:#111;color:#8e8;'
         db 'max-width:46rem;margin:auto;padding:2rem 1rem}'
         db 'a{color:#da6}'
         db 'h1,h2{color:#da6;font-weight:400}'
         db 'h1{font-size:1.6rem;margin:0}'
         db 'h2{font-size:1rem}'
         db 'header{border-bottom:1px solid #232;padding-bottom:1rem;margin-bottom:1rem}'
         db '.g{margin:0}'
         db '.t{padding:.6rem 0;border-bottom:1px solid #232}'
         db '.e,.g,.m,label{color:#474}'
         db '.m,label{font-size:.8rem}'
         db '.p,form{border:1px solid #232;padding:1rem;margin:1rem 0}'
         db '.p .m{color:#da6}'
         db 'pre{white-space:pre-wrap;margin:0;font:inherit}'
         db 'label{display:block;margin:.8rem 0 .3rem}'
         db 'input,textarea{display:block;width:100%;background:#010;color:#8e8;'
         db 'border:1px solid #242;padding:.5rem;font:inherit}'
         db ':focus{outline:1px solid #da6}'
         db '[type=submit]{width:auto;background:#232;color:#da6;cursor:pointer}'
         db '.e{border:1px dashed #242;padding:1rem}'
; Admin tables: forms are block-level by default, which would break each row
; across lines, and the shared form border would box every button.
         db 'table{width:100%;border-collapse:collapse;font-size:.85rem}'
         db 'td{padding:.4rem .5rem;border-bottom:1px solid #1a2a1c;'
         db 'vertical-align:middle}'
         db 'td form{display:inline;border:0;padding:0;margin:0}'
         db 'td [type=submit]{padding:.2rem .5rem;font-size:.8rem}'
         db '</style>', 0

; Literal U+00B7 middle dots (2 bytes) replace the 8-byte &middot; entity.
s_idx_top: db '<header><h1>geektaco</h1>'
           db '<p class=g>minimalist forum ', 0xC2, 0xB7, ' pure x86_64 asm ', 0xC2, 0xB7, ' no libc</p>'
           db '</header>', 0
s_th_a:  db '<div class=t><a href="/t/', 0
s_th_b:  db '">', 0
s_th_c:  db '</a><div class=m>by ', 0
s_dot:   db ' ', 0xC2, 0xB7, ' ', 0
s_th_e:  db ' replies</div></div>', 0
s_empty: db '<p class=e>// no threads yet. be the first to post.</p>', 0
; Shared form fragments: identical markup in the new-thread and reply forms.
s_f_a:   db '<label>author</label><input name=a maxlength=23 required>', 0
s_f_b:   db '<label>body</label><textarea name=b maxlength=399 required></textarea>', 0
s_newform: db '<h2>new thread</h2>'
           db '<form method=post action=/new>', 0
s_newform2: db '<label>title</label><input name=t maxlength=79 required>', 0
s_newform3: db '<input type=submit value="post"></form>'
           db '</body></html>', 0

s_t_top: db '<header><a href="/">geektaco</a><span class=g> / thread</span></header>'
         db '<h1>', 0
s_h1b:   db '</h1><div class=p><div class=m>', 0
s_post_c: db '</div><pre>', 0
s_post_d: db '</pre></div>', 0
s_repl_a: db '<h2>reply</h2><form method=post action=/reply>'
          db '<input type=hidden name=p value=', 0
s_repl_b: db '<input type=submit value="reply"></form>'
          db '</body></html>', 0
s_404body: db '<h1>404</h1><p>nothing here. <a href="/">back to index</a></p>'
          db '</body></html>', 0
s_red_a: db '<p>moved: <a href="', 0
s_red_c: db '</a></p>', 0
s_untitled: db '(untitled)', 0
s_anon:  db 'anonymous', 0

; ---- v2 pages -------------------------------------------------------------
; The cookie IS the auth token, so HttpOnly (no script access) and
; SameSite=Strict (no cross-site submission) are load-bearing, not hygiene.
s_ck_a:  db 'Set-Cookie: ', 0
s_ck_b:  db '=', 0
s_ck_c:  db '; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000', 13, 10, 0
s_403a:  db 'HTTP/1.0 403 Forbidden', 13, 10, 0

s_joined: db '<h1>welcome</h1><p class=e>code accepted. you can post now.</p>'
          db '<p><a href="/">-> the forum</a></p></body></html>', 0
s_join_a: db '<header><a href="/">geektaco</a><span class=g> / join</span></header>'
          db '<h1>invite only</h1>'
          db '<p class=m>geektaco runs on invite codes. paste yours below.</p>', 0
s_join_err: db '<p class=e>that code is invalid, revoked, or mistyped.</p>', 0
s_join_b: db '<form method=post action=/join>'
          db '<label>invite code</label>'
          db '<input name=c maxlength=16 required autofocus>'
          db '<input type=submit value="redeem"></form>'
          db '<p class=m><a href="/">browse without posting</a></p>'
          db '</body></html>', 0
s_403body: db '<header><a href="/">geektaco</a></header>'
           db '<h1>403</h1><p>posting needs an invite. '
           db '<a href="/join">redeem a code</a></p></body></html>', 0
s_nav:    db '<p class=m><a href="/join">have an invite?</a></p>', 0

; admin panel
s_adm_top: db '<header><a href="/">geektaco</a><span class=g> / admin</span></header>'
           db '<h1>invites</h1>'
           db '<form method=post action=/admin/inv>'
           db '<input type=submit value="create invite"></form>'
           db '<table>', 0
s_adm_inv: db '<tr><td>', 0
s_adm_td:  db '</td><td>', 0
s_adm_rev: db '</td><td><form method=post action=/admin/rev>'
           db '<input type=hidden name=i value=', 0
s_adm_revb: db '><input type=submit value="revoke"></form>', 0
s_adm_del: db '</td><td><form method=post action=/admin/del>'
           db '<input type=hidden name=i value=', 0
s_adm_delb: db '><input type=submit value="delete"></form>', 0
s_adm_tr:  db '</td></tr>', 0
s_adm_mid: db '</table><h1>posts</h1><table>', 0
s_adm_end: db '</table></body></html>', 0
s_st_rev:  db 'revoked', 0
s_st_free: db 'unused', 0
s_st_used: db 'used by post ', 0
s_st_unc:  db 'uncommitted', 0
s_st_del:  db 'deleted', 0
s_st_ok:   db 'live', 0
s_reply_to: db '(reply to ', 0
s_paren:   db ')', 0
s_inv_col: db 'inv ', 0

section .text

; ---------------------------------------------------------------------------
; ob_reset() -- empty the output buffer.
; args: none.  returns: nothing.  clobbers: nothing (writes TLS_OBLEN only).
ob_reset:
        push    rbx
        mov     rbx, [fs:TLS_SELF]
        mov     qword [rbx + TLS_OBLEN], 0
        pop     rbx
        ret

; ---------------------------------------------------------------------------
; ob_put(rdi=src, rsi=len) -- append raw bytes.
; Truncates to the remaining space instead of ever overflowing obuf.
; clobbers: rax, rcx, rdx, rsi, rdi.
ob_put:
        push    rbx
        mov     rbx, [fs:TLS_SELF]
        mov     rax, [rbx + TLS_OBLEN]
        mov     rcx, OBUF_SIZE
        sub     rcx, rax                ; free space; CF if length > OBUF_SIZE
        jbe     .done                   ; nothing free -> drop
        cmp     rsi, rcx
        cmovb   rcx, rsi                ; rcx = min(len, free)
        mov     rsi, rdi                ; rep movsb source
        mov     rdi, [rbx + TLS_OBUF]
        add     rdi, rax                ; dst = this thread's buffer + length
        add     [rbx + TLS_OBLEN], rcx
        rep movsb
.done:
        pop     rbx
        ret

; ---------------------------------------------------------------------------
; ob_puts(rdi=NUL-terminated string) -- append it raw, no escaping.
; clobbers: rax, rcx, rdx, rsi, rdi.
ob_puts:
        mov     rsi, rdi
.scan:
        cmp     byte [rsi], 0
        je      .go
        inc     rsi
        jmp     .scan
.go:
        sub     rsi, rdi                ; length
        jmp     ob_put

; ---------------------------------------------------------------------------
; ob_putc(dil=byte) -- append a single byte.
; clobbers: rax.
ob_putc:
        push    rbx
        mov     rbx, [fs:TLS_SELF]
        mov     rax, [rbx + TLS_OBLEN]
        cmp     rax, OBUF_SIZE
        jae     .done
        add     rax, [rbx + TLS_OBUF]
        mov     [rax], dil
        inc     qword [rbx + TLS_OBLEN]
.done:
        pop     rbx
        ret

; ---------------------------------------------------------------------------
; ob_putu(rdi=u64) -- append decimal ASCII. Emits "0" for zero.
; Digits are produced backwards into a stack scratch via div by 10.
; clobbers: rax, rcx, rdx, rsi, rdi, r8, r9.
ob_putu:
        sub     rsp, 40                 ; 32-byte digit scratch, keeps rsp 8-aligned
        mov     rax, rdi
        push    10
        pop     rcx
        lea     r9, [rsp + 32]          ; one past the scratch area
        mov     r8, r9
.digit:
        xor     edx, edx
        div     rcx                     ; rax = quot, rdx = rem
        add     dl, '0'
        dec     r8
        mov     [r8], dl
        test    rax, rax
        jnz     .digit
        mov     rdi, r8
        mov     rsi, r9
        sub     rsi, r8                 ; digit count
        call    ob_put
        add     rsp, 40
        ret

; ---------------------------------------------------------------------------
; ob_put_esc(rdi=ptr, rsi=len) -- append HTML-escaped bytes.
; THE XSS barrier: & < > " ' become entities; control bytes < 0x20 other
; than \n and \t are dropped; everything else (incl. UTF-8) passes through.
; clobbers: caller-saved regs; preserves rbx, r12, r13.
ob_put_esc:
        push    rbx
        push    r12
        push    r13
        mov     rbx, rdi                ; src
        mov     r12, rsi                ; len
        xor     r13d, r13d              ; i
.loop:
        cmp     r13, r12
        jae     .done
        movzx   eax, byte [rbx + r13]
        cmp     al, 0x20
        jb      .ctrl
        cmp     al, '&'
        je      .amp
        cmp     al, '<'
        je      .lt
        cmp     al, '>'
        je      .gt
        cmp     al, '"'
        je      .quot
        cmp     al, 0x27                ; '\''
        je      .apos
.raw:
        movzx   edi, al
        call    ob_putc
.next:
        inc     r13
        jmp     .loop
.ctrl:
        cmp     al, 0x0A                ; newline survives
        je      .raw
        cmp     al, 0x09                ; tab survives
        je      .raw
        jmp     .next                   ; other control bytes dropped
.amp:
        mov     edi, e_amp
        jmp     .ent
.lt:
        mov     edi, e_lt
        jmp     .ent
.gt:
        mov     edi, e_gt
        jmp     .ent
.quot:
        mov     edi, e_quot
        jmp     .ent
.apos:
        mov     edi, e_apos
.ent:
        call    ob_puts
        jmp     .next
.done:
        pop     r13
        pop     r12
        pop     rbx
        ret

; ---------------------------------------------------------------------------
; ob_put_esc_z(rdi=NUL-padded field, rsi=field capacity)
; Computes the logical length (first NUL or capacity) then escapes.
; clobbers: caller-saved regs.
ob_put_esc_z:
        xor     eax, eax
.scan:
        cmp     rax, rsi
        jae     .go
        cmp     byte [rdi + rax], 0
        je      .go
        inc     rax
        jmp     .scan
.go:
        mov     rsi, rax
        jmp     ob_put_esc

; ---------------------------------------------------------------------------
; emit_head -- local helper: shared doctype/head/style so all pages match.
; clobbers: caller-saved regs.
emit_head:
        mov     edi, s_head
        jmp     ob_puts

; ---------------------------------------------------------------------------
; esc_field(rdi=NUL-padded field, rsi=capacity, rdx=fallback z-string)
; Escapes the field; when the field is empty appends the fallback instead,
; so links stay clickable and meta lines never render blank.
; ef_a is the same with rax = field offset into the record at rdi.
; clobbers: caller-saved regs.
esc_field:
        cmp     byte [rdi], 0
        jne     ob_put_esc_z
        mov     rdi, rdx
        jmp     ob_puts
ef_a:
        lea     rdi, [rdi + rax]
        jmp     esc_field

; ---------------------------------------------------------------------------
; emit_post(rdi=record) -- one <div class=p> block (meta line + pre body).
; Emits s_h1b (h1 close + post div open) then the post body.
; clobbers: caller-saved regs; preserves rbx.
emit_post:
        push    rbx
        mov     rbx, rdi
        mov     edi, s_h1b            ; </h1><div class=p><div class=m>
        call    ob_puts
        mov     eax, R_AUTHOR
        push    AUTHOR_MAX
        pop     rsi
        lea     rdx, [s_anon]
        mov     rdi, rbx
        call    ef_a
        mov     edi, s_dot            ; middle dot
        call    ob_puts
        mov     edi, [rbx + R_TIME]
        call    ob_putu                 ; raw epoch seconds
        mov     edi, s_post_c         ; </div><pre>
        call    ob_puts
        lea     rdi, [rbx + R_BODY]
        mov     esi, BODY_MAX
        call    ob_put_esc_z
        mov     edi, s_post_d         ; </pre></div>
        call    ob_puts
        pop     rbx
        ret

; ---------------------------------------------------------------------------
; render_index() -- 200 page listing every thread root, newest first.
; A record is a root iff R_PARENT == its own index. Reply counts come from a
; second pass counting R_PARENT == root index (the root itself excluded).
; clobbers: caller-saved regs; preserves rbx, r12-r15.
render_index:
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        push    r15
        mov     rbx, [fs:TLS_SELF]
        mov     qword [rbx + TLS_OBLEN], 0
        mov     edi, s_200
        call    ob_puts
        mov     edi, s_hdr
        call    ob_puts
        call    emit_head
        mov     edi, s_idx_top
        call    ob_puts
        call    db_count
        mov     r12, rax                ; snapshot of the allocation cursor
        test    r12, r12
        jz      .empty
        mov     r13, r12                ; i runs r12-1 .. 0: newest first
.outer:
        dec     r13
        mov     rdi, r13
        call    db_rec
        test    rax, rax
        jz      .next                   ; unavailable record: skip it
        cmp     dword [rax + R_TIME], 0
        je      .next                   ; reserved slot, not yet published
        test    byte [rax + R_FLAGS], FLAG_DELETED
        jnz     .next                   ; deleted roots are hidden from the public
        mov     rbp, rax                ; direct root pointer survives inner scan
        cmp     dword [rbp + R_PARENT], r13d ; root iff parent == own index
        jne     .next
        ; Reply count is read straight from R_NREPLY, which the replier bumps
        ; with a lock inc. The old second pass over every record made this page
        ; O(n^2); at 65536 records that is 4 billion iterations per request.
        mov     r15d, [rbp + R_NREPLY]
        mov     edi, s_th_a           ; <div class=t><a href="/t/
        call    ob_puts
        mov     rdi, r13
        call    ob_putu                 ; ...N
        mov     edi, s_th_b           ; ">
        call    ob_puts
        mov     eax, R_TITLE
        push    TITLE_MAX
        pop     rsi
        lea     rdx, [s_untitled]
        mov     rdi, rbp
        call    ef_a                    ; escaped title
        mov     edi, s_th_c           ; </a><div class=m>by
        call    ob_puts
        mov     eax, R_AUTHOR
        push    AUTHOR_MAX
        pop     rsi
        lea     rdx, [s_anon]
        mov     rdi, rbp
        call    ef_a                    ; escaped author
        mov     edi, s_dot            ; middle dot
        call    ob_puts
        mov     rdi, r15
        call    ob_putu                 ; reply count
        mov     edi, s_th_e           ; replies</div></div>
        call    ob_puts
.next:
        test    r13, r13
        jnz     .outer                  ; stop after index 0 was processed
        jmp     .form
.empty:
        mov     edi, s_empty
        call    ob_puts
.form:
        mov     edi, s_nav
        call    ob_puts
        mov     edi, s_newform
        call    ob_puts
        mov     edi, s_f_a
        call    ob_puts
        mov     edi, s_newform2
        call    ob_puts
        mov     edi, s_f_b
        call    ob_puts
        mov     edi, s_newform3
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        jmp     ob_puts

; ---------------------------------------------------------------------------
; render_thread(rdi=root index) -- 200 page: root post + replies ascending.
; Falls back to the 404 response when db_rec fails, the slot is uncommitted,
; or the record is not a thread root (R_PARENT != index).
; clobbers: caller-saved regs; preserves rbx, r12-r15.
render_thread:
        push    rbx
        push    r12
        push    r13
        push    r14
        mov     rbx, [fs:TLS_SELF]
        mov     r12, rdi                ; root index
        mov     rdi, r12
        call    db_rec
        test    rax, rax
        jz      .notfound
        cmp     dword [rax + R_TIME], 0
        je      .notfound               ; reserved root is not yet visible
        test    byte [rax + R_FLAGS], FLAG_DELETED
        jnz     .notfound               ; a deleted thread reads as gone
        mov     r13, rax                ; direct root pointer until reply scan
        cmp     dword [r13 + R_PARENT], r12d ; must be a root record
        jne     .notfound
        mov     qword [rbx + TLS_OBLEN], 0
        mov     edi, s_200
        call    ob_puts
        mov     edi, s_hdr
        call    ob_puts
        call    emit_head
        mov     edi, s_t_top          ; header + <h1>
        call    ob_puts
        mov     eax, R_TITLE
        push    TITLE_MAX
        pop     rsi
        lea     rdx, [s_untitled]
        mov     rdi, r13
        call    ef_a                    ; escaped title
        ; -- root post (emit_post emits s_h1b = h1 close + post div open)
        mov     rdi, r13
        call    emit_post
        ; -- replies: j in 0..db_count-1, parent == root, j != root
        call    db_count
        mov     r14, rax
        xor     r13d, r13d              ; j
.rep:
        cmp     r13, r12
        je      .rnext                  ; skip the root itself
        mov     rdi, r13
        call    db_rec
        test    rax, rax
        jz      .rnext
        cmp     dword [rax + R_TIME], 0
        je      .rnext                  ; reserved reply is not yet visible
        test    byte [rax + R_FLAGS], FLAG_DELETED
        jnz     .rnext                  ; deleted replies vanish from the thread
        cmp     dword [rax + R_PARENT], r12d
        jne     .rnext
        mov     rdi, rax
        call    emit_post
.rnext:
        inc     r13
        cmp     r13, r14
        jb      .rep
.repdone:
        mov     edi, s_repl_a         ; form + hidden p=
        call    ob_puts
        mov     rdi, r12
        call    ob_putu                 ; value=N
        mov     edi, s_th_b           ; ">" closes the hidden input
        call    ob_puts
        mov     edi, s_f_a
        call    ob_puts
        mov     edi, s_f_b
        call    ob_puts
        mov     edi, s_repl_b
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        jmp     ob_puts
.out:
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        ret
.notfound:
        call    render_404              ; emit the 404 response instead
        jmp     .out

; ---------------------------------------------------------------------------
; render_404() -- minimal 404 response.
; clobbers: caller-saved regs.
render_404:
        push    rbx
        mov     rbx, [fs:TLS_SELF]
        mov     qword [rbx + TLS_OBLEN], 0
        mov     edi, s_404a
        call    ob_puts
        mov     edi, s_hdr
        call    ob_puts
        call    emit_head
        mov     edi, s_404body
        pop     rbx
        jmp     ob_puts

; ---------------------------------------------------------------------------
; render_redirect(rdi=NUL-terminated location path) -- 302 response.
; clobbers: caller-saved regs; preserves rbx.
render_redirect:
        push    rbx
        push    r12
        mov     r12, rdi                ; path
        mov     rbx, [fs:TLS_SELF]
        mov     qword [rbx + TLS_OBLEN], 0
        mov     edi, s_302a           ; status + "Location: "
        call    ob_puts
        mov     rdi, r12
        call    ob_puts                 ; path
        mov     edi, s_crlf           ; CRLF
        call    ob_puts
        mov     edi, s_hdr            ; headers + blank line
        call    ob_puts
        mov     edi, s_red_a          ; tiny body: <p>moved: <a href="
        call    ob_puts
        mov     rdi, r12
        call    ob_puts
        mov     edi, s_th_b           ; ">
        call    ob_puts
        mov     rdi, r12
        call    ob_puts
        mov     edi, s_red_c          ; </a></p>
        pop     r12
        pop     rbx
        jmp     ob_puts

; ---------------------------------------------------------------------------
; render_403() -- posting requires an invite.
; clobbers: caller-saved regs; preserves rbx.
render_403:
        push    rbx
        mov     rbx, [fs:TLS_SELF]
        mov     qword [rbx + TLS_OBLEN], 0
        mov     edi, s_403a
        call    ob_puts
        mov     edi, s_hdr
        call    ob_puts
        call    emit_head
        mov     edi, s_403body
        pop     rbx
        jmp     ob_puts

; ---------------------------------------------------------------------------
; render_join(rdi=error flag) -- the redeem page; nonzero shows the error line.
; clobbers: caller-saved regs; preserves rbx, r12.
render_join:
        push    rbx
        push    r12
        mov     r12, rdi                ; error flag
        mov     rbx, [fs:TLS_SELF]
        mov     qword [rbx + TLS_OBLEN], 0
        mov     edi, s_200
        call    ob_puts
        mov     edi, s_hdr
        call    ob_puts
        call    emit_head
        mov     edi, s_join_a
        call    ob_puts
        test    r12, r12
        jz      .form
        mov     edi, s_join_err
        call    ob_puts
.form:
        mov     edi, s_join_b
        pop     r12
        pop     rbx
        jmp     ob_puts

; ---------------------------------------------------------------------------
; render_head_cookie(rdi=cookie name z-string, rsi=value, rdx=value length)
; 200 response that installs the session cookie, plus a short confirmation.
; The value is emitted by length, not assumed NUL-terminated.
; clobbers: caller-saved regs; preserves rbx, r12-r14.
render_head_cookie:
        push    rbx
        push    r12
        push    r13
        push    r14
        mov     r12, rdi                ; name
        mov     r13, rsi                ; value
        mov     r14, rdx                ; value length
        mov     rbx, [fs:TLS_SELF]
        mov     qword [rbx + TLS_OBLEN], 0
        mov     edi, s_200
        call    ob_puts
        mov     edi, s_ck_a           ; "Set-Cookie: "
        call    ob_puts
        mov     rdi, r12
        call    ob_puts
        mov     edi, s_ck_b           ; "="
        call    ob_puts
        mov     rdi, r13
        mov     rsi, r14
        call    ob_put
        mov     edi, s_ck_c           ; attributes + CRLF
        call    ob_puts
        mov     edi, s_hdr
        call    ob_puts
        call    emit_head
        mov     edi, s_joined
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        jmp     ob_puts

; ---------------------------------------------------------------------------
; render_admin() -- operator panel.
; Unlike the public pages this deliberately SHOWS uncommitted and deleted
; records: hiding them is exactly what an operator must not have done for him.
; clobbers: caller-saved regs; preserves rbx, rbp, r12-r15.
render_admin:
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        push    r15
        mov     rbx, [fs:TLS_SELF]
        mov     qword [rbx + TLS_OBLEN], 0
        mov     edi, s_200
        call    ob_puts
        mov     edi, s_hdr
        call    ob_puts
        call    emit_head
        mov     edi, s_adm_top
        call    ob_puts

        ; ---- invites, ascending
        call    inv_count
        mov     r12, rax
        xor     r13d, r13d
.inv:
        cmp     r13, r12
        jae     .inv_done
        mov     rdi, r13
        call    inv_rec
        test    rax, rax
        jz      .inv_next
        cmp     dword [rax + I_TIME], 0
        je      .inv_next               ; reserved slot, no code written yet
        mov     rbp, rax
        mov     edi, s_adm_inv        ; <tr><td>
        call    ob_puts
        mov     rdi, r13
        call    ob_putu                 ; index
        mov     edi, s_adm_td
        call    ob_puts
        ; The code is hex today, but rendering it raw would make this panel a
        ; stored-XSS sink the moment anything upstream changes.
        lea     rdi, [rbp + I_CODE]
        push    CODE_LEN
        pop     rsi
        call    ob_put_esc_z
        mov     edi, s_adm_td
        call    ob_puts
        ; status: revoked > used > unused
        test    byte [rbp + I_FLAGS], INV_FLAG_REVOKED
        jz      .inv_used
        mov     edi, s_st_rev
        call    ob_puts
        mov     edi, s_adm_tr           ; no revoke button for a revoked invite
        call    ob_puts
        jmp     .inv_next
.inv_used:
        mov     r14d, [rbp + I_USED]
        test    r14d, r14d
        jnz     .inv_usedby
        mov     edi, s_st_free
        call    ob_puts
        jmp     .inv_btn
.inv_usedby:
        mov     edi, s_st_used
        call    ob_puts
        lea     rdi, [r14 - 1]          ; field stores 1 + post index
        call    ob_putu
.inv_btn:
        mov     edi, s_adm_rev
        call    ob_puts
        mov     rdi, r13
        call    ob_putu
        mov     edi, s_adm_revb
        call    ob_puts
        mov     edi, s_adm_tr
        call    ob_puts
.inv_next:
        inc     r13
        jmp     .inv
.inv_done:
        mov     edi, s_adm_mid          ; </table><h1>posts</h1><table>
        call    ob_puts

        ; ---- posts, newest first
        call    db_count
        mov     r12, rax
        test    r12, r12
        jz      .done
        mov     r13, r12
.post:
        dec     r13
        mov     rdi, r13
        call    db_rec
        test    rax, rax
        jz      .post_next
        mov     rbp, rax
        mov     edi, s_adm_inv
        call    ob_puts
        mov     rdi, r13
        call    ob_putu                 ; index
        mov     edi, s_adm_td
        call    ob_puts
        cmp     dword [rbp + R_TIME], 0
        jne     .post_live
        mov     edi, s_st_unc           ; reserved but never published
        call    ob_puts
        mov     edi, s_adm_tr
        call    ob_puts
        jmp     .post_next
.post_live:
        mov     eax, R_AUTHOR
        push    AUTHOR_MAX
        pop     rsi
        lea     rdx, [s_anon]
        mov     rdi, rbp
        call    ef_a
        mov     edi, s_adm_td
        call    ob_puts
        cmp     dword [rbp + R_PARENT], r13d
        je      .post_root
        mov     edi, s_reply_to         ; "(reply to N)"
        call    ob_puts
        mov     edi, [rbp + R_PARENT]
        call    ob_putu
        mov     edi, s_paren
        call    ob_puts
        jmp     .post_inv
.post_root:
        mov     eax, R_TITLE
        push    TITLE_MAX
        pop     rsi
        lea     rdx, [s_untitled]
        mov     rdi, rbp
        call    ef_a
.post_inv:
        mov     edi, s_adm_td
        call    ob_puts
        mov     edi, s_inv_col
        call    ob_puts
        mov     edi, [rbp + R_INVITE]
        call    ob_putu                 ; authoring invite
        mov     edi, s_adm_td
        call    ob_puts
        test    byte [rbp + R_FLAGS], FLAG_DELETED
        jz      .post_btn
        mov     edi, s_st_del
        call    ob_puts
        mov     edi, s_adm_tr           ; already deleted: no button
        call    ob_puts
        jmp     .post_next
.post_btn:
        mov     edi, s_st_ok
        call    ob_puts
        mov     edi, s_adm_del
        call    ob_puts
        mov     rdi, r13
        call    ob_putu
        mov     edi, s_adm_delb
        call    ob_puts
        mov     edi, s_adm_tr
        call    ob_puts
.post_next:
        test    r13, r13
        jnz     .post
.done:
        mov     edi, s_adm_end
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        jmp     ob_puts
