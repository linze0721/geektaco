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
         db 'table.s{width:auto;margin-bottom:1.5rem}'
         db 'table.s td{border:0;padding:.15rem .8rem .15rem 0}'
         db 'td.n{text-align:right;color:#8e8}'
         db 'td.w{text-align:right;color:#da6}'
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

; ---- pagination nav -------------------------------------------------------
s_nv_a:  db '<nav>', 0
s_nv_nw: db '<a href="', 0
s_nv_nwt: db '">newer</a>', 0
s_nv_pg: db '<span class=m> page ', 0
s_nv_pge: db ' </span>', 0
s_nv_odt: db '">older</a>', 0
s_nv_end: db '</nav>', 0
s_pfx_p: db '/p/', 0
s_pfx_t: db '/t/', 0
s_slash: db '/', 0

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
s_adm_hdr: db '<header><a href="/">geektaco</a><span class=g> / admin</span></header>', 0
; Stats sit between the header and the invites table. The uncommitted count is
; the one diagnostic number here: nonzero means a worker died mid-write.
s_st_a:   db '<table class=s>', 0
s_st_r:   db '<tr><td>', 0
s_st_v:   db '</td><td class=n>', 0
s_st_e:   db '</td></tr>', 0
s_st_warn: db '</td><td class=w>', 0
s_st_z:   db '</table>', 0
s_l_slot: db 'slots', 0
s_l_live: db 'committed', 0
s_l_hole: db 'uncommitted', 0
s_l_del:  db 'deleted', 0
s_l_root: db 'threads', 0
s_l_rep:  db 'replies', 0
s_l_inv:  db 'invites', 0
s_l_free: db 'unused', 0
s_l_uses: db 'redeemed', 0
s_l_rev:  db 'revoked', 0
s_adm_top: db '<h1>invites</h1>'
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
; emit_nav(rdi=page, rsi=more flag, rdx=prefix z-string, rcx=thread index)
; Emits "newer . page N . older", omitting whichever link does not exist.
; rdx is "/p/" for the index or "/t/" for a thread; when it is "/t/" the
; thread index in rcx is emitted before the page segment. Page 0 canonicalises
; to "/" or "/t/<n>" so the first page never has two URLs.
; clobbers: caller-saved regs; preserves rbx, r12-r15.
emit_nav:
        push    rbx
        push    r12
        push    r13
        push    r14
        push    r15
        mov     r12, rdi                ; page
        mov     r13, rsi                ; more?
        mov     r14, rdx                ; prefix
        mov     r15, rcx                ; thread index (only for "/t/")
        test    r12, r12
        jnz     .has_newer
        test    r13, r13
        jz      .none                   ; single page: no nav at all
.has_newer:
        mov     edi, s_nv_a
        call    ob_puts
        test    r12, r12
        jz      .page_no                ; page 0 has nothing newer
        mov     edi, s_nv_nw          ; <a href="
        call    ob_puts
        lea     rdi, [r12 - 1]
        call    .href
        mov     edi, s_nv_nwt         ; ">newer</a>
        call    ob_puts
.page_no:
        mov     edi, s_nv_pg
        call    ob_puts
        lea     rdi, [r12 + 1]          ; 1-based for a human reader
        call    ob_putu
        mov     edi, s_nv_pge
        call    ob_puts
        test    r13, r13
        jz      .close
        mov     edi, s_nv_nw
        call    ob_puts
        lea     rdi, [r12 + 1]
        call    .href
        mov     edi, s_nv_odt         ; ">older</a>
        call    ob_puts
.close:
        mov     edi, s_nv_end
        call    ob_puts
.none:
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbx
        ret

; .href(rdi=target page) -- writes the URL for that page using r14/r15.
.href:
        push    rbp
        mov     rbp, rdi                ; target page
        cmp     r14d, s_pfx_t
        jne     .h_index
        mov     edi, s_pfx_t          ; /t/
        call    ob_puts
        mov     rdi, r15
        call    ob_putu                 ; /t/<root>
        test    rbp, rbp
        jz      .h_done                 ; page 0 is bare /t/<root>
        mov     edi, s_slash
        call    ob_puts
        mov     rdi, rbp
        call    ob_putu
        jmp     .h_done
.h_index:
        test    rbp, rbp
        jnz     .h_num
        mov     edi, s_slash          ; page 0 is bare /
        call    ob_puts
        jmp     .h_done
.h_num:
        mov     edi, s_pfx_p          ; /p/<n>
        call    ob_puts
        mov     rdi, rbp
        call    ob_putu
.h_done:
        pop     rbp
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
        ; Scratch holds the page number and the "a further page exists" flag:
        ; every register is already spoken for by the scan.
        mov     [rbx + TLS_PAGE], rdi   ; requested page
        mov     qword [rbx + TLS_MORE], 0
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
        xor     r14d, r14d              ; matching roots seen so far
        xor     r15d, r15d              ; roots emitted on this page
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
        ; Skip by MATCHES, never by raw index: deleting one thread would
        ; otherwise shift every later page and drop a row at each boundary.
        mov     rax, [rbx + TLS_PAGE]
        imul    rax, rax, PAGE_SIZE_N
        inc     r14
        cmp     r14, rax
        jbe     .next                   ; still ahead of this page's first row
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
        mov     edi, [rbp + R_NREPLY]   ; denormalised count: no rescan
        call    ob_putu
        mov     edi, s_th_e           ; replies</div></div>
        call    ob_puts
        inc     r15
        cmp     r15, PAGE_SIZE_N
        jb      .next
        ; Stop the moment the page is full. Walking on to record 0 and
        ; discarding would make page 0 O(n) again, which is the whole point.
        mov     qword [rbx + TLS_MORE], 1  ; more rows exist: show "older"
        jmp     .form
.next:
        test    r13, r13
        jnz     .outer                  ; stop after index 0 was processed
        jmp     .form
.empty:
        mov     edi, s_empty
        call    ob_puts
.form:
        mov     rdi, [rbx + TLS_PAGE]
        mov     rsi, [rbx + TLS_MORE]
        mov     edx, s_pfx_p
        xor     ecx, ecx
        call    emit_nav
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
        push    rbp
        push    r12
        push    r13
        push    r14
        push    r15
        mov     rbx, [fs:TLS_SELF]
        mov     [rbx + TLS_PAGE], rsi   ; requested reply page
        mov     qword [rbx + TLS_MORE], 0
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
        xor     ebp, ebp                ; matching replies seen
        xor     r15d, r15d              ; replies emitted on this page
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
        ; Skip by MATCHES, not by index, for the same reason as the index page.
        mov     rdx, [rbx + TLS_PAGE]
        imul    rdx, rdx, PAGE_SIZE_N
        inc     rbp
        cmp     rbp, rdx
        jbe     .rnext
        mov     rdi, rax
        call    emit_post
        inc     r15
        cmp     r15, PAGE_SIZE_N
        jb      .rnext
        mov     qword [rbx + TLS_MORE], 1  ; more replies exist
        jmp     .repdone
.rnext:
        inc     r13
        cmp     r13, r14
        jb      .rep
.repdone:
        mov     rdi, [rbx + TLS_PAGE]
        mov     rsi, [rbx + TLS_MORE]
        mov     edx, s_pfx_t
        mov     rcx, r12                ; thread index for the URL
        call    emit_nav
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
        call    ob_puts
.out:
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
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
; emit_stats() -- summary table above the admin panel's two lists.
; One pass per mapping; db_rec is called once per index, never twice.
; Counters live in TLS_SCRATCH because there are more of them than there are
; free callee-saved registers, and a .bss array would be shared by 4 threads.
;   scratch qword 0..5  slots, committed, holes, deleted, roots, replies
;   scratch qword 6..9  invites, unused, redeemed, revoked
; clobbers: caller-saved regs; preserves rbx, rbp, r12-r15.
emit_stats:
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        mov     rbx, [fs:TLS_SELF]
        mov     r14, [rbx + TLS_SCRATCH]
        xor     eax, eax
        mov     ecx, 10
        mov     rdi, r14
        rep     stosq                   ; zero all ten counters

        call    db_count
        mov     r12, rax
        mov     [r14], rax              ; slots = the cursor itself
        xor     r13d, r13d
.post:
        cmp     r13, r12
        jae     .posts_done
        mov     rdi, r13
        call    db_rec
        test    rax, rax
        jz      .posts_done             ; null means past the cursor: stop
        mov     rbp, rax
        cmp     dword [rbp + R_TIME], 0
        jne     .committed
        inc     qword [r14 + 16]        ; uncommitted hole
        jmp     .post_next
.committed:
        inc     qword [r14 + 8]
        test    byte [rbp + R_FLAGS], FLAG_DELETED
        jz      .not_del
        inc     qword [r14 + 24]
        jmp     .post_next              ; deleted rows are not counted as live
.not_del:
        cmp     dword [rbp + R_PARENT], r13d
        jne     .is_reply
        inc     qword [r14 + 32]        ; root
        jmp     .post_next
.is_reply:
        inc     qword [r14 + 40]
.post_next:
        inc     r13
        jmp     .post
.posts_done:

        call    inv_count
        mov     r12, rax
        xor     r13d, r13d
.inv:
        cmp     r13, r12
        jae     .inv_done
        mov     rdi, r13
        call    inv_rec
        test    rax, rax
        jz      .inv_done
        mov     rbp, rax
        cmp     dword [rbp + I_TIME], 0
        je      .inv_next               ; reserved, no code written yet
        inc     qword [r14 + 48]
        test    byte [rbp + I_FLAGS], INV_FLAG_REVOKED
        jz      .inv_live
        inc     qword [r14 + 72]
        jmp     .inv_next
.inv_live:
        cmp     dword [rbp + I_USED], 0
        jne     .inv_used
        inc     qword [r14 + 56]
        jmp     .inv_next
.inv_used:
        inc     qword [r14 + 64]
.inv_next:
        inc     r13
        jmp     .inv
.inv_done:

        mov     edi, s_st_a
        call    ob_puts
        mov     edi, s_l_slot
        mov     rsi, [r14]
        call    .row
        mov     edi, s_l_live
        mov     rsi, [r14 + 8]
        call    .row
        ; The only number that signals a fault, so it is the only one that
        ; changes colour -- and only when it is actually nonzero.
        mov     edi, s_l_hole
        mov     rsi, [r14 + 16]
        test    rsi, rsi
        jz      .hole_ok
        call    .row_warn
        jmp     .rest
.hole_ok:
        call    .row
.rest:
        mov     edi, s_l_del
        mov     rsi, [r14 + 24]
        call    .row
        mov     edi, s_l_root
        mov     rsi, [r14 + 32]
        call    .row
        mov     edi, s_l_rep
        mov     rsi, [r14 + 40]
        call    .row
        mov     edi, s_l_inv
        mov     rsi, [r14 + 48]
        call    .row
        mov     edi, s_l_free
        mov     rsi, [r14 + 56]
        call    .row
        mov     edi, s_l_uses
        mov     rsi, [r14 + 64]
        call    .row
        mov     edi, s_l_rev
        mov     rsi, [r14 + 72]
        call    .row
        mov     edi, s_st_z
        call    ob_puts
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        ret

; .row(rdi=label z-string, rsi=value) -- one label/value pair.
.row:
        push    r15
        mov     r15, rsi
        push    rdi
        mov     edi, s_st_r
        call    ob_puts
        pop     rdi
        call    ob_puts
        mov     edi, s_st_v
        call    ob_puts
        mov     rdi, r15
        call    ob_putu
        mov     edi, s_st_e
        call    ob_puts
        pop     r15
        ret
.row_warn:
        push    r15
        mov     r15, rsi
        push    rdi
        mov     edi, s_st_r
        call    ob_puts
        pop     rdi
        call    ob_puts
        mov     edi, s_st_warn
        call    ob_puts
        mov     rdi, r15
        call    ob_putu
        mov     edi, s_st_e
        call    ob_puts
        pop     r15
        ret

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
        mov     edi, s_adm_hdr
        call    ob_puts
        call    emit_stats
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
