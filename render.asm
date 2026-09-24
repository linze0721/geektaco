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
global render_login, render_register, render_admin, render_403, render_head_cookie

extern db_count
extern db_rec
extern inv_count, inv_rec, usr_rec

section .rodata

; HTML entities. Kept out of the compressed table: ob_put_esc emits them
; through ob_put (no expansion), so they must be plain literals.
e_amp:   db '&amp;', 0
e_lt:    db '&lt;', 0
e_gt:    db '&gt;', 0
e_quot:  db '&quot;', 0
e_apos:  db '&#39;', 0

%include "strtab.inc"

; EMIT name, ... -- append strings by ID. Expands to `call emit` followed by
; one ID byte per string, bit 7 set on the last; emit returns past it.
; A name may also be an @field opcode (see FIELD_OPS): IDs from SID_COUNT up
; emit a field of the caller's record in rbp or its index in r13.
%macro EMIT 1-*
        call    emit
%rep %0 - 1
        db      sid_%1
%rotate 1
%endrep
        db      sid_%1 | 0x80
%endmacro

; Field opcodes, in ID order after the strings. Each op_X is a stub in the
; field-op block below; field_ops holds their offsets from op_base.
%define FIELD_OPS nreply, inv, parent, idx, author, title, date, body, code, reset, path, cookie, span_esc, span_md, url, item
%macro field_ids 1-*
%assign i 0
%rep %0
sid_@%1 equ SID_COUNT + i
%assign i i + 1
%rotate 1
%endrep
%if SID_COUNT + i > 0x80
%error "string IDs and field opcodes must fit in 7 bits"
%endif
%endmacro
%macro field_tab 1-*
%rep %0
        db      op_%1 - op_base
        times   (op_%1 - op_base) / 256 * -1 db 0   ; error: op past byte range
%rotate 1
%endrep
%endmacro
field_ids FIELD_OPS
field_ops: field_tab FIELD_OPS

month_days: db 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31

; render_login/render_register message for error codes 1..5.
auth_err: db sid_lg_e1, sid_rg_e2, sid_rg_e3, sid_rg_e4, sid_rg_e5

section .text


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
; ob_puts(rdi=NUL-terminated string) -- append it, expanding dictionary tokens.
;
; Bytes in TOK_LO..TOK_HI are indices into str_dict and expand recursively;
; everything else is emitted raw. The generator guarantees those byte values
; never occur literally in the corpus.
;
; EXPANSION IS LITERAL-ONLY. ob_put and ob_put_esc deliberately do NOT expand,
; because they carry user data: a poster who submitted a raw 0x03 byte would
; otherwise have it turn into live markup. ob_put_esc drops control bytes
; below 0x20 anyway, but the separation is the actual guarantee -- do not
; "unify" these two paths.
; clobbers: caller-saved regs; preserves rbx, r12.
ob_puts:
        push    rbx
        push    r12
        mov     r12, rdi
.next:
        movzx   eax, byte [r12]
        test    al, al
        jz      .done
        inc     r12
        cmp     al, TOK_LO
        jb      .raw
        cmp     al, TOK_HI
        ja      .raw
        ; token: recurse into its dictionary entry
        lea     edx, [rax - TOK_LO]
        mov     edi, str_dict
        call    nth
        call    ob_puts
        jmp     .next
.raw:
        mov     edi, eax
        call    ob_putc
        jmp     .next
.done:
        pop     r12
        pop     rbx
        ret

; ---------------------------------------------------------------------------
; emit -- `call emit` followed by inline IDs (see EMIT). Each ID goes to
; ob_putid; the byte with bit 7 set is the last one, and emit returns to the
; instruction after it. The ID cursor lives on the stack, so field opcodes
; see every register of the caller.
; clobbers: rax, rdx, rdi, flags when every ID is a string (ob_put_md relies
; on rcx surviving); caller-saved regs when a field opcode is used.
emit:
        pop     rax                     ; -> first ID
.id:
        movzx   edi, byte [rax]
        inc     rax
        push    rax
        and     edi, 0x7f
        call    ob_putid
        pop     rax
        test    byte [rax - 1], 0x80
        jz      .id
        jmp     rax                     ; return past the last ID

; ob_putid(edi=string ID) -- ob_puts of string ID edi (s_* in ID order);
; IDs from SID_COUNT run field opcode edi - SID_COUNT instead.
; clobbers: caller-saved regs; preserves rbx, r12.
ob_putid:
        mov     edx, edi
        cmp     edi, SID_COUNT
        jae     .op
        mov     edi, str_ids
        call    nth
        jmp     ob_puts
.op:
        movzx   eax, byte [rdx + field_ops - SID_COUNT]
        add     eax, op_base
        jmp     rax

; nth(rdi=first of consecutive z-strings, edx=n) -> rdi = the n-th string.
; clobbers: rax, rdx, flags.
nth:
        xor     eax, eax
.skip:
        dec     edx
        js      .ret
.nul:
        scasb
        jne     .nul
        jmp     .skip
.ret:
        ret

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
; Field opcodes (EMIT @name). Records: rbp = post record (invite record for
; @code), r13 = its index. Each stub clobbers caller-saved regs only.
op_base:
; ob_reset() -- empty the output buffer. Also EMIT @reset.
; args: none.  returns: nothing.  clobbers: nothing (writes TLS_OBLEN only).
ob_reset:
op_reset:
        push    rbx
        mov     rbx, [fs:TLS_SELF]
        mov     qword [rbx + TLS_OBLEN], 0
        pop     rbx
        ret
op_path:                                ; r12 = z-string (redirect path,
        mov     rdi, r12                ; cookie name): trusted, not user data
        jmp     ob_puts
op_cookie:                              ; r13/r14 = cookie value and length
        mov     rdi, r13
        mov     rsi, r14
        jmp     ob_put
; Markdown inline spans: rbx = text base, [rbp, r14) = span, r13 = URL start
; and r12 - 1 = URL end (the ')' index).
op_url:
        lea     rdi, [rbx + r13]
        lea     rsi, [r12 - 1]
        sub     rsi, r13
        jmp     ob_put_esc              ; url escaped too: quotes cannot break out
op_item:                                ; ob_put_md: line r13 of length rcx,
        lea     rdi, [rbx + r13 + 2]    ; minus its "> " / "- " marker
        lea     rsi, [rcx - 2]
        jmp     md_inline
op_span_esc:
        mov     eax, ob_put_esc         ; no inline processing inside
        jmp     op_span
op_span_md:
        mov     eax, md_inline          ; nested inline markup
op_span:
        lea     rdi, [rbx + rbp]
        mov     rsi, r14
        sub     rsi, rbp
        jmp     rax
op_nreply:                              ; reply count of a root
        mov     edi, [rbp + R_NREPLY]
        jmp     op_u
op_inv:                                 ; authoring user/invite
        mov     edi, [rbp + R_INVITE]
        jmp     op_u
op_parent:                              ; thread root index
        mov     edi, [rbp + R_PARENT]
        jmp     op_u
op_idx:                                 ; the record's own index
        mov     rdi, r13
op_u:
        jmp     ob_putu
op_date:
        mov     edi, [rbp + R_TIME]
        jmp     ob_putdate
op_body:
        lea     rdi, [rbp + R_BODY]
        mov     esi, BODY_MAX
        jmp     ob_put_md
op_code:                                ; invite code, escaped: rendering it
        lea     rdi, [rbp + I_CODE]     ; raw would make the admin panel a
        push    CODE_LEN                ; stored-XSS sink the moment anything
        pop     rsi                     ; upstream changes
        jmp     ob_put_esc_z
; Author / title, escaped; when the field is empty the "anon" / "(no subject)"
; fallback is appended instead, so links stay clickable and meta lines never
; render blank.
op_author:
        lea     rdi, [rbp + R_AUTHOR]
        push    AUTHOR_MAX
        pop     rsi
        mov     dl, sid_anon
        jmp     op_esc
op_title:
        lea     rdi, [rbp + R_TITLE]
        push    TITLE_MAX
        pop     rsi
        mov     dl, sid_untitled
op_esc:
        cmp     byte [rdi], 0
        jne     ob_put_esc_z
        movzx   edi, dl
        jmp     ob_putid

; ---------------------------------------------------------------------------
; ob_putdate(edi=unix epoch seconds) -- "1999-12-31 23:59 UTC".
; A raw epoch integer is an unfinished-looking detail on a message board, and
; a board of this era always showed a readable date.
;
; An unsigned 32-bit epoch spans 1970-01-01 .. 2106-02-07, so the date is
; found by walking whole years and then months: at most 136 + 11 steps, no
; division beyond splitting off the time of day. Within that span every year
; divisible by 4 is a leap year except 2100.
; clobbers: caller-saved regs; preserves rbx, r12-r15.
ob_putdate:
        push    r12
        mov     eax, edi
        xor     edx, edx
        mov     ecx, 86400
        div     ecx                     ; eax = days, edx = second of day
        xchg    eax, edx
        mov     esi, edx                ; days since 1970-01-01
        push    60
        pop     rcx
        cdq                             ; second of day < 2^31: edx = 0
        div     ecx                     ; eax = minute of day
        cdq
        div     ecx                     ; eax = hour, edx = minute
        push    rdx                     ; the four padded fields, popped in
        push    rax                     ; output order below: month, day,
        mov     edi, 1970               ; hour, minute
.year:
        xor     ecx, ecx                ; ecx = 1 in a leap year
        test    dil, 3
        jnz     .ylen
        cmp     edi, 2100
        setne   cl
.ylen:
        lea     eax, [rcx + 365]
        cmp     esi, eax
        jb      .month0
        sub     esi, eax
        inc     edi
        jmp     .year
.month0:
        xor     edx, edx                ; month - 1
.month:
        movzx   eax, byte [rdx + month_days]
        cmp     edx, 1
        jne     .mlen
        add     eax, ecx                ; February
.mlen:
        cmp     esi, eax
        jb      .mdone
        sub     esi, eax
        inc     edx
        jmp     .month
.mdone:
        inc     esi                     ; day of month, 1-based
        push    rsi
        inc     edx
        push    rdx
        call    ob_putu                 ; year
        mov     r12d, s_dsep            ; "-- :" precede the four fields
.field:
        movzx   edi, byte [r12]
        call    ob_putc
        pop     rdi
        cmp     edi, 10                 ; two digits, zero padded
        jae     .wide
        push    rdi
        mov     dil, '0'
        call    ob_putc
        pop     rdi
.wide:
        call    ob_putu
        inc     r12
        cmp     byte [r12], 0
        jne     .field
        pop     r12
        EMIT    utc
        ret

; ---------------------------------------------------------------------------
; Markdown rendering for post bodies.
;
; ORDER IS THE WHOLE SECURITY ARGUMENT: every byte of user text reaches the
; page through ob_put_esc, and the only unescaped bytes are the literal tags
; this code emits itself. Parsing first and escaping afterwards is the classic
; markdown XSS -- you either escape your own tags into visible text, or you
; exempt them and hand the user a hole.
;
; Second rule, specific to this codebase: ob_puts expands dictionary tokens
; and is fed literals only. User bytes go to ob_put_esc, never ob_puts.
;
; Subset: fenced code, blockquote, unordered list, paragraphs; inline code,
; **strong**, *em*, and [text](url) with an http/https// scheme allowlist.
; Unmatched markers render literally. No headings, images, tables, or HTML.

; md_inline(rdi=ptr, rsi=len) -- inline pass over one already-block-classified
; run of text. clobbers caller-saved; preserves rbx, rbp, r12-r15.
md_inline:
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        mov     rbx, rdi                ; base
        mov     r12, rsi                ; length
        xor     r13d, r13d              ; cursor
.loop:
        cmp     r13, r12
        jae     .done
        movzx   eax, byte [rbx + r13]
        cmp     al, '`'
        je      .code
        cmp     al, '*'
        je      .star
        cmp     al, '['
        je      .link
.lit:
        ; ordinary byte: emit escaped, one at a time so the scanner stays simple
        lea     rdi, [rbx + r13]
        push    1
        pop     rsi
        call    ob_put_esc
        inc     r13
        jmp     .loop

        ; ---- `code` --------------------------------------------------------
.code:
        lea     rbp, [r13 + 1]
        mov     r14, rbp
.code_scan:
        cmp     r14, r12
        jae     .lit                    ; unmatched backtick: literal
        cmp     byte [rbx + r14], '`'
        je      .code_hit
        inc     r14
        jmp     .code_scan
.code_hit:
        EMIT    md_cd, @span_esc, md_cde
        lea     r13, [r14 + 1]
        jmp     .loop

        ; ---- **strong** and *em* -------------------------------------------
.star:
        lea     rbp, [r13 + 1]
        cmp     rbp, r12
        jae     .lit
        cmp     byte [rbx + rbp], '*'
        jne     .em
        ; strong: find a closing "**"
        inc     rbp                     ; content start
        mov     r14, rbp
.st_scan:
        lea     rax, [r14 + 1]
        cmp     rax, r12
        jae     .lit
        cmp     byte [rbx + r14], '*'
        jne     .st_next
        cmp     byte [rbx + rax], '*'
        je      .st_hit
.st_next:
        inc     r14
        jmp     .st_scan
.st_hit:
        EMIT    md_st, @span_md, md_ste
        lea     r13, [r14 + 2]
        jmp     .loop
.em:
        mov     r14, rbp
.em_scan:
        cmp     r14, r12
        jae     .lit
        cmp     byte [rbx + r14], '*'
        je      .em_hit
        inc     r14
        jmp     .em_scan
.em_hit:
        cmp     r14, rbp
        je      .lit                    ; "**" with nothing between: literal
        EMIT    md_em, @span_md, md_eme
        lea     r13, [r14 + 1]
        jmp     .loop

        ; ---- [text](url) ---------------------------------------------------
.link:
        lea     rbp, [r13 + 1]          ; text start
        mov     r14, rbp
.lk_text:
        cmp     r14, r12
        jae     .lit
        cmp     byte [rbx + r14], ']'
        je      .lk_close
        inc     r14
        jmp     .lk_text
.lk_close:
        lea     rax, [r14 + 1]
        cmp     rax, r12
        jae     .lit
        cmp     byte [rbx + rax], '('
        jne     .lit
        ; r14 = ']' index, url starts at r14+2
        lea     rdx, [r14 + 2]
        mov     r8, rdx                 ; url start
.lk_url:
        cmp     rdx, r12
        jae     .lit
        cmp     byte [rbx + rdx], ')'
        je      .lk_have
        inc     rdx
        jmp     .lk_url
.lk_have:
        ; rdx = ')' index. Scheme allowlist: http://, https://, or leading '/'.
        ; Anything else -- javascript:, data:, vbscript: -- renders as plain
        ; text. This check is the entire reason links are safe to support.
        push    rdx
        push    r8
        mov     rdi, rbx
        add     rdi, r8
        mov     rsi, rdx
        sub     rsi, r8
        call    md_url_ok
        pop     r8
        pop     rdx
        test    eax, eax
        jz      .lit                    ; rejected: fall through to literal
        ; rdx (the ')' index) and r8 (url start) are caller-saved, so the
        ; URL moves to callee-saved r13 (@url) and r12 (resume point) before
        ; emitting anything. Link text is escaped, no nested markup.
        push    r12
        lea     r12, [rdx + 1]          ; resume just past ')'
        mov     r13, r8
        EMIT    md_a1, @url, md_a2, @span_esc, md_a3
        mov     r13, r12
        pop     r12
        jmp     .loop
.done:
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        ret

; md_url_ok(rdi=ptr, rsi=len) -> eax = 1 if the URL may be linked.
; Allowlist only: "/" prefix, "http://", "https://". Everything else is
; rejected, which is what keeps javascript: and data: out of href.
md_url_ok:
        test    rsi, rsi
        jz      .no
        cmp     byte [rdi], '/'
        je      .yes
        cmp     rsi, 7
        jb      .no
        mov     eax, [rdi]
        or      eax, 0x20202020         ; fold case
        cmp     eax, 'http'
        jne     .no
        ; "http" matched. Accept "http://" or "https://" -- compare the
        ; separator bytes individually rather than as a dword, so a 7-byte
        ; URL cannot be matched by reading an 8th byte past its end.
        cmp     byte [rdi + 4], ':'
        je      .sep
        cmp     byte [rdi + 4], 's'
        jne     .no
        cmp     rsi, 8
        jb      .no
        inc     rdi                     ; skip the 's', then expect "://"
        cmp     byte [rdi + 4], ':'
        jne     .no
.sep:
        cmp     byte [rdi + 5], '/'
        jne     .no
        cmp     byte [rdi + 6], '/'
        jne     .no
.yes:
        mov     eax, 1
        ret
.no:
        xor     eax, eax
        ret

; ob_put_md(rdi=ptr, rsi=capacity) -- block pass over a NUL-padded body.
; Walks line by line: ``` fences a code block (verbatim, escaped, no inline),
; "> " is a blockquote, "- "/"* " builds a list, everything else accumulates
; into a paragraph. clobbers caller-saved; preserves rbx, rbp, r12-r15.
ob_put_md:
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        push    r15
        mov     rbx, rdi                ; base
        ; logical length: up to the first NUL or the capacity
        xor     r12d, r12d
.len:
        cmp     r12, rsi
        jae     .len_done
        cmp     byte [rbx + r12], 0
        je      .len_done
        inc     r12
        jmp     .len
.len_done:
        xor     r13d, r13d              ; cursor
        xor     r14d, r14d              ; 1 while inside <ul>
        xor     r15d, r15d              ; 1 while inside a paragraph

.line:
        cmp     r13, r12
        jae     .finish
        ; rbp = end of this line (index of \n, or r12)
        mov     rbp, r13
.eol:
        cmp     rbp, r12
        jae     .eol_done
        cmp     byte [rbx + rbp], 10
        je      .eol_done
        inc     rbp
        jmp     .eol
.eol_done:
        mov     rax, rbp
        sub     rax, r13                ; line length
        ; strip a trailing CR so CRLF bodies behave
        test    rax, rax
        jz      .have
        mov     rcx, rbp
        dec     rcx
        cmp     byte [rbx + rcx], 13
        jne     .have
        dec     rax
.have:
        mov     rcx, rax                ; rcx = line length (no CR)
        ; ---- fence?
        cmp     rcx, 3
        jb      .not_fence
        cmp     word [rbx + r13], '``'
        jne     .not_fence
        cmp     byte [rbx + r13 + 2], '`'
        jne     .not_fence
        call    .close_open
        EMIT    md_pre
        ; body runs from the line after the fence to a closing fence
        lea     r13, [rbp + 1]
.fence_line:
        cmp     r13, r12
        jae     .fence_done
        mov     rbp, r13
.f_eol:
        cmp     rbp, r12
        jae     .f_eol_done
        cmp     byte [rbx + rbp], 10
        je      .f_eol_done
        inc     rbp
        jmp     .f_eol
.f_eol_done:
        mov     rax, rbp
        sub     rax, r13
        cmp     rax, 3
        jb      .f_emit
        cmp     word [rbx + r13], '``'
        jne     .f_emit
        cmp     byte [rbx + r13 + 2], '`'
        je      .fence_close
.f_emit:
        lea     rdi, [rbx + r13]
        mov     rsi, rax
        call    ob_put_esc              ; verbatim, no inline pass
        push    10
        pop     rdi
        call    ob_putc
        lea     r13, [rbp + 1]
        jmp     .fence_line
.fence_close:
        lea     r13, [rbp + 1]
.fence_done:
        EMIT    md_pree
        jmp     .line
.not_fence:
        ; ---- blank line ends a paragraph and a list
        test    rcx, rcx
        jnz     .not_blank
        call    .close_open
        lea     r13, [rbp + 1]
        jmp     .line
.not_blank:
        ; ---- "> " blockquote
        cmp     rcx, 2
        jb      .not_quote
        cmp     byte [rbx + r13], '>'
        jne     .not_quote
        cmp     byte [rbx + r13 + 1], ' '
        jne     .not_quote
        call    .close_open
        EMIT    md_bq, @item, md_bqe
        lea     r13, [rbp + 1]
        jmp     .line
.not_quote:
        ; ---- "- " or "* " list item
        cmp     rcx, 2
        jb      .para
        cmp     byte [rbx + r13 + 1], ' '
        jne     .para
        movzx   eax, byte [rbx + r13]
        cmp     al, '-'
        je      .item
        cmp     al, '*'
        jne     .para
.item:
        test    r15, r15
        jz      .item_nop
        EMIT    md_pe           ; a list ends any open paragraph
        xor     r15d, r15d
.item_nop:
        test    r14, r14
        jnz     .item_body
        EMIT    md_ul
        mov     r14d, 1
.item_body:
        EMIT    md_li, @item, md_lie ; rcx survives the string IDs before @item
        lea     r13, [rbp + 1]
        jmp     .line
.para:
        ; ---- paragraph text. A hard newline inside a paragraph is preserved
        ; as a newline; the stylesheet's pre-wrap keeps it visible, so old
        ; multi-line posts do not collapse onto one line.
        test    r14, r14
        jz      .para_nolist
        EMIT    md_ule
        xor     r14d, r14d
.para_nolist:
        test    r15, r15
        jnz     .para_cont
        EMIT    md_p
        mov     r15d, 1
        jmp     .para_text
.para_cont:
        push    10
        pop     rdi
        call    ob_putc                 ; line break within the paragraph
.para_text:
        lea     rdi, [rbx + r13]
        mov     rsi, rcx
        call    md_inline
        lea     r13, [rbp + 1]
        jmp     .line

.finish:
        call    .close_open
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        ret

; close whichever block is open; clobbers only caller-saved regs
.close_open:
        test    r15, r15
        jz      .co_list
        EMIT    md_pe
        xor     r15d, r15d
.co_list:
        test    r14, r14
        jz      .co_done
        EMIT    md_ule
        xor     r14d, r14d
.co_done:
        ret

; ---------------------------------------------------------------------------
; emit_post(rdi=record) -- one post block: h1 close + meta line + body.
; clobbers: caller-saved regs; preserves rbx, rbp.
emit_post:
        push    rbp
        mov     rbp, rdi
        EMIT    h1b, @author, dot, @date, post_c, @body, post_d
        pop     rbp
        ret

; ---------------------------------------------------------------------------
; emit_nav(ecx=thread index, or -1 for the index page) -- rbx = TLS base.
; Emits "newer . page N . older" for TLS_PAGE / TLS_MORE, omitting whichever
; link does not exist. Index links are "/p/<n>"; thread links are
; "/t/<ecx>/<n>". Page 0 canonicalises to "/" or "/t/<ecx>" so the first page
; never has two URLs.
; clobbers: caller-saved regs; preserves rbx, rbp, r12-r15.
emit_nav:
        push    r12
        push    r13
        push    r14
        push    r15
        mov     r12, [rbx + TLS_PAGE]
        mov     r14, [rbx + TLS_MORE]
        mov     r15d, ecx               ; thread index; sign set: index page
        lea     r13, [r12 + 1]          ; 1-based page for a human reader
        mov     rax, r12
        or      rax, r14
        jz      .none                   ; single page: no nav at all
        EMIT    nv_a
        test    r12, r12
        jz      .page_no                ; page 0 has nothing newer
        lea     rdi, [r12 - 1]
        call    .href
        EMIT    nv_nwt          ; ">newer</a>
.page_no:
        EMIT    nv_pg, @idx, nv_pge
        test    r14, r14
        jz      .none
        mov     rdi, r13
        call    .href
        EMIT    nv_odt          ; ">older</a>
.none:
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        ret

; .href(rdi=target page) -- '<a href="' and the URL for that page, using r15.
.href:
        push    rbp
        mov     rbp, rdi                ; target page
        EMIT    nv_nw           ; <a href="
        push    sid_pfx_p
        pop     rdi
        test    r15d, r15d
        js      .h_page
        EMIT    pfx_t           ; /t/<root>
        mov     edi, r15d
        call    ob_putu
        push    sid_slash
        pop     rdi
        test    rbp, rbp
        jnz     .h_num
        pop     rbp                     ; page 0 is bare /t/<root>
        ret
.h_page:
        test    rbp, rbp
        jnz     .h_num
        pop     rbp                     ; index page 0 is bare /
        mov     dil, sid_slash
        jmp     ob_putid
.h_num:
        call    ob_putid                ; /p/<n> or /t/<root>/<n>
        mov     rdi, rbp
        pop     rbp
        jmp     ob_putu

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
        EMIT    @reset, 200, hdr, head, idx_top
        call    db_count
        mov     r12, rax                ; snapshot of the allocation cursor
        test    r12, r12
        jz      .empty
        EMIT    ul_a            ; <ul> wraps rows only, never the
                                ; empty-state paragraph
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
        ; the reply count is denormalised: no rescan
        EMIT    th_a, @idx, th_b, @title, th_c, @author, dot, @nreply, th_e
        inc     r15
        cmp     r15, PAGE_SIZE_N
        jb      .next
        ; Stop the moment the page is full. Walking on to record 0 and
        ; discarding would make page 0 O(n) again, which is the whole point.
        mov     qword [rbx + TLS_MORE], 1  ; more rows exist: show "older"
        jmp     .listend
.next:
        test    r13, r13
        jnz     .outer                  ; stop after index 0 was processed
        jmp     .listend
.empty:
        EMIT    empty
        jmp     .form
.listend:
        EMIT    ul_b            ; </ul>
.form:
        or      ecx, -1                 ; index links
        call    emit_nav
        ; Signed in: name the account and offer sign-out. Signed out: offer
        ; the two ways in. The nav is the only place identity is visible.
        cmp     qword [rbx + TLS_USER], 0
        jl      .anon_nav
        EMIT    who
        mov     rdi, [rbx + TLS_USER]
        call    usr_rec
        test    rax, rax
        jz      .nav_out
        lea     rdi, [rax + U_NAME]
        push    NAME_MAX
        pop     rsi
        call    ob_put_esc_z
        EMIT    lg_out
        jmp     .nav_out
.anon_nav:
        EMIT    nav
.nav_out:
        EMIT    newform, f_a, newform2, f_b, newform3
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        ret

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
        mov     rbp, rax                ; direct root pointer until reply scan
        cmp     dword [rbp + R_PARENT], r12d ; must be a root record
        jne     .notfound
        EMIT    @reset, 200, hdr, head, t_top, @title   ; header + <h2>title
        ; -- root post (emit_post closes the heading first)
        mov     rdi, rbp
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
        mov     ecx, r12d               ; thread links
        call    emit_nav
        mov     r13, r12                ; hidden p=<root index>
        EMIT    repl_a, @idx, th_b, f_a, f_b, repl_b
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
        EMIT    @reset, 404a, hdr, head, 404body
        ret

; ---------------------------------------------------------------------------
; render_redirect(rdi=NUL-terminated location path) -- 302 response.
; clobbers: caller-saved regs.
render_redirect:
        push    r12
        mov     r12, rdi                ; path
        EMIT    @reset, 302a, @path, crlf, hdr, red_a, @path, th_b, @path, red_c
        pop     r12
        ret

; ---------------------------------------------------------------------------
; render_403() -- posting requires an invite.
; clobbers: caller-saved regs; preserves rbx.
render_403:
        EMIT    @reset, 403a, hdr, head, 403body
        ret

; ---------------------------------------------------------------------------
; render_login(rdi=error code)  /  render_register(rdi=error code)
; 0 renders clean; 1..5 select a message. Both share one body: the only
; difference is which heading and form are emitted, so the entry points load
; that ID pair (heading in bits 0-7, form in bits 8-15) and share the rest.
; clobbers: caller-saved; preserves rbx, r12, r13.
render_login:
        mov     esi, sid_lg_a | sid_lg_b << 8
        jmp     render_auth_page
render_register:
        mov     esi, sid_rg_a | sid_rg_b << 8
render_auth_page:
        push    r12
        push    r13
        mov     r12, rdi                ; error code
        mov     r13d, esi               ; heading / form IDs
        EMIT    @reset, 200, hdr, head
        movzx   edi, r13b
        call    ob_putid                ; heading
        test    r12, r12
        jz      .form
        movzx   edi, byte [r12 + auth_err - 1]
        call    ob_putid                ; error line
.form:
        shr     r13d, 8
        mov     edi, r13d
        pop     r13
        pop     r12
        jmp     ob_putid                ; form

; ---------------------------------------------------------------------------
; render_head_cookie(rdi=cookie name z-string, rsi=value, rdx=value length)
; 200 response that installs the session cookie, plus a short confirmation.
; The value is emitted by length, not assumed NUL-terminated.
; clobbers: caller-saved regs.
render_head_cookie:
        push    r12
        push    r13
        push    r14
        mov     r12, rdi                ; name
        mov     r13, rsi                ; value
        mov     r14, rdx                ; value length
        EMIT    @reset, 200, ck_a, @path, ck_b, @cookie, ck_c, hdr, head, joined
        pop     r14
        pop     r13
        pop     r12
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
        EMIT    @reset, 200, hdr, head, adm_hdr

        ; ---- stats: summary table above the two lists.
        ; One pass per mapping; db_rec is called once per index, never twice.
        ; Counters live in TLS_SCRATCH because there are more of them than
        ; there are free callee-saved registers, and a .bss array would be
        ; shared by 4 threads.
        ;   scratch qword 0..5  slots, committed, holes, deleted, roots, replies
        ;   scratch qword 6..9  invites, unused, redeemed, revoked
        mov     r14, [rbx + TLS_SCRATCH]
        xor     eax, eax
        mov     ecx, 10
        mov     rdi, r14
        rep     stosq                   ; zero all ten counters

        call    db_count
        mov     r12, rax
        mov     [r14], rax              ; slots = the cursor itself
        xor     r13d, r13d
.sp:
        cmp     r13, r12
        jae     .sps_done
        mov     rdi, r13
        call    db_rec
        test    rax, rax
        jz      .sps_done             ; null means past the cursor: stop
        mov     rbp, rax
        cmp     dword [rbp + R_TIME], 0
        jne     .s_committed
        inc     qword [r14 + 16]        ; uncommitted hole
        jmp     .sp_next
.s_committed:
        inc     qword [r14 + 8]
        test    byte [rbp + R_FLAGS], FLAG_DELETED
        jz      .s_not_del
        inc     qword [r14 + 24]
        jmp     .sp_next              ; deleted rows are not counted as live
.s_not_del:
        cmp     dword [rbp + R_PARENT], r13d
        jne     .s_is_reply
        inc     qword [r14 + 32]        ; root
        jmp     .sp_next
.s_is_reply:
        inc     qword [r14 + 40]
.sp_next:
        inc     r13
        jmp     .sp
.sps_done:

        call    inv_count
        mov     r12, rax
        xor     r13d, r13d
.si:
        cmp     r13, r12
        jae     .si_done
        mov     rdi, r13
        call    inv_rec
        test    rax, rax
        jz      .si_done
        mov     rbp, rax
        cmp     dword [rbp + I_TIME], 0
        je      .si_next               ; reserved, no code written yet
        inc     qword [r14 + 48]
        test    byte [rbp + I_FLAGS], INV_FLAG_REVOKED
        jz      .si_live
        inc     qword [r14 + 72]
        jmp     .si_next
.si_live:
        cmp     dword [rbp + I_USED], 0
        jne     .si_used
        inc     qword [r14 + 56]
        jmp     .si_next
.si_used:
        inc     qword [r14 + 64]
.si_next:
        inc     r13
        jmp     .si
.si_done:

        ; The ten labels have consecutive string IDs and the ten counters
        ; are consecutive qwords, so one loop walks both in step.
%if sid_l_end - sid_l_slot != 10
%error "stats labels must have consecutive string IDs"
%endif
        EMIT    st_a
        mov     r12d, sid_l_slot        ; label ID
        mov     r13, r14                ; -> counter
.st_row:
        EMIT    st_r
        mov     edi, r12d
        call    ob_putid
        mov     edi, sid_st_v
        cmp     r12b, sid_l_hole
        jne     .st_v
        cmp     qword [r13], 0
        je      .st_v
        mov     edi, sid_st_warn        ; the one diagnostic number
.st_v:
        call    ob_putid
        mov     rdi, [r13]
        call    ob_putu
        add     r13, 8
        inc     r12d
        cmp     r12b, sid_l_end
        jb      .st_row
        EMIT    st_z, adm_top

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
        EMIT    adm_inv, @idx, adm_td, @code, adm_td
        ; status: revoked > used > unused
        test    byte [rbp + I_FLAGS], INV_FLAG_REVOKED
        jz      .inv_used
        EMIT    st_rev
        jmp     .inv_next
.inv_used:
        mov     r14d, [rbp + I_USED]
        test    r14d, r14d
        jnz     .inv_usedby
        EMIT    st_free
        jmp     .inv_btn
.inv_usedby:
        EMIT    st_used
        lea     rdi, [r14 - 1]          ; field stores 1 + post index
        call    ob_putu
.inv_btn:
        EMIT    adm_rev, @idx, adm_revb
.inv_next:
        inc     r13
        jmp     .inv
.inv_done:
        EMIT    adm_mid         ; </table><h2>$ messages</h2><table>

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
        EMIT    adm_inv, @idx, adm_td
        cmp     dword [rbp + R_TIME], 0
        jne     .post_live
        EMIT    st_unc          ; reserved but never published
        jmp     .post_next
.post_live:
        EMIT    @author, adm_td
        cmp     dword [rbp + R_PARENT], r13d
        je      .post_root
        EMIT    reply_to, @parent, paren
        jmp     .post_inv
.post_root:
        EMIT    @title
.post_inv:
        EMIT    adm_td, inv_col, @inv, adm_td
        test    byte [rbp + R_FLAGS], FLAG_DELETED
        jz      .post_btn
        EMIT    st_del
        jmp     .post_next
.post_btn:
        EMIT    st_ok, adm_del, @idx, adm_delb
.post_next:
        test    r13, r13
        jnz     .post
.done:
        EMIT    adm_end
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        ret
