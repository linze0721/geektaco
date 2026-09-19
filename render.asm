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

; HTML entities. Kept out of the compressed table: ob_put_esc emits them
; through ob_put (no expansion), so they must be plain literals.
e_amp:   db '&amp;', 0
e_lt:    db '&lt;', 0
e_gt:    db '&gt;', 0
e_quot:  db '&quot;', 0
e_apos:  db '&#39;', 0

%include "strtab.inc"

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
        ; NASM folds `[sym + (rax-K)*2]` into a bogus (rax,rax) form and drops
        ; the symbol, so compute the index explicitly.
        sub     eax, TOK_LO
        mov     edx, str_dict_off
        movzx   eax, word [rdx + rax*2]
        mov     edi, str_dict
        add     rdi, rax
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
; emit_200() -- reset the buffer and emit the 200 status line, the standard
; headers, and the document head. Four page builders opened identically.
; rbx must already hold the TLS base. clobbers: caller-saved regs.
emit_200:
        mov     qword [rbx + TLS_OBLEN], 0
        mov     edi, s_200
        call    ob_puts
        mov     edi, s_hdr
        call    ob_puts
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
; ob_putdate(edi=unix epoch seconds) -- "1999-12-31 23:59 UTC".
; A raw epoch integer is an unfinished-looking detail on a message board, and
; a board of this era always showed a readable date.
;
; Uses Howard Hinnant's civil_from_days: shift the epoch to an era beginning
; on 0000-03-01 so leap days land at the end of the cycle, then invert the
; 146097-day/400-year and 1461-day/4-year cycles with integer arithmetic only.
; No libc, no tables, no division by a non-constant.
; clobbers: caller-saved regs; preserves rbx, r12-r14.
ob_putdate:
        push    rbx
        push    rbp
        push    r12
        push    r13
        push    r14
        mov     r14d, edi               ; epoch seconds (unsigned 32-bit)

        mov     eax, r14d
        xor     edx, edx
        mov     ecx, 86400
        div     ecx                     ; eax = days, edx = second of day
        mov     r13d, edx               ; keep the time of day
        mov     r12d, eax               ; days since 1970-01-01

        ; --- civil_from_days ---------------------------------------------
        add     r12d, 719468            ; shift epoch to 0000-03-01
        mov     eax, r12d
        xor     edx, edx
        mov     ecx, 146097
        div     ecx                     ; eax = era, edx = day of era
        mov     r8d, eax                ; era
        mov     r9d, edx                ; doe

        ; yoe = (doe - doe/1460 + doe/36524 - doe/146096) / 365
        mov     eax, r9d
        xor     edx, edx
        mov     ecx, 1460
        div     ecx
        mov     r10d, r9d
        sub     r10d, eax
        mov     eax, r9d
        xor     edx, edx
        mov     ecx, 36524
        div     ecx
        add     r10d, eax
        mov     eax, r9d
        xor     edx, edx
        mov     ecx, 146096
        div     ecx
        sub     r10d, eax
        mov     eax, r10d
        xor     edx, edx
        mov     ecx, 365
        div     ecx
        mov     r10d, eax               ; yoe

        ; doy = doe - (365*yoe + yoe/4 - yoe/100)
        imul    eax, r10d, 365
        mov     r11d, eax
        mov     eax, r10d
        shr     eax, 2
        add     r11d, eax
        mov     eax, r10d
        xor     edx, edx
        mov     ecx, 100
        div     ecx
        sub     r11d, eax
        mov     ecx, r9d
        sub     ecx, r11d               ; ecx = doy

        ; mp = (5*doy + 2)/153 ; d = doy - (153*mp+2)/5 + 1
        imul    eax, ecx, 5
        add     eax, 2
        xor     edx, edx
        mov     r11d, 153
        div     r11d
        mov     r11d, eax               ; mp
        imul    eax, r11d, 153
        add     eax, 2
        xor     edx, edx
        mov     esi, 5
        div     esi
        sub     ecx, eax
        inc     ecx
        mov     ebx, ecx                ; day -> rbx: ob_putu/ob_putc clobber
                                        ; ecx, and the day is emitted last.

        ; m = mp < 10 ? mp+3 : mp-9 ; y = yoe + era*400 + (m <= 2)
        mov     eax, r11d
        cmp     r11d, 10
        jb      .m_early
        sub     eax, 9
        jmp     .m_done
.m_early:
        add     eax, 3
.m_done:
        mov     r11d, eax               ; month
        imul    eax, r8d, 400
        add     eax, r10d
        cmp     r11d, 2
        ja      .y_done
        inc     eax                     ; Jan/Feb belong to the next year
.y_done:
        mov     r12d, eax               ; year  -> callee-saved
        mov     r14d, r11d              ; month -> callee-saved

        ; --- emit "YYYY-MM-DD HH:MM UTC" ---------------------------------
        ; Every field lives in a callee-saved register: the emit helpers are
        ; free to clobber the caller-saved set between fields.
        ; Split the time of day before emitting so all five fields are live
        ; in callee-saved registers and one loop can walk them.
        mov     eax, r13d
        xor     edx, edx
        mov     ecx, 3600
        div     ecx
        mov     r13d, eax               ; hour
        mov     eax, edx
        xor     edx, edx
        mov     ecx, 60
        div     ecx
        mov     ebp, eax                ; minute
        ; Emit year, then four padded fields each preceded by its separator.
        mov     edi, r12d
        call    ob_putu
        mov     r12d, s_dsep            ; "-- :"
.dt_emit:
        movzx   edi, byte [r12]
        call    ob_putc
        mov     edi, r14d               ; month
        mov     r14d, ebx               ; rotate: month<-day<-hour<-minute
        mov     ebx, r13d
        mov     r13d, ebp
        call    .pad2
        inc     r12
        cmp     byte [r12], 0
        jne     .dt_emit
        mov     edi, s_utc
        call    ob_puts
        pop     r14
        pop     r13
        pop     r12
        pop     rbp
        pop     rbx
        ret

; .pad2(edi=value 0..99) -- two digits, zero padded.
.pad2:
        cmp     edi, 10
        jae     .p2_wide
        push    rdi
        mov     dil, '0'
        call    ob_putc
        pop     rdi
.p2_wide:
        jmp     ob_putu

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
        mov     edi, s_md_cd
        call    ob_puts
        lea     rdi, [rbx + rbp]
        mov     rsi, r14
        sub     rsi, rbp
        call    ob_put_esc              ; no inline processing inside code
        mov     edi, s_md_cde
        call    ob_puts
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
        mov     edi, s_md_st
        call    ob_puts
        lea     rdi, [rbx + rbp]
        mov     rsi, r14
        sub     rsi, rbp
        call    md_inline               ; nested inline inside strong
        mov     edi, s_md_ste
        call    ob_puts
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
        mov     edi, s_md_em
        call    ob_puts
        lea     rdi, [rbx + rbp]
        mov     rsi, r14
        sub     rsi, rbp
        call    md_inline
        mov     edi, s_md_eme
        call    ob_puts
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
        ; rdx (the ')' index) and r8 (url start) are caller-saved and every
        ; emit below clobbers them, so park the resume position in a
        ; callee-saved register before emitting anything.
        push    r12
        lea     r12, [rdx + 1]          ; resume just past ')'
        push    r8
        push    rdx
        mov     edi, s_md_a1
        call    ob_puts
        pop     rdx
        pop     r8
        lea     rdi, [rbx + r8]
        mov     rsi, rdx
        sub     rsi, r8
        call    ob_put_esc              ; url escaped too: quotes cannot break out
        mov     edi, s_md_a2
        call    ob_puts
        lea     rdi, [rbx + rbp]
        mov     rsi, r14
        sub     rsi, rbp
        call    ob_put_esc              ; link text: escaped, no nested markup
        mov     edi, s_md_a3
        call    ob_puts
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
        mov     edi, s_md_pre
        call    ob_puts
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
        mov     edi, s_md_pree
        call    ob_puts
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
        mov     edi, s_md_bq
        call    ob_puts
        lea     rdi, [rbx + r13 + 2]
        lea     rsi, [rcx - 2]
        call    md_inline
        mov     edi, s_md_bqe
        call    ob_puts
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
        mov     edi, s_md_pe            ; a list ends any open paragraph
        call    ob_puts
        xor     r15d, r15d
.item_nop:
        test    r14, r14
        jnz     .item_body
        mov     edi, s_md_ul
        call    ob_puts
        mov     r14d, 1
.item_body:
        mov     edi, s_md_li
        call    ob_puts
        lea     rdi, [rbx + r13 + 2]
        lea     rsi, [rcx - 2]
        call    md_inline
        mov     edi, s_md_lie
        call    ob_puts
        lea     r13, [rbp + 1]
        jmp     .line
.para:
        ; ---- paragraph text. A hard newline inside a paragraph is preserved
        ; as a newline; the stylesheet's pre-wrap keeps it visible, so old
        ; multi-line posts do not collapse onto one line.
        test    r14, r14
        jz      .para_nolist
        mov     edi, s_md_ule
        call    ob_puts
        xor     r14d, r14d
.para_nolist:
        test    r15, r15
        jnz     .para_cont
        mov     edi, s_md_p
        call    ob_puts
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
        mov     edi, s_md_pe
        call    ob_puts
        xor     r15d, r15d
.co_list:
        test    r14, r14
        jz      .co_done
        mov     edi, s_md_ule
        call    ob_puts
        xor     r14d, r14d
.co_done:
        ret

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
        call    ob_putdate
        mov     edi, s_post_c         ; </div><pre>
        call    ob_puts
        lea     rdi, [rbx + R_BODY]
        mov     esi, BODY_MAX
        call    ob_put_md
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
        call    emit_200
        mov     edi, s_idx_top
        call    ob_puts
        call    db_count
        mov     r12, rax                ; snapshot of the allocation cursor
        test    r12, r12
        jz      .empty
        mov     edi, s_ul_a             ; <ul> wraps rows only, never the
        call    ob_puts                 ; empty-state paragraph
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
        jmp     .listend
.next:
        test    r13, r13
        jnz     .outer                  ; stop after index 0 was processed
        jmp     .listend
.empty:
        mov     edi, s_empty
        call    ob_puts
        jmp     .form
.listend:
        mov     edi, s_ul_b             ; </ul>
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
        call    emit_200
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
        call    emit_200
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
        ; The ten labels are consecutive NUL-terminated strings and the ten
        ; counters are consecutive qwords, so one loop walks both in step.
        ; Unrolled this was ten 13-byte blocks.
        mov     r12d, s_l_live          ; -> next label
        lea     r13, [r14 + 8]          ; -> next counter
.stat_row:
        mov     rsi, [r13]
        mov     edi, r12d
        cmp     r12d, s_l_hole
        jne     .stat_plain
        test    rsi, rsi
        jz      .stat_plain
        call    .row_warn               ; the one diagnostic number
        jmp     .stat_next
.stat_plain:
        call    .row
.stat_next:
        add     r13, 8
.stat_skip:                             ; advance past this label's NUL
        cmp     byte [r12], 0
        lea     r12, [r12 + 1]
        jne     .stat_skip
        cmp     r12d, s_l_end
        jb      .stat_row
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
        call    emit_200
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
