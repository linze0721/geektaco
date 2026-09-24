; NASM flat binary immediately after the ELF header and single program header.
; Standard forward ZX0 v2 stream, inverted offset MSB, maximum offset 32640.
%ifndef IMG_ADDR
    %error IMG_ADDR must be supplied by mkpack.py
%endif

bits 64
org PACK_BASE + 120

_start:
    mov eax, 9                      ; mmap linked image and zero-initialized BSS
    mov edi, (IMG_ADDR & -4096)
    mov esi, IMG_MEMSZ + (IMG_ADDR & 4095)
    mov edx, 7                      ; PROT_READ | PROT_WRITE | PROT_EXEC
    mov r10d, 0x32                  ; MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS
    mov r8d, -1
    xor r9d, r9d
    syscall
    test rax, rax
    js .fail
    mov r10, rsp                    ; restore this exact kernel entry stack
    cld
    lea rsi, [rel payload]
    mov edi, IMG_ADDR
    mov ebx, 1                      ; last offset, in bytes
    xor r12d, r12d                  ; bit to backtrack from the last byte?
    xor r13d, r13d                  ; current bit mask

.literals:
    xor ebp, ebp                    ; non-inverted interlaced Elias gamma
    call gamma
    mov ecx, eax
    rep movsb                       ; bytes follow interleaved control bits
    call bit
    test eax, eax
    jnz .new_offset
.last_offset:
    xor ebp, ebp
    call gamma
    mov ecx, eax
    call copy
    call bit
    test eax, eax
    jz .literals
.new_offset:
    mov ebp, 1                      ; offset high bits are inverted in ZX0 v2
    call gamma
    cmp eax, 256                    ; ZX0 end marker
    je .unfilter
    shl eax, 7
    mov ebx, eax
    movzx eax, byte [rsi]
    inc rsi
    mov r15d, eax                   ; next control bit is its bit 0
    shr eax, 1
    sub ebx, eax
    mov r12d, 1
    xor ebp, ebp
    call gamma
    lea ecx, [rax + 1]
    call copy
    call bit
    test eax, eax
    jz .literals
    jmp .new_offset

.unfilter:
    cmp rdi, IMG_ADDR + IMG_SIZE
    jne .fail                       ; reject an incomplete or overlong stream
    mov edi, IMG_ADDR
.scan:
    cmp rdi, IMG_ADDR + IMG_SIZE - 5
    ja .handoff
    cmp byte [rdi], 0xe8
    je .relative
    cmp byte [rdi], 0xe9
    jne .not_branch
.relative:
    mov eax, [rdi + 1]
    lea ecx, [rdi + 5 - IMG_ADDR]
    sub eax, ecx
    mov [rdi + 1], eax
    add rdi, 5
    jmp .scan
.not_branch:
    inc rdi
    jmp .scan
.handoff:
    mov rsp, r10
    jmp IMG_ENTRY                   ; _start takes ownership of every register
.fail:
    mov eax, 60                     ; exit(127) if destination mmap failed
    mov edi, 127
    syscall

; Append ECX bytes from the previously decoded output. The source may
; overlap the destination; REP MOVSB walks in the same direction as ZX0.
copy:
    push rsi
    mov rsi, rdi
    sub rsi, rbx
    rep movsb
    pop rsi
    ret

; EAX = next bit. ZX0 places the first bit of each new-offset length in
; the low bit of the offset byte, before resuming the ordinary bit stream.
bit:
    test r12d, r12d
    jz .ordinary
    xor r12d, r12d
    mov eax, r15d
    and eax, 1
    ret
.ordinary:
    shr r13b, 1
    jnz .test
    mov r13b, 128
    movzx r14d, byte [rsi]
    mov r15d, r14d
    inc rsi
.test:
    xor eax, eax
    test r14b, r13b
    setnz al
    ret

; EBP = invert (0 for lengths, 1 for ZX0 v2 offset MSB), EAX = value.
gamma:
    mov edx, 1
.next:
    call bit
    test eax, eax
    jnz .done
    call bit
    xor eax, ebp
    shl edx, 1
    or edx, eax
    jmp .next
.done:
    mov eax, edx
    ret

payload:
