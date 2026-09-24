%include "common.inc"
default rel

global db_init, db_hdr, db_base, db_count, db_rec, db_reserve, db_commit, db_sync
global inv_hdr, inv_base, inv_count, inv_rec, inv_reserve, inv_commit, now_secs
global map_file, record_ptr, record_reserve, record_commit

section .rodata
db_path:  db "geektaco.db", 0
inv_path: db "geektaco.inv", 0

section .bss
alignb 8
db_hdr:
db_base: resq 1
inv_hdr:
inv_base: resq 1
; This is the one safe piece of global scratch: every thread writes the same
; value and reads only tv_sec, so the race is benign. Intentionally not TLS.
; Both mapping pointers and this 16-byte timespec are 8-byte aligned.
db_timespec: resq 2
; Commit counter for the periodic flush. Bumped with `lock xadd` because all
; four workers commit concurrently; a plain inc would miss boundaries.
sync_ctr: resd 1

section .text

; Startup only, before workers. Returns 0 or -1; publishes bases on success.
db_init:
    push rbx
    mov edi, db_path
    mov rsi, DB_MAGIC
    mov edx, DB_BYTES
    call map_file
    cmp rax, -1
    je .done
    mov rbx, rax
    mov edx, MAX_POSTS
    call clamp_header
    mov edi, inv_path
    mov rsi, INV_MAGIC
    mov edx, INV_BYTES
    call map_file
    cmp rax, -1
    je .unmap_posts
    mov edx, MAX_INVITES
    call clamp_header
    mov [inv_base], rax
    mov [db_base], rbx
    xor eax, eax
.done:
    pop rbx
    ret
.unmap_posts:
    mov rdi, rbx
    mov esi, DB_BYTES
    push SYS_munmap
    pop rax
    syscall
    push -1
    pop rax
    jmp .done

; rax=mapping, edx=capacity. Initialization is exclusive, not a worker write.
clamp_header:
    cmp [rax + H_COUNT], edx
    jbe .done
    mov [rax + H_COUNT], edx
.done:
    ret

; rdi=path, rsi=magic, rdx=total bytes -> rax=mapping or -1.
; Both files are fixed-size sparse mappings; record pointers never move.
map_file:
    push rbx
    push r12
    push r13
    mov r12, rsi
    mov r13, rdx
    push SYS_open
    pop rax
    push O_RDWR | O_CREAT
    pop rsi
    mov edx, DB_MODE
    syscall
    test eax, eax
    js .fail
    mov ebx, eax
    mov edi, eax
    mov rsi, r13
    push SYS_ftruncate
    pop rax
    syscall
    test eax, eax
    js .close_fail
    xor edi, edi
    mov rsi, r13
    push PROT_READ | PROT_WRITE
    pop rdx
    push MAP_SHARED             ; syscall argument 4, NOT rcx
    pop r10
    mov r8d, ebx
    xor r9d, r9d
    push SYS_mmap
    pop rax
    syscall
    mov r8, rax                     ; keep the full-width runtime pointer
    mov edi, ebx
    push SYS_close
    pop rax
    syscall                         ; the mapping owns the file now
    cmp r8, -4095                   ; only unsigned -4095..-1 are errors
    jae .fail
    mov rax, [r8 + H_MAGIC]
    test rax, rax
    jz .fresh
    cmp rax, r12
    jne .foreign
    jmp .mapped                     ; valid magic: preserve the cursor
.fresh:
    mov [r8 + H_MAGIC], r12
    mov dword [r8 + H_VERSION], DB_VERSION
    mov dword [r8 + H_COUNT], 0
.mapped:
    mov rax, r8
.done:
    pop r13
    pop r12
    pop rbx
    ret
.foreign:
    mov rdi, r8
    mov rsi, r13
    push SYS_munmap
    pop rax
    syscall
    jmp .fail
.close_fail:
    mov edi, ebx
    push SYS_close
    pop rax
    syscall
.fail:
    push -1
    pop rax
    jmp .done

; Count is the allocation cursor, including holes, clamped to the mapping.
db_count:
    mov rsi, [db_base]
    mov edx, MAX_POSTS
    jmp record_count
inv_count:
    mov rsi, [inv_base]
    mov edx, MAX_INVITES
record_count:
    mov eax, [rsi + H_COUNT]
    cmp eax, edx
    cmova eax, edx
    ret

; rdi=index -> mapped record or 0, including reserved/uncommitted records.
; Public readers must skip zero timestamps themselves; writers need holes.
db_rec:
    mov rsi, [db_base]
    mov edx, MAX_POSTS
    push REC_SHIFT
    pop rcx
    jmp record_ptr
inv_rec:
    mov rsi, [inv_base]
    mov edx, MAX_INVITES
    push INV_SHIFT
    pop rcx
record_ptr:
    ; Check capacity as well as cursor: failed reservations still advance it.
    cmp rdi, rdx
    jae .none
    mov eax, [rsi + H_COUNT]
    cmp rdi, rax
    jae .none
    lea rax, [rdi + 1]
    shl rax, cl
    add rax, rsi
    ret
.none:
    xor eax, eax
    ret

; One atomic gives each writer an exclusive index. A full file returns -1.
db_reserve:
    mov rsi, [db_base]
    mov edx, MAX_POSTS
    jmp record_reserve
inv_reserve:
    mov rsi, [inv_base]
    mov edx, MAX_INVITES
record_reserve:
    push 1
    pop rax
    lock xadd [rsi + H_COUNT], eax
    cmp eax, edx
    jae storage_fail
    ret
storage_fail:
    push -1
    pop rax
    ret

; rdi=index -> 0, or -1 for an invalid index. The body must already be filled.
db_commit:
    push rdx                        ; align the stack for both calls
    call db_rec
    push R_TIME
    pop rdx
    jmp record_commit
inv_commit:
    push rdx
    call inv_rec
    push I_TIME
    pop rdx
record_commit:
    test rax, rax
    jz .invalid
    lea r8, [rax + rdx]              ; now_secs preserves r8
    call now_secs
    test rax, rax
    jle .fallback                    ; a failed clock must not hide the body
    test eax, eax
    jnz .publish                     ; the stored 32-bit marker must be nonzero
.fallback:
    push 1
    pop rax
.publish:
    ; x86-64 TSO does not reorder stores with stores, so this plain mov is
    ; correctly ordered against preceding body writes. R_TIME (or I_TIME)
    ; must be the textually last store to the record: this publishes it.
    mov [r8], eax
    pop rdx
    ; Bound how much a power cut can lose. MAP_SHARED pages already survive
    ; process death, so this is only about the machine losing power.
    ; The counter must be atomic: four workers commit concurrently, and a
    ; plain inc would let two threads both see the boundary, or neither.
    push 1
    pop rax
    lock xadd [sync_ctr], eax       ; returns the PRE-increment value
    inc eax                         ; so test the count, not the old index:
    and eax, SYNC_EVERY - 1         ; otherwise commit #1 flushes a clean map
    jnz .done
    ; MS_ASYNC, not MS_SYNC: MS_SYNC blocks this worker until writeback
    ; finishes, stalling a quarter of the server on every 32nd post.
    ; Full range: the file is sparse, so the kernel walks its own dirty list
    ; and passing DB_BYTES avoids error-prone page-alignment arithmetic.
    mov rdi, [db_base]
    mov esi, DB_BYTES
    push MS_ASYNC
    pop rdx
    push SYS_msync
    pop rax
    syscall                         ; return ignored: the record is already
                                    ; published and visible; a failed flush
                                    ; must not fail the commit.
.done:
    xor eax, eax
    ret
.invalid:
    pop rdx
    jmp storage_fail

; Explicit durability for posts only; invites have an independent lifecycle.
db_sync:
    mov rdi, [db_base]
    mov esi, DB_BYTES
    push MS_SYNC
    pop rdx
    push SYS_msync
    pop rax
    syscall
    test eax, eax
    js storage_fail
    ret

; Epoch seconds or -1. Clobbers rax, rcx, rsi, rdi, r11; preserves r8.
now_secs:
    mov eax, SYS_clock_gettime
    xor edi, edi                    ; CLOCK_REALTIME
    mov esi, db_timespec
    syscall
    test eax, eax
    js storage_fail
    mov rax, [db_timespec]
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
