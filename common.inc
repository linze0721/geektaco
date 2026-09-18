; ============================================================================
; geektaco -- shared constants and layout contract
; x86_64 Linux, NASM syntax, freestanding (no libc)
;
; v2: multithreaded, mmap-backed persistence, invite + admin system.
; ============================================================================
%ifndef GEEKTACO_COMMON_INC
%define GEEKTACO_COMMON_INC

; ---- threading ------------------------------------------------------------
; Four worker threads each block in accept() on the shared listening socket.
; Linux wakes exactly one waiter per connection, so no dispatch queue and no
; thundering herd. Threads never touch each other's buffers: every mutable
; per-request buffer is reached through %fs (see TLS block below).
THREADS         equ 4
STACK_SIZE      equ 65536       ; per-thread stack, mmap'd

; clone(2) flags for a thread sharing VM/fds/signals.
; CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM. Deliberately NOT CLONE_SETTLS:
; the child installs its own %fs with arch_prctl after mmap'ing its buffers,
; because it cannot know the block address until that mmap returns.
CLONE_FLAGS     equ 0x00050F00

; ---- per-thread block, addressed via %fs ----------------------------------
; [fs:0] MUST hold the block's own address (TCB self-pointer convention) so a
; thread can materialise its base with `mov rbx, [fs:TLS_SELF]`.
;
; Everything a request mutates lives here. Under 4 threads a shared .bss
; buffer is not a race to be papered over later -- it is immediate cross-user
; data corruption, where one reader serves another's half-written page.
TLS_SELF        equ 0           ; dq  -> this block
TLS_OBUF        equ 8           ; dq  -> this thread's output buffer
TLS_OBLEN       equ 16          ; dq  bytes currently in that buffer
TLS_REQ         equ 24          ; dq  -> this thread's request buffer
TLS_REC         equ 32          ; dq  -> this thread's 512-byte record scratch
TLS_SCRATCH     equ 40          ; dq  -> 256-byte general scratch

; Parsed request metadata: http_parse writes these, routing reads them.
; Formerly the globals req_method/req_path/... which cannot survive threading.
TLS_METHOD      equ 48          ; dq  M_GET / M_POST / M_OTHER
TLS_PATH        equ 56          ; dq  -> into the request buffer
TLS_PATHLEN     equ 64          ; dq
TLS_BODY        equ 72          ; dq  -> first body byte, or 0
TLS_BODYLEN     equ 80          ; dq  bytes of body actually present
TLS_CLEN        equ 88          ; dq  declared Content-Length

; Session state for the current request, resolved once per connection.
TLS_INVITE      equ 96          ; dq  invite slot from the cookie, or -1
TLS_ADMIN       equ 104         ; dq  1 if the admin cookie checked out

; Pagination state for the page being rendered. These need their own slots:
; TLS_SCRATCH is reused by cookie extraction, form fields and redirect
; construction, so a page builder cannot keep anything there across a call.
TLS_PAGE        equ 112         ; dq  requested page number
TLS_MORE        equ 120         ; dq  1 when a further page exists
TLS_SIZE        equ 128

SCRATCH_SIZE    equ 256

; ---- post record (512 bytes; index -> offset is shl 9) --------------------
; R_TIME is the COMMIT MARKER. A slot is reserved by an atomic bump of the
; header cursor, filled in, and only then given a nonzero R_TIME. Any record
; with R_TIME == 0 is a reserved-but-uncommitted hole and MUST be skipped by
; every reader. This is what makes crash recovery and lock-free reads work.
REC_SIZE        equ 512
REC_SHIFT       equ 9

R_PARENT        equ 0           ; dd  root index if == own index, else root
R_TIME          equ 4           ; dd  unix epoch seconds; 0 => not committed
R_FLAGS         equ 8           ; dd  bit0 = deleted
R_INVITE        equ 12          ; dd  invite slot that authored this (audit)
R_NREPLY        equ 16          ; dd  replies to this root; `lock inc`d by the
                                ;     replier so the index page never rescans.
                                ;     Meaningful on roots only.
R_AUTHOR        equ 20          ; 24 bytes, NUL padded
R_TITLE         equ 44          ; 80 bytes, NUL padded
R_BODY          equ 124         ; 388 bytes, NUL padded

AUTHOR_MAX      equ 24
TITLE_MAX       equ 80
BODY_MAX        equ 388

FLAG_DELETED    equ 1

MAX_POSTS       equ 65536

; ---- invite record (32 bytes) ---------------------------------------------
; Lifecycle: unused -> consumed (holder is a member) -> revoked (banned).
; The code doubles as the member token, so there is no session table.
INV_SIZE        equ 32
INV_SHIFT       equ 5

I_CODE          equ 0           ; 16 bytes ascii hex, NUL padded
I_USED          equ 16          ; dd  0 = unused, else 1 + first post index
I_TIME          equ 20          ; dd  creation time; 0 => not committed
I_FLAGS         equ 24          ; dd  bit0 = revoked
I_PAD           equ 28          ; dd

INV_FLAG_REVOKED equ 1
CODE_LEN        equ 16          ; hex chars in an invite code
MAX_INVITES     equ 4096

; ---- file headers ---------------------------------------------------------
; Slot 0 of each file is a header, so payload record i lives at (i+1)*size.
; The cursor is bumped with `lock xadd`, which is why it lives in the mapped
; file rather than in .bss: allocation and persistence share one word.
H_MAGIC         equ 0           ; dq
H_VERSION       equ 8           ; dd
H_COUNT         equ 12          ; dd  allocation cursor
DB_MAGIC        equ 0x3149424B54454547   ; "GEEKTKB1"
INV_MAGIC       equ 0x31564E49544547     ; "GETINV1"
DB_VERSION      equ 1

DB_BYTES        equ (MAX_POSTS + 1) * REC_SIZE
INV_BYTES       equ (MAX_INVITES + 1) * INV_SIZE

; ---- admin ----------------------------------------------------------------
KEY_LEN         equ 32          ; hex chars in the admin key
KEY_RAW         equ 16          ; random bytes behind it

; ---- buffers --------------------------------------------------------------
OBUF_SIZE       equ 262144
REQ_SIZE        equ 16384

; ---- request method codes -------------------------------------------------
M_GET           equ 0
M_POST          equ 1
M_OTHER         equ 2

; ---- pagination -----------------------------------------------------------
; Threads per index page and replies per thread page. The index walks newest
; first, so page 0 is always the cheapest request -- it stops after PAGE_SIZE_N
; matches instead of scanning to record 0.
PAGE_SIZE_N     equ 25

; ---- durability -----------------------------------------------------------
; MS_ASYNC queues writeback without blocking the worker; the kernel already
; guarantees the mapping is coherent for readers, so this only bounds how long
; a power cut can lose. Every SYNC_EVERY commits one worker issues an async
; flush, so the loss window is bounded by writes, not by time.
SYNC_EVERY      equ 32
MS_ASYNC        equ 1

; ---- net ------------------------------------------------------------------
PORT_BE         equ 0x901F      ; htons(8080)
AF_INET         equ 2
SOCK_STREAM     equ 1
SOL_SOCKET      equ 1
SO_REUSEADDR    equ 2
BACKLOG         equ 128

; ---- mmap / open ----------------------------------------------------------
PROT_READ       equ 1
PROT_WRITE      equ 2
MAP_SHARED      equ 1
MAP_PRIVATE     equ 2
MAP_ANONYMOUS   equ 0x20
MS_SYNC         equ 4
PAGE_SIZE       equ 4096

O_RDONLY        equ 0x0000
O_WRONLY        equ 0x0001
O_RDWR          equ 0x0002
O_CREAT         equ 0x0040
O_EXCL          equ 0x0080
O_TRUNC         equ 0x0200
DB_MODE         equ 0o644
KEY_MODE        equ 0o600

; ---- syscalls -------------------------------------------------------------
SYS_read        equ 0
SYS_write       equ 1
SYS_open        equ 2
SYS_close       equ 3
SYS_fstat       equ 5
SYS_mmap        equ 9
SYS_munmap      equ 11
SYS_msync       equ 26
SYS_socket      equ 41
SYS_accept      equ 43
SYS_shutdown    equ 48
SYS_bind        equ 49
SYS_listen      equ 50
SYS_setsockopt  equ 54
SYS_clone       equ 56
SYS_exit        equ 60          ; per-thread exit; NEVER exit_group in a worker
SYS_ftruncate   equ 77
SYS_rt_sigaction equ 13
SYS_arch_prctl  equ 158
SYS_futex       equ 202
SYS_clock_gettime equ 228
SYS_exit_group  equ 231
SYS_getrandom   equ 318

ARCH_SET_FS     equ 0x1002
CLOCK_REALTIME  equ 0

%endif
