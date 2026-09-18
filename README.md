# geektaco

asm based forum, simple and clean with 8k.

```
$ make && ./geektaco
Admin key: 5f0c…
geektaco http://0.0.0.0:8090
```

Open `/admin` with the cookie `ga=<key>` to create invites. Invites let people register.

- x86-64 assembly, no libc, 4 threads, mmap storage
- accounts, invites, markdown, admin panel
- no JavaScript, no dependencies

Build: `nasm`, `ld`, `python3`. Test: `./smoke.sh`.

Inspired by [qr-server](https://github.com/Xelckis/qr-server).

License: [Apache-2.0](LICENSE).
