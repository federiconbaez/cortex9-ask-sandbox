# ask-sandbox

[![CI](https://github.com/federiconbaez/cortex9-ask-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/federiconbaez/cortex9-ask-sandbox/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

Supervisor `seccomp_unotify` en Rust: decide por syscall, abre el archivo él mismo (`openat2` + `RESOLVE_BENEATH`) e inyecta el fd con `SECCOMP_IOCTL_NOTIF_ADDFD`. Nunca usa `SECCOMP_USER_NOTIF_FLAG_CONTINUE` para políticas sobre punteros — así cierra el TOCTOU documentado en el man page.

Rust `seccomp_unotify` supervisor that decides per syscall, opens the file itself (`openat2` + `RESOLVE_BENEATH`) and injects the fd with `SECCOMP_IOCTL_NOTIF_ADDFD`. It never answers with `SECCOMP_USER_NOTIF_FLAG_CONTINUE` for pointer-argument policy — closing the TOCTOU race documented in the man page.

> **ES** primero · **EN** below

---

## ES

### Qué problema resuelve

Los sandboxes de agentes suelen fijar las reglas de filesystem al lanzar el proceso. Si a mitad de una tarea el agente necesita un path fuera del allowlist, falla o hay que relanzarlo con permisos más anchos.

`ask-sandbox` deja que una política (estática, de sesión, o un hook `--ask`) conceda **exactamente una operación** mientras el target está bloqueado en el syscall. El supervisor:

1. copia el path **una sola vez** con `process_vm_readv`;
2. lo resuelve bajo un root pineado con `openat2(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS)`;
3. consulta la política;
4. inyecta el fd con `SECCOMP_ADDFD_FLAG_SEND` (atómico).

El kernel **no** vuelve a leer el puntero del target, así que un hilo hermano que mute el buffer no puede cambiar lo que se abrió.

### Qué no es

El man page de [`seccomp_unotify(2)`](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) dice con claridad que el mecanismo **no** está pensado como política de seguridad genérica, y que `CONTINUE` es inherentemente race-prone. Este crate toma esa advertencia en serio: emula opens en vez de continuarlos. No reemplaza Landlock, namespaces ni un kernel en userspace (gVisor).

### Arte previo (leído)

| Proyecto | Qué hace | Hueco que deja |
|---|---|---|
| [anthropics/sandbox-runtime](https://github.com/anthropics/sandbox-runtime) | bubblewrap / Seatbelt + proxies de red; tiene ask callback y `--control-fd` para **red**. Su README (sección `--control-fd`) dice explícitamente que las reglas de filesystem ya están en el perfil/argv al envolver y **no cambian** con updates. | FS fijo al wrap. |
| Codex linux-sandbox, nsjail, bubblewrap, gVisor | Política estática o reimplementación del kernel. | Sin “ask” por operación de FS anti-TOCTOU. |

### Requisitos

- Linux x86_64, kernel ≥ 5.14 (ADDFD+SEND). Probado en 6.12.
- `PR_SET_NO_NEW_PRIVS` + `SECCOMP_FILTER_FLAG_NEW_LISTENER` funcionan **sin root** (verificado con `--self-check` en esta máquina).
- Rust 1.82+.

### Uso

```sh
# Allowlist estática (más libs del dynamic linker por defecto)
cargo run --release --bin ask-sandbox -- \
  --allow /tmp/ws:rw -- /bin/cat /tmp/ws/a.txt

# Hook: un programa que lee un JSON por stdin y responde
# allow-once | allow-session | deny
cargo run --release --bin ask-sandbox -- \
  --allow /tmp/ws:rw --ask /path/to/decider.sh -- /bin/sh -c '...'

# Preguntar en la TTY
cargo run --release --bin ask-sandbox -- \
  --allow /tmp/ws:rw --ask-tty -- /bin/sh -c 'echo hi > /tmp/out.txt'
```

`--no-system-libs` saca `/usr`, `/lib`, `/lib64`, `/etc` del allowlist de lectura (sin eso, un binario dinámico no puede cargar `.so`).

```sh
ask-sandbox --corpus          # las 30 syscalls clasificadas
ask-sandbox --self-check      # instala el filtro sin privilegios
```

### Corpus de 30 syscalls

| Clase | Significado |
|---|---|
| `emulate` | `USER_NOTIF`; el supervisor copia args y actúa (opens con ADDFD; mkdir/unlink/rename hoy responden `EPERM` — sin CONTINUE). |
| `deny` | `EPERM` en el filtro cBPF. |
| `null-path-only` | Permitido solo si el puntero de path es NULL (valor de registro, no mutable por otro hilo). |
| `unmediated` | Path-taking que hoy se deja pasar (execve, stat*, …); el README lo declara, no lo esconde. |

### Mediciones (corridas en esta sesión, release)

```text
# TOCTOU — 1000 intentos, hilo hermano mutando el path buffer
$ cargo run --release --bin ask-sandbox-harness -- -n=1000
mode=secure           escapes=0   opens_ok=502 opens_err=498

$ cargo run --release --bin ask-sandbox-harness -- -n=1000 --continue-control
mode=continue-control escapes=246 # control negativo: el harness detecta fugas

# Latencia openat mediado vs directo (n=5000)
$ cargo run --release --bin ask-sandbox-bench
direct:   p50=0.52µs p99=0.67µs
mediated: p50=11.11µs p99=17.78µs  # meta <50µs → cumplida

# Tareas sin relanzar (n=20): leer en workspace + escribir fuera
$ cargo run --release --bin ask-sandbox-tasks -- --static -n=20
mode=static completed_without_relaunch=0/20 pct=0.0

$ cargo run --release --bin ask-sandbox-tasks -- --ask -n=20
mode=ask    completed_without_relaunch=20/20 pct=100.0
```

Los números exactos varían con la carga; los comandos de arriba los reproducen.

### Qué está probado / qué no

| Probado | No / limitado |
|---|---|
| 0 escapes en el harness TOCTOU multihilo (N=1000) | Mediar `connect` / red |
| p99 openat mediado < 50µs (medido ~18µs) | Emulación completa de mkdir/unlink/rename (hoy `EPERM`) |
| 100% tareas sin relanzar vs 0% estático (n=20) | Paths relativos / `dirfd` del target (se rechazan) |
| Filtro unprivileged con `no_new_privs` | macOS / otras arches |
| ADDFD + `openat2(RESOLVE_BENEATH)` | Landlock / namespaces encima |
| Control negativo CONTINUE observa escapes | Oráculo CONTINUE genérico (eso es el #41 del teammate) |

### Tests

```sh
cargo test --release
# unitarios del crate + 6 integration que ejercitan seccomp de verdad
# (fallan visible si el kernel no soporta USER_NOTIF)
```

### Licencia

Apache-2.0.

---

## EN

### Problem

Agent sandboxes usually freeze filesystem policy at process start. If a task mid-flight needs a path outside the allowlist, it fails or must be relaunched with a wider profile.

`ask-sandbox` lets a policy (static rules, session grants, or an `--ask` hook) grant **exactly one operation** while the target is blocked in the syscall. The supervisor copies the path once, opens it under a pinned root with `openat2(RESOLVE_BENEATH)`, and injects the fd with `SECCOMP_ADDFD_FLAG_SEND`. The kernel never re-reads the target's pointer.

### Not a generic security policy

[`seccomp_unotify(2)`](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) states the mechanism is not intended as a security-policy tool and that `CONTINUE` is race-prone. This crate follows that: it emulates opens instead of continuing them.

### Prior art (read)

[anthropics/sandbox-runtime](https://github.com/anthropics/sandbox-runtime) mediates network with proxies and an ask callback / `--control-fd`, but its README states filesystem rules are already in the seatbelt profile / bubblewrap argv at wrap time and do **not** change with control-fd updates. Codex's linux-sandbox, nsjail, bubblewrap and gVisor are static or reimplement the kernel. None of them ship the “supervisor opens + ADDFD” agent-oriented pattern against path-pointer TOCTOU.

### Measurements (this session, `--release`)

See the ES section for the exact commands. Headline numbers:

- TOCTOU secure mode: **0 escapes / 1000**
- TOCTOU CONTINUE control: **246 escapes / 1000** (harness sensitivity)
- Mediated openat p99: **17.78µs** (target < 50µs)
- Tasks without relaunch: **0% static vs 100% ask** (n=20)

### License

Apache-2.0.
