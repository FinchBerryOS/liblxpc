# liblxpc

**liblxpc** is the core IPC (Inter-Process Communication) engine for FinchBerryOS. It provides a high-performance, dictionary-based messaging system inspired by Apple's XPC — implemented in Rust with a clean C API.

## Overview

In FinchBerryOS, services and applications do not communicate via raw sockets or D-Bus. Instead, they use `liblxpc` to exchange structured data. `syscored` acts as the broker and connection router, while `liblxpc` handles serialization, transport, and connection lifecycle.

### Key Features

- **Structured Data** — Send nested Dictionaries, Arrays, Strings, Integers, Doubles, Booleans, UUIDs, and raw Byte Blobs
- **File Descriptor Passing** — Native support for passing file descriptors across process boundaries via `SCM_RIGHTS`
- **Reply Semantics** — Built-in Request/Response with automatic Correlation-IDs (`lxpc.msg_id` / `lxpc.reply_to`)
- **Bootstrap Verification** — Services cryptographically verify via the kernel that they were started by `syscored` (PID 1)
- **C API** — Clean opaque types (`lxpc_object_t`, `lxpc_connection_t`) for binary stability

---

## Architecture

```
┌─────────────────────────────────┐
│         Application / Service   │
│         (C, C++, Rust, ...)     │
├─────────────────────────────────┤
│           liblxpc.so            │  ← you are here
│   serialization · transport     │
│   bootstrap · reply semantics   │
├─────────────────────────────────┤
│       Unix Domain Sockets       │
│         (via syscored)          │
├─────────────────────────────────┤
│          Linux Kernel           │
└─────────────────────────────────┘
```

### How a Connection Works

1. A client calls `lxpc_connection_create("de.fbyc.myservice")`
2. `liblxpc` connects to `syscored` at `/run/syscored.sock`
3. `syscored` looks up the service, starts it if needed, and passes a socket FD to both sides
4. Client and service communicate directly — `syscored` is no longer in the data path

---

## Wire Format

Every message is framed with a 12-byte header followed by a CBOR-serialized payload:

```
 0       4       6       8      12
 +-------+-------+-------+-------+
 | MAGIC | VER   | FLAGS | LEN   |
 +-------+-------+-------+-------+

 MAGIC : u32 LE  — 0x4C585043 ("LXPC")
 VER   : u16 LE  — Protocol version (currently 1)
 FLAGS : u16 LE  — Reserved, must be 0
 LEN   : u32 LE  — Length of the following CBOR payload in bytes
```

Maximum message size is 4 MiB. Messages exceeding this limit are rejected.

---

## Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# For local testing without syscored (disables bootstrap PID check)
cargo build --features disable_pid_check
```

The output is `liblxpc.so` (or `liblxpc.dylib` on macOS). Include `lxpc.h` in your C project.

---

## C API — Quick Reference

### Memory Rules

Every object returned by liblxpc must be explicitly released:

| Object | Release function |
|---|---|
| `lxpc_object_t*` | `lxpc_object_release()` |
| `lxpc_connection_t*` | `lxpc_connection_release()` |
| `char*` from `get_string` | `lxpc_string_release()` |

### Service (Daemon) Side

```c
#include "lxpc.h"

lxpc_connection_t *g_conn = NULL;

static void on_message(lxpc_object_t *msg) {
    char *name = lxpc_dictionary_get_string(msg, "name");

    lxpc_object_t *reply = lxpc_dictionary_create();
    lxpc_dictionary_set_string(reply, "greeting", "Hello!");

    lxpc_connection_send_reply(g_conn, reply, lxpc_object_get_msg_id(msg));

    lxpc_object_release(reply);
    if (name) lxpc_string_release(name);
    lxpc_object_release(msg);  // always last
}

static void on_new_client(lxpc_connection_t *conn) {
    g_conn = conn;
    lxpc_connection_set_event_handler(conn, on_message);
    lxpc_connection_resume(conn);
}

int main(void) {
    lxpc_main(on_new_client, NULL);
}
```

### Client Side

```c
#include "lxpc.h"

static void on_reply(lxpc_object_t *msg) {
    char *greeting = lxpc_dictionary_get_string(msg, "greeting");
    if (greeting) {
        printf("%s\n", greeting);
        lxpc_string_release(greeting);
    }
    lxpc_object_release(msg);
}

int main(void) {
    lxpc_connection_t *conn = lxpc_connection_create("de.fbyc.myservice");
    lxpc_connection_set_event_handler(conn, on_reply);
    lxpc_connection_resume(conn);

    lxpc_object_t *msg = lxpc_dictionary_create();
    lxpc_dictionary_set_string(msg, "name", "world");
    lxpc_connection_send_message(conn, msg);
    lxpc_object_release(msg);
}
```

---

## Value Types

| Type | Setter | Getter |
|---|---|---|
| String | `lxpc_dictionary_set_string` | `lxpc_dictionary_get_string` |
| Int64 | `lxpc_dictionary_set_int64` | `lxpc_dictionary_get_int64` |
| Double | `lxpc_dictionary_set_double` | `lxpc_dictionary_get_double` |
| Bool | `lxpc_dictionary_set_bool` | `lxpc_dictionary_get_bool` |
| Data (blob) | `lxpc_dictionary_set_data` | — |
| UUID | `lxpc_dictionary_set_uuid` | — |
| File Descriptor | `lxpc_dictionary_set_fd` | `lxpc_dictionary_get_fd` |
| Null | `lxpc_dictionary_set_null` | — |

---

## Bootstrap & FD 3

`syscored` starts every service via `fork()`+`exec()`. Before `exec()`, it places the bootstrap socket on **FD 3** and closes all other file descriptors (`closefrom(4)`). The service is guaranteed to find its connection to `syscored` on FD 3 — this is a fixed convention, not configurable.

`lxpc_main()` calls `lxpc_bootstrap_connection_activate()` internally, which verifies via `getsockopt(SO_PEERCRED)` that the peer on FD 3 is PID 1 running as UID 0. If this check fails the process exits immediately.

---

## License

Part of FinchBerryOS / FBYC. See repository root for license information.