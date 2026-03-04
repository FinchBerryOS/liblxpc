# liblxpc

**liblxpc** is the core IPC (Inter-Process Communication) engine for FinchBerryOS. It implements the XPC protocol, providing a high-performance, dictionary-based messaging system inspired by Apple's XPC.

## 🚀 Overview

In FinchBerryOS, services and applications do not communicate via raw sockets or complex D-Bus interfaces. Instead, they use `liblxpc` to exchange structured data. While `syscored` acts as the broker (the "Matchmaker"), `liblxpc` handles the actual serialization and transport of data between peers.

### Key Features:
* **Structured Data:** Send complex nested Dictionaries, Arrays, Strings, and Integers.
* **Peer-to-Peer:** Once a connection is established by `syscored`, data flows directly between processes via Unix Domain Sockets.
* **File Descriptor Passing:** Native support for passing file descriptors (e.g., shared memory, pipes) across process boundaries.
* **Opaque Types:** Uses a clean, C-based API with opaque objects (`xpc_object_t`) to ensure memory safety and binary stability.

---

## 🏗 Architecture

`liblxpc` sits between the High-Level Frameworks and the Linux Kernel. It is typically re-exported by the **`libfinch.so`** umbrella library.



### The XPC Stack:
1. **Application Layer:** Calls `xpc_connection_send_message()`.
2. **liblxpc.so:** Serializes the dictionary into the FinchBerry Wire Format.
3. **Transport Layer:** Writes the binary blob to a Unix Domain Socket.
4. **Kernel Layer:** Delivers bytes to the target process.

---

## 🛠 Basic Usage (C API)

### Creating a Connection
To communicate with a system service (e.g., `com.finchberry.configd`):

```c
#include <finch/xpc.h>

// Create a connection to a named service
xpc_connection_t conn = xpc_connection_create_mach_service("com.finchberry.configd", NULL, 0);

xpc_connection_set_event_handler(conn, ^(xpc_object_t event) {
    if (xpc_get_type(event) == XPC_TYPE_DICTIONARY) {
        // Handle incoming message
    }
});

xpc_connection_resume(conn);