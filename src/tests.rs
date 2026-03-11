#[cfg(test)]
mod tests {
    use std::os::unix::io::{RawFd, IntoRawFd};
    use std::sync::{Arc, Mutex};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;
    use std::io::{Read, Write};
    use std::os::unix::io::FromRawFd;
    use nix::sys::socket::{socketpair, AddressFamily, SockType, SockFlag};

    use crate::lxpc::{
        LxpcConnection, LxpcObject, LxpcError,
        LXPC_MAGIC, LXPC_PROTOCOL_VERSION,
        HEADER_SIZE, encode_header,
    };

    // -----------------------------------------------------------------------
    // Hilfsfunktion: socketpair als RawFd-Paar
    // -----------------------------------------------------------------------

    fn make_pair() -> (RawFd, RawFd) {
        let (a, b) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        ).expect("socketpair fehlgeschlagen");
        (a.into_raw_fd(), b.into_raw_fd())
    }

    // -----------------------------------------------------------------------
    // 1. Alle Werttypen — keine Netzwerkkommunikation nötig
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_value_types() {
        let mut obj = LxpcObject::new_dictionary();
        obj.set_string("s", "test");
        obj.set_int64("i", -42);
        obj.set_double("d", 3.14);
        obj.set_bool("b", true);
        obj.set_data("bytes", vec![1, 2, 3]);
        obj.set_uuid("uuid", [0xAB; 16]);
        obj.set_null("n");

        assert_eq!(obj.get_string("s"), Some("test"));
        assert_eq!(obj.get_int64("i"), Some(-42));
        assert!((obj.get_double("d").unwrap() - 3.14).abs() < 1e-10);
        assert_eq!(obj.get_bool("b"), Some(true));
        assert_eq!(obj.get_data("bytes"), Some([1u8, 2, 3].as_slice()));
        assert_eq!(obj.get_uuid("uuid"), Some([0xABu8; 16]));
        assert!(obj.is_null("n"));

        // Fehlende Keys → None
        assert_eq!(obj.get_string("nope"), None);
        // Falscher Typ → None
        assert_eq!(obj.get_int64("s"), None);
    }

    // -----------------------------------------------------------------------
    // 2. Nachricht > 4 MiB wird abgelehnt
    // -----------------------------------------------------------------------

    #[test]
    fn test_message_too_large() {
        let (fd_a, fd_b) = make_pair();
        let conn = LxpcConnection::new(fd_a);
        unsafe { libc::close(fd_b) };

        let mut msg = LxpcObject::new_dictionary();
        msg.set_data("blob", vec![0u8; 5 * 1024 * 1024]);

        let result = conn.send_message(&msg);
        assert!(
            matches!(result, Err(LxpcError::MessageTooLarge(_))),
            "Erwartet MessageTooLarge, bekommen: {result:?}"
        );
    }

    // -----------------------------------------------------------------------
    // 3. Falsche Magic Number → Lese-Thread stoppt
    // -----------------------------------------------------------------------

    #[test]
    fn test_bad_magic() {
        let (fd_a, fd_b) = make_pair();

        // Müll-Header mit falscher Magic schreiben
        let mut bad_header = [0u8; HEADER_SIZE];
        bad_header[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        bad_header[8..12].copy_from_slice(&4u32.to_le_bytes());

        let mut writer = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd_a) };
        writer.write_all(&bad_header).unwrap();
        writer.write_all(&[0u8; 4]).unwrap();
        std::mem::forget(writer);

        let conn_b = LxpcConnection::new(fd_b);
        conn_b.activate();

        thread::sleep(Duration::from_millis(300));

        assert!(
            !*conn_b.running.lock().unwrap(),
            "Lese-Thread sollte nach BadMagic gestoppt sein"
        );
    }

    // -----------------------------------------------------------------------
    // 4. Protokollversion zu neu → Lese-Thread stoppt
    // -----------------------------------------------------------------------

    #[test]
    fn test_unsupported_version() {
        let (fd_a, fd_b) = make_pair();

        let mut header = [0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(&LXPC_MAGIC.to_le_bytes());
        header[4..6].copy_from_slice(&(LXPC_PROTOCOL_VERSION + 1).to_le_bytes());
        header[8..12].copy_from_slice(&4u32.to_le_bytes());

        let mut writer = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd_a) };
        writer.write_all(&header).unwrap();
        writer.write_all(&[0u8; 4]).unwrap();
        std::mem::forget(writer);

        let conn_b = LxpcConnection::new(fd_b);
        conn_b.activate();

        thread::sleep(Duration::from_millis(300));

        assert!(
            !*conn_b.running.lock().unwrap(),
            "Lese-Thread sollte nach UnsupportedVersion gestoppt sein"
        );
    }

    // -----------------------------------------------------------------------
    // 5. Verbindung getrennt → running = false
    // -----------------------------------------------------------------------

    #[test]
    fn test_connection_closed() {
        let (fd_a, fd_b) = make_pair();

        let conn_b = LxpcConnection::new(fd_b);
        conn_b.activate();

        // fd_a schließen → Gegenseite bekommt EOF
        unsafe { libc::close(fd_a) };

        thread::sleep(Duration::from_millis(300));

        assert!(
            !*conn_b.running.lock().unwrap(),
            "Lese-Thread sollte nach EOF gestoppt sein"
        );
    }

    // -----------------------------------------------------------------------
    // 6. Reply-Semantik: msg_id und reply_to korrekt gesetzt
    // -----------------------------------------------------------------------

    #[test]
    fn test_reply_correlation() {
        let (fd_a, fd_b) = make_pair();

        // fd_b liest raw und sammelt die CBOR-Objekte
        let ids: Arc<Mutex<Vec<(i64, i64)>>> = Arc::new(Mutex::new(Vec::new()));
        let ids_clone = Arc::clone(&ids);

        thread::spawn(move || {
            let mut stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd_b) };
            stream.set_read_timeout(Some(Duration::from_millis(500))).ok();

            loop {
                let mut hbuf = [0u8; HEADER_SIZE];
                if stream.read_exact(&mut hbuf).is_err() { break; }

                let length = u32::from_le_bytes(hbuf[8..12].try_into().unwrap());
                let mut payload = vec![0u8; length as usize];
                if stream.read_exact(&mut payload).is_err() { break; }

                if let Ok(obj) = ciborium::from_reader::<LxpcObject, _>(&payload[..]) {
                    let msg_id   = obj.get_int64("lxpc.msg_id").unwrap_or(-1);
                    let reply_to = obj.get_int64("lxpc.reply_to").unwrap_or(-1);
                    ids_clone.lock().unwrap().push((msg_id, reply_to));
                }
            }
            std::mem::forget(stream);
        });

        let conn_a = LxpcConnection::new(fd_a);

        // Normale Nachricht senden
        let msg = LxpcObject::new_dictionary();
        conn_a.send_message(&msg).unwrap();

        // Reply auf msg_id 42
        let mut reply = LxpcObject::new_dictionary();
        conn_a.send_reply(&mut reply, 42).unwrap();

        thread::sleep(Duration::from_millis(400));

        let collected = ids.lock().unwrap().clone();
        assert_eq!(collected.len(), 2,
            "Erwartet 2 Nachrichten, bekommen: {}", collected.len());

        // Erste Nachricht: keine reply_to
        assert!(collected[0].0 > 0, "msg_id sollte positiv sein");
        assert_eq!(collected[0].1, -1, "Erste Nachricht hat kein reply_to");

        // Zweite Nachricht: reply_to = 42
        assert!(collected[1].0 > 0, "msg_id sollte positiv sein");
        assert_eq!(collected[1].1, 42, "Reply sollte reply_to=42 tragen");
    }

    // -----------------------------------------------------------------------
    // 7. Gleichzeitige Sender — kein Protokollbruch
    // -----------------------------------------------------------------------

    #[test]
    fn test_concurrent_senders() {
        let (fd_a, fd_b) = make_pair();

        // Zähler für empfangene Nachrichten
        static MSG_COUNT: AtomicUsize = AtomicUsize::new(0);
        MSG_COUNT.store(0, Ordering::SeqCst);

        unsafe extern "C" fn count_handler(msg: *mut LxpcObject) {
            MSG_COUNT.fetch_add(1, Ordering::SeqCst);
            unsafe { crate::lxpc_object_release(msg) };
        }

        let conn_b = LxpcConnection::new(fd_b);
        conn_b.handler.lock().unwrap().replace(count_handler);
        conn_b.activate();

        // 10 Threads × 10 Nachrichten = 100 gesamt
        let conn_a = Arc::new(LxpcConnection::new(fd_a));
        let handles: Vec<_> = (0..10).map(|_| {
            let conn = Arc::clone(&conn_a);
            thread::spawn(move || {
                for _ in 0..10 {
                    let mut msg = LxpcObject::new_dictionary();
                    msg.set_string("x", "y");
                    conn.send_message(&msg).expect("send fehlgeschlagen");
                }
            })
        }).collect();

        for h in handles { h.join().unwrap(); }

        // Warten bis alle Nachrichten verarbeitet sind
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while MSG_COUNT.load(Ordering::SeqCst) < 100 {
            if std::time::Instant::now() > deadline {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert_eq!(MSG_COUNT.load(Ordering::SeqCst), 100,
            "Nicht alle Nachrichten angekommen: {}/100", MSG_COUNT.load(Ordering::SeqCst));
        assert!(*conn_b.running.lock().unwrap(),
            "Lese-Thread sollte noch laufen");
    }

    // -----------------------------------------------------------------------
    // 8. Read-Timeout — unvollständiger Payload blockiert nicht ewig
    // -----------------------------------------------------------------------

    #[test]
    fn test_read_timeout() {
        let (fd_a, fd_b) = make_pair();

        // Timeout auf 1s kürzen BEVOR activate() aufgerufen wird
        {
            use nix::sys::socket::setsockopt;
            use nix::sys::socket::sockopt::ReceiveTimeout;
            use nix::sys::time::TimeVal;
            let borrowed = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(fd_b) };
            setsockopt(&borrowed, ReceiveTimeout, &TimeVal::new(1, 0)).unwrap();
        }

        // Nur den Header schicken, Payload kommt nie
        let header = encode_header(1024);
        let mut writer = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd_a) };
        writer.write_all(&header).unwrap();
        std::mem::forget(writer); // fd_a offen lassen — kein EOF

        let conn_b = LxpcConnection::new_with_timeout(fd_b, 1);
        conn_b.activate();

        thread::sleep(Duration::from_millis(1500));

        assert!(
            !*conn_b.running.lock().unwrap(),
            "Lese-Thread sollte nach Read-Timeout gestoppt sein"
        );
    }

    // -----------------------------------------------------------------------
    // 9. CBOR Round-Trip — Serialisierung ist verlustfrei
    // -----------------------------------------------------------------------

    #[test]
    fn test_cbor_roundtrip() {
        let mut original = LxpcObject::new_dictionary();
        original.set_string("name", "FinchBerry");
        original.set_int64("version", 2);
        original.set_double("pi", std::f64::consts::PI);
        original.set_bool("active", true);
        original.set_data("blob", vec![0xDE, 0xAD, 0xBE, 0xEF]);
        original.set_uuid("id", [0x01; 16]);

        // Serialisieren
        let mut buf = Vec::new();
        ciborium::into_writer(&original, &mut buf).unwrap();

        // Deserialisieren
        let restored: LxpcObject = ciborium::from_reader(&buf[..]).unwrap();

        assert_eq!(restored.get_string("name"), Some("FinchBerry"));
        assert_eq!(restored.get_int64("version"), Some(2));
        assert!((restored.get_double("pi").unwrap() - std::f64::consts::PI).abs() < 1e-15);
        assert_eq!(restored.get_bool("active"), Some(true));
        assert_eq!(restored.get_data("blob"), Some([0xDE, 0xAD, 0xBE, 0xEFu8].as_slice()));
        assert_eq!(restored.get_uuid("id"), Some([0x01u8; 16]));
    }
}