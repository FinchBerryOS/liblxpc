use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::unix::io::{FromRawFd, RawFd, BorrowedFd}; // BorrowedFd hinzugefügt für sichere FD-Referenzen
use std::os::unix::net::{UnixListener, UnixStream};
use std::ptr;
use std::thread;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};

// Wir nutzen cfg-guards, damit der Code auf deinem Mac kompiliert, 
// aber die Linux-Logik (PeerCred) für den echten Einsatz auf Linux bereithält.
#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::PeerCred;
use nix::sys::socket::getsockopt;

// --- Konstanten & Definitionen ---

// Typ-Identifikatoren für die C-API
pub const LXPC_TYPE_ERROR: i32 = 0;
pub const LXPC_TYPE_DICTIONARY: i32 = 1;

// Magic Number ('LXPC' in Hex) zum Absichern des Datenstroms. 
// Verhindert das Parsen von Müll, falls ein falscher Prozess in den Socket schreibt.
const LXPC_MAGIC: u32 = 0x4C585043; 

/// Repräsentiert eine aktive Verbindung zu einem anderen Prozess.
/// Arc und Mutex werden genutzt, da der Hintergrund-Thread und der C-Nutzer 
/// potenziell gleichzeitig auf den Handler oder den Status zugreifen.
#[allow(non_camel_case_types)]
#[repr(C)] // Garantiert, dass das Speicher-Layout kompatibel zu C ist
pub struct lxpc_connection {
    fd: RawFd,
    handler: Arc<Mutex<Option<extern "C" fn(*mut lxpc_object)>>>,
    running: Arc<Mutex<bool>>,
}

/// Das Daten-Wörterbuch, das zwischen den Prozessen verschickt wird.
/// Serde macht es uns leicht, dies später automatisch nach CBOR zu übersetzen.
#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Clone)]
#[repr(C)]
pub struct lxpc_object {
    pub obj_type: i32,
    pub data: HashMap<String, String>,
}


// --- Speicherverwaltung ---


/// Gibt ein lxpc_object frei. 
/// C-Entwickler MÜSSEN diese Funktion aufrufen, da C den von Rust 
/// allokierten Speicher (Box) sonst nicht freigeben kann (Memory Leak).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_object_release(ptr: *mut lxpc_object) {
    if !ptr.is_null() {
        // Box::from_raw übernimmt die Kontrolle über den Pointer zurück.
        // Sobald der Scope hier endet, wird der Speicher automatisch freigegeben.
        let _ = unsafe { Box::from_raw(ptr) };
    }
}

/// Gibt einen C-String frei, den Rust zuvor an C übergeben hat.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_string_release(ptr: *mut libc::c_char) {
    if !ptr.is_null() {
        // CString::from_raw nimmt den String zurück und dropt ihn.
        let _ = unsafe { CString::from_raw(ptr) };
    }
}


// --- Dictionary API ---


/// Erzeugt ein leeres Dictionary im Heap und gibt einen rohen C-Pointer zurück.
#[unsafe(no_mangle)]
pub extern "C" fn lxpc_dictionary_create() -> *mut lxpc_object {
    Box::into_raw(Box::new(lxpc_object {
        obj_type: LXPC_TYPE_DICTIONARY,
        data: HashMap::new(),
    }))
}

/// Fügt dem Dictionary einen String hinzu. 
/// Wandelt dabei die rohen C-Strings (*const c_char) sicher in Rust-Strings um.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_dictionary_set_string(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
    value: *const libc::c_char,
) {
    if obj.is_null() || key.is_null() || value.is_null() { return; }
    let dict = unsafe { &mut *obj }; // Dereferenziert den Pointer sicher
    
    // to_string_lossy schützt vor ungültigem UTF-8 aus der C-Welt
    let k = unsafe { CStr::from_ptr(key) }.to_string_lossy().into_owned();
    let v = unsafe { CStr::from_ptr(value) }.to_string_lossy().into_owned();
    dict.data.insert(k, v);
}

/// Holt einen String aus dem Dictionary.
/// Erzeugt eine Kopie des Strings im Heap für C. Der Caller muss lxpc_string_release nutzen!
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_dictionary_get_string(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
) -> *mut libc::c_char {
    if obj.is_null() || key.is_null() { return ptr::null_mut(); }
    let dict = unsafe { &*obj };
    let k = unsafe { CStr::from_ptr(key) }.to_string_lossy();
    
    if let Some(val) = dict.data.get(k.as_ref()) {
        // into_raw übergibt die Besitzschaft des Strings an C
        return CString::new(val.as_str()).unwrap().into_raw();
    }
    ptr::null_mut()
}


// --- Netzwerk & Framing ---


/// Serialisiert das Objekt zu CBOR und schickt es mitsamt Header über den Socket.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_connection_send_message(conn: *mut lxpc_connection, obj: *mut lxpc_object) {
    if conn.is_null() || obj.is_null() { return; }
    let conn = unsafe { &mut *conn };
    let dict = unsafe { &*obj };

    let mut payload = Vec::new();
    // Wandle das Rust-Struct via Ciborium in binäres CBOR um
    if ciborium::into_writer(dict, &mut payload).is_ok() {
        // Baue einen Stream aus dem File Descriptor auf
        let mut stream = unsafe { UnixStream::from_raw_fd(conn.fd) };
        
        // Header: 4 Bytes Magic Number + 4 Bytes Payload-Länge
        let mut header = Vec::with_capacity(8);
        header.extend_from_slice(&LXPC_MAGIC.to_le_bytes());
        header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        
        // Alles in den Socket schreiben
        let _ = stream.write_all(&header);
        let _ = stream.write_all(&payload);
        
        // EXTREM WICHTIG: forget verhindert, dass Rust den Socket (stream) am Ende 
        // der Funktion schließt. Wir wollen die Verbindung ja offen halten!
        std::mem::forget(stream); 
    }
}

/// Startet einen Hintergrund-Thread, der auf Nachrichten wartet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_connection_resume(conn: *mut lxpc_connection) {
    if conn.is_null() { return; }
    let conn = unsafe { &mut *conn };
    
    // Verhindere, dass wir den Loop zweimal starten
    let mut running = conn.running.lock().unwrap();
    if *running { return; }
    *running = true;

    // Kopiere benötigte Daten für den neuen Thread
    let fd = conn.fd;
    let handler_arc = Arc::clone(&conn.handler);
    let running_arc = Arc::clone(&conn.running);

    // Starte den Hintergrund-Worker
    thread::spawn(move || {
        let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
        let mut header_buf = [0u8; 8];
        
        while *running_arc.lock().unwrap() {
            // 1. Lese exakt 8 Bytes für den Header. Blockiert, bis Daten da sind.
            if stream.read_exact(&mut header_buf).is_ok() {
                let magic = u32::from_le_bytes(header_buf[0..4].try_into().unwrap());
                let length = u32::from_le_bytes(header_buf[4..8].try_into().unwrap());
                
                // 2. Validierung
                if magic == LXPC_MAGIC {
                    let mut payload = vec![0u8; length as usize];
                    // 3. Lese exakt so viele Bytes, wie der Header angekündigt hat
                    if stream.read_exact(&mut payload).is_ok() {
                        // 4. Decodiere das CBOR in unser Rust-Objekt
                        if let Ok(obj_data) = ciborium::from_reader::<lxpc_object, _>(&payload[..]) {
                            let obj_ptr = Box::into_raw(Box::new(obj_data));
                            let h_lock = handler_arc.lock().unwrap();
                            // 5. Rufe die C-Funktion auf, falls der Nutzer eine registriert hat
                            if let Some(h) = *h_lock { h(obj_ptr); }
                        }
                    }
                }
            } else { 
                // Socket Fehler oder geschlossen -> Loop abbrechen
                break; 
            }
        }
    });
}


// --- Bootstrap (Sicherheits-Check) ---


/// Überprüft, ob der Prozess, der uns auf FD 3 gestartet hat, 
/// wirklich syscored (PID 1) ist.
#[unsafe(no_mangle)]
pub extern "C" fn lxpc_bootstrap_connection_activate() -> i32 {
    let fd_raw: RawFd = 3; // syscored übergibt Socket immer auf FD 3
    
    // Wir wrappen den RawFd in einen BorrowedFd, damit AsFd (für getsockopt) funktioniert,
    // ohne dass Rust versucht, den Socket beim Aufräumen zu schließen.
    let fd = unsafe { BorrowedFd::borrow_raw(fd_raw) };

    // Dies wird nur kompiliert, wenn wir wirklich für Linux bauen
    #[cfg(target_os = "linux")]
    {
        if let Ok(creds) = getsockopt(&fd, PeerCred) {
            // Check: Ist der verbundene Partner PID 1?
            if creds.pid() != 1 { return -3; }
            return 0; // Erfolg
        }
        return -1; // Fehler beim Auslesen der Credentials
    }

    // Für den Mac (während der Entwicklung) tun wir so, als wäre alles in Ordnung
    #[cfg(not(target_os = "linux"))]
    {
        0 
    }
}

/// Der Einstiegspunkt für Daemons. Übernimmt FD 3 und nimmt neue Clients an.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_main(handler: extern "C" fn(*mut lxpc_connection)) {
    // 1. Zuerst verifizieren wir die Startbedingungen
    if lxpc_bootstrap_connection_activate() != 0 {
        unsafe { libc::exit(1) };
    }

    // 2. Wir deklarieren FD 3 als lauschenden Socket
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    
    // 3. Endlosschleife: Wir akzeptieren jeden neuen Client von syscored
    for stream in listener.incoming() {
        if let Ok(s) = stream {
            use std::os::unix::io::AsRawFd;
            let client_fd = s.as_raw_fd();
            
            // Wichtig: Wir brauchen nur den FD, Rust darf den Stream nicht schließen!
            std::mem::forget(s); 
            
            // Erstelle ein neues Verbindungsobjekt für den neuen Client
            let conn = Box::into_raw(Box::new(lxpc_connection {
                fd: client_fd,
                handler: Arc::new(Mutex::new(None)),
                running: Arc::new(Mutex::new(false)),
            }));
            
            // Reiche das fertige Objekt an die App-Logik des C-Programms weiter
            handler(conn);
        }
    }
}