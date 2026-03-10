use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, BorrowedFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::io::{Read, IoSlice, IoSliceMut};
use serde::{Serialize, Deserialize};


#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::PeerCredentials;

#[cfg(target_os = "macos")]
use nix::sys::socket::sockopt::LocalPeerPid;

use nix::sys::socket::{
    getsockopt, sendmsg, recvmsg, ControlMessage, ControlMessageOwned, MsgFlags
};

// ---------------------------------------------------------------------------
// Konstanten
// ---------------------------------------------------------------------------

/// Typ-Identifikator für Dictionary-Objekte.
pub const LXPC_TYPE_DICTIONARY: i32 = 1;

/// Magic Number ('LXPC' in ASCII als Little-Endian u32).
/// Schützt vor versehentlichem oder bösartigem Müll auf dem Socket.
pub const LXPC_MAGIC: u32 = 0x4C585043;

/// Aktuelle Protokollversion. Wird im Header mitgesendet.
/// Empfänger die eine höhere Version sehen, sollen die Verbindung ablehnen.
pub const LXPC_PROTOCOL_VERSION: u16 = 1;

/// Maximale erlaubte Nachrichtengröße: 4 MiB.
/// Schützt vor OOM durch bösartige oder fehlerhafte Gegenstellen.
pub const LXPC_MAX_MESSAGE_SIZE: u32 = 4 * 1024 * 1024;

/// Maximale Anzahl FDs die in einer einzigen Nachricht übertragen werden dürfen.
pub const LXPC_MAX_FDS_PER_MSG: usize = 16;

/// Der Bootstrap-FD den syscored an Dienste übergibt (immer FD 3).
pub const BOOTSTRAP_FD: RawFd = 3;

// ---------------------------------------------------------------------------
// Fehlertypen
// ---------------------------------------------------------------------------

/// Alle möglichen Fehler die LXPC erzeugen kann — explizit, kein stilles Schlucken mehr.
#[derive(Debug)]
pub enum LxpcError {
    /// Socket-Operation fehlgeschlagen (recvmsg, sendmsg, …)
    Io(std::io::Error),
    /// Nix-Syscall fehlgeschlagen
    Nix(nix::Error),
    /// Serialisierungs- oder Deserialisierungsfehler
    Serialization(String),
    /// Protokollfehler: falsche Magic Number
    BadMagic,
    /// Protokollfehler: unbekannte oder neuere Protokollversion
    UnsupportedVersion(u16),
    /// Nachricht ist zu groß (DoS-Schutz)
    MessageTooLarge(u32),
    /// Gegenstelle ist nicht syscored (bootstrap_check fehlgeschlagen)
    NotBootstrap,
    /// Verbindung wurde von der Gegenstelle geschlossen
    ConnectionClosed,
    /// Ungültiger Null-Pointer aus C-Code
    NullPointer,
}

impl std::fmt::Display for LxpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LxpcError::Io(e)               => write!(f, "I/O-Fehler: {e}"),
            LxpcError::Nix(e)              => write!(f, "Syscall-Fehler: {e}"),
            LxpcError::Serialization(s)    => write!(f, "Serialisierungsfehler: {s}"),
            LxpcError::BadMagic            => write!(f, "Ungültige Magic Number — kein LXPC-Protokoll"),
            LxpcError::UnsupportedVersion(v) => write!(f, "Protokollversion {v} wird nicht unterstützt"),
            LxpcError::MessageTooLarge(n)  => write!(f, "Nachricht zu groß: {n} Bytes (max {LXPC_MAX_MESSAGE_SIZE})"),
            LxpcError::NotBootstrap        => write!(f, "Verbindung kommt nicht von syscored (PID 1)"),
            LxpcError::ConnectionClosed    => write!(f, "Verbindung wurde geschlossen"),
            LxpcError::NullPointer         => write!(f, "Null-Pointer von C-Seite"),
        }
    }
}

pub type LxpcResult<T> = Result<T, LxpcError>;

// ---------------------------------------------------------------------------
// Wire-Format Header  (12 Bytes)
//
//  0       4       6       8      12
//  +-------+-------+-------+-------+
//  | MAGIC | VER   | FLAGS | LEN   |
//  +-------+-------+-------+-------+
//
//  MAGIC  : u32 LE  — 0x4C585043
//  VER    : u16 LE  — Protokollversion (aktuell 1)
//  FLAGS  : u16 LE  — reserviert, muss 0 sein
//  LEN    : u32 LE  — Länge des folgenden CBOR-Payloads in Bytes
// ---------------------------------------------------------------------------

/// Größe des Frame-Headers in Bytes.
const HEADER_SIZE: usize = 12;

fn encode_header(payload_len: u32) -> [u8; HEADER_SIZE] {
    let mut h = [0u8; HEADER_SIZE];
    h[0..4].copy_from_slice(&LXPC_MAGIC.to_le_bytes());
    h[4..6].copy_from_slice(&LXPC_PROTOCOL_VERSION.to_le_bytes());
    h[6..8].copy_from_slice(&0u16.to_le_bytes()); // flags = 0
    h[8..12].copy_from_slice(&payload_len.to_le_bytes());
    h
}

fn decode_header(buf: &[u8; HEADER_SIZE]) -> LxpcResult<u32> {
    let magic   = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    let length  = u32::from_le_bytes(buf[8..12].try_into().unwrap());

    if magic != LXPC_MAGIC {
        return Err(LxpcError::BadMagic);
    }
    if version > LXPC_PROTOCOL_VERSION {
        return Err(LxpcError::UnsupportedVersion(version));
    }
    if length > LXPC_MAX_MESSAGE_SIZE {
        return Err(LxpcError::MessageTooLarge(length));
    }
    Ok(length)
}

// ---------------------------------------------------------------------------
// Werttypen  (vollständige Parität mit Apple XPC)
// ---------------------------------------------------------------------------

/// Alle Typen die LXPC transportieren kann.
/// Entspricht 1:1 den xpc_type_t-Werten von Apple XPC.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum LxpcValue {
    /// UTF-8 String
    String(String),
    /// 64-Bit vorzeichenbehafteter Integer
    Int64(i64),
    /// 64-Bit Gleitkommazahl (IEEE 754 double)
    Double(f64),
    /// Boolescher Wert
    Bool(bool),
    /// Rohe Bytes (Blob/Data)
    Data(Vec<u8>),
    /// UUID als 16-Byte-Array
    Uuid([u8; 16]),
    /// Null / kein Wert
    Null,
    /// Verschachteltes Dictionary
    Dictionary(HashMap<String, LxpcValue>),
    /// Geordnete Liste beliebiger Werte
    Array(Vec<LxpcValue>),
    /// File Descriptor — wird via SCM_RIGHTS durch den Kernel übertragen.
    /// Die Zahl hier ist nur ein lokaler Platzhalter; beim Senden wird sie
    /// durch den tatsächlichen Kernel-FD ersetzt.
    Fd(RawFd),
}

// ---------------------------------------------------------------------------
// LxpcObject
// ---------------------------------------------------------------------------

/// Das Haupt-Dictionary das als Paket zwischen Prozessen verschickt wird.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LxpcObject {
    pub obj_type: i32,
    pub data: HashMap<String, LxpcValue>,
}

impl LxpcObject {
    pub fn new_dictionary() -> Self {
        Self { obj_type: LXPC_TYPE_DICTIONARY, data: HashMap::new() }
    }

    // --- Setter ---

    pub fn set_string(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.data.insert(key.into(), LxpcValue::String(value.into()));
    }

    pub fn set_int64(&mut self, key: impl Into<String>, value: i64) {
        self.data.insert(key.into(), LxpcValue::Int64(value));
    }

    pub fn set_double(&mut self, key: impl Into<String>, value: f64) {
        self.data.insert(key.into(), LxpcValue::Double(value));
    }

    pub fn set_bool(&mut self, key: impl Into<String>, value: bool) {
        self.data.insert(key.into(), LxpcValue::Bool(value));
    }

    pub fn set_data(&mut self, key: impl Into<String>, value: Vec<u8>) {
        self.data.insert(key.into(), LxpcValue::Data(value));
    }

    pub fn set_uuid(&mut self, key: impl Into<String>, value: [u8; 16]) {
        self.data.insert(key.into(), LxpcValue::Uuid(value));
    }

    pub fn set_null(&mut self, key: impl Into<String>) {
        self.data.insert(key.into(), LxpcValue::Null);
    }

    pub fn set_array(&mut self, key: impl Into<String>, value: Vec<LxpcValue>) {
        self.data.insert(key.into(), LxpcValue::Array(value));
    }

    pub fn set_dictionary(&mut self, key: impl Into<String>, value: HashMap<String, LxpcValue>) {
        self.data.insert(key.into(), LxpcValue::Dictionary(value));
    }

    /// Speichert einen File Descriptor.
    /// WICHTIG: Nur die Zahl wird hier gespeichert. Das physische Übertragen
    /// via SCM_RIGHTS passiert in send_message().
    pub fn set_fd(&mut self, key: impl Into<String>, fd: RawFd) {
        self.data.insert(key.into(), LxpcValue::Fd(fd));
    }

    // --- Getter ---

    pub fn get_string(&self, key: &str) -> Option<&str> {
        match self.data.get(key) {
            Some(LxpcValue::String(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn get_int64(&self, key: &str) -> Option<i64> {
        match self.data.get(key) {
            Some(LxpcValue::Int64(n)) => Some(*n),
            _ => None,
        }
    }

    pub fn get_double(&self, key: &str) -> Option<f64> {
        match self.data.get(key) {
            Some(LxpcValue::Double(d)) => Some(*d),
            _ => None,
        }
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        match self.data.get(key) {
            Some(LxpcValue::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    pub fn get_data(&self, key: &str) -> Option<&[u8]> {
        match self.data.get(key) {
            Some(LxpcValue::Data(d)) => Some(d.as_slice()),
            _ => None,
        }
    }

    pub fn get_uuid(&self, key: &str) -> Option<[u8; 16]> {
        match self.data.get(key) {
            Some(LxpcValue::Uuid(u)) => Some(*u),
            _ => None,
        }
    }

    pub fn get_array(&self, key: &str) -> Option<&Vec<LxpcValue>> {
        match self.data.get(key) {
            Some(LxpcValue::Array(a)) => Some(a),
            _ => None,
        }
    }

    pub fn get_fd(&self, key: &str) -> Option<RawFd> {
        match self.data.get(key) {
            Some(LxpcValue::Fd(fd)) => Some(*fd),
            _ => None,
        }
    }

    pub fn is_null(&self, key: &str) -> bool {
        matches!(self.data.get(key), Some(LxpcValue::Null))
    }
}

// ---------------------------------------------------------------------------
// Reply-Semantik: Correlation-IDs
// ---------------------------------------------------------------------------

/// Internes Systemobjekt das LXPC automatisch in jede Nachricht einfügt.
/// Damit kann der Empfänger Antworten den richtigen Anfragen zuordnen.
///
/// Schlüssel sind absichtlich mit "lxpc." präfixiert — C-Code soll sie
/// nicht versehentlich überschreiben.
const KEY_MSG_ID:   &str = "lxpc.msg_id";
const KEY_REPLY_TO: &str = "lxpc.reply_to";
/// Reserviert für zukünftige strukturierte Fehler-Propagation (analog XPC_ERROR_*)
#[allow(dead_code)]
const KEY_ERROR_MSG:  &str = "lxpc.error";
#[allow(dead_code)]
const KEY_ERROR_CODE: &str = "lxpc.error_code";

/// Erzeugt eine neue, monoton steigende Nachrichten-ID.
fn next_msg_id() -> i64 {
    use std::sync::atomic::{AtomicI64, Ordering};
    static COUNTER: AtomicI64 = AtomicI64::new(1);
    COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// RAII-Guard für empfangene FDs
// ---------------------------------------------------------------------------

/// Schließt alle enthaltenen FDs automatisch beim Drop.
/// Verhindert FD-Leaks wenn die Deserialisierung nach dem SCM_RIGHTS-Empfang scheitert.
struct FdGuard {
    fds: Vec<RawFd>,
    consumed: bool,
}

impl FdGuard {
    fn new(fds: Vec<RawFd>) -> Self {
        Self { fds, consumed: false }
    }

    /// Gibt die FDs heraus und deaktiviert den automatischen Close.
    fn take(mut self) -> Vec<RawFd> {
        self.consumed = true;
        self.fds.clone()
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        if !self.consumed {
            for fd in &self.fds {
                // Fehler beim Schließen können wir hier nicht sinnvoll propagieren,
                // aber wir wollen sie zumindest loggen.
                if unsafe { libc::close(*fd) } != 0 {
                    eprintln!("[lxpc WARN]  FdGuard: close({fd}) fehlgeschlagen");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// LxpcConnection
// ---------------------------------------------------------------------------

/// Callback-Typ für eingehende Nachrichten.
pub type MessageHandler = extern "C" fn(*mut LxpcObject);

/// Callback-Typ für Verbindungsfehler (Connection-Error als first-class Event).
pub type ErrorHandler = extern "C" fn(i32, *const libc::c_char);

/// Repräsentiert eine aktive Verbindung zwischen zwei Prozessen.
pub struct LxpcConnection {
    pub fd: RawFd,
    /// Schreibt-Mutex: verhindert interleaved Writes von mehreren Threads.
    write_lock: Mutex<()>,
    /// Eingehende Nachrichten-Handler.
    pub handler: Arc<Mutex<Option<MessageHandler>>>,
    /// Verbindungsfehler-Handler.
    pub error_handler: Arc<Mutex<Option<ErrorHandler>>>,
    /// Ob der Lese-Thread läuft.
    pub running: Arc<Mutex<bool>>,
}

impl LxpcConnection {
    pub fn new(fd: RawFd) -> Self {
        Self {
            fd,
            write_lock: Mutex::new(()),
            handler: Arc::new(Mutex::new(None)),
            error_handler: Arc::new(Mutex::new(None)),
            running: Arc::new(Mutex::new(false)),
        }
    }

    // -----------------------------------------------------------------------
    // Senden
    // -----------------------------------------------------------------------

    /// Sendet ein Dictionary an die Gegenstelle.
    /// Gibt einen Fehler zurück wenn das Senden fehlschlägt.
    pub fn send_message(&self, obj: &LxpcObject) -> LxpcResult<()> {
        self.send_message_internal(obj, None)
    }

    /// Sendet eine Antwort auf eine empfangene Nachricht.
    /// Setzt automatisch `lxpc.reply_to` auf die ID der Anfrage.
    pub fn send_reply(&self, reply: &mut LxpcObject, to_msg_id: i64) -> LxpcResult<()> {
        self.send_message_internal(reply, Some(to_msg_id))
    }

    fn send_message_internal(&self, obj: &LxpcObject, reply_to: Option<i64>) -> LxpcResult<()> {
        // --- 1. Vorbereitung: Arbeitskopie mit injizierten System-Keys ---
        let mut working = obj.clone();
        let msg_id = next_msg_id();
        working.set_int64(KEY_MSG_ID, msg_id);
        if let Some(rt) = reply_to {
            working.set_int64(KEY_REPLY_TO, rt);
        }

        // --- 2. FD-Extraktion ---
        let mut fds_to_beam: Vec<RawFd> = Vec::new();
        collect_fds(&working.data, &mut fds_to_beam);

        if fds_to_beam.len() > LXPC_MAX_FDS_PER_MSG {
            return Err(LxpcError::MessageTooLarge(fds_to_beam.len() as u32));
        }

        // --- 3. CBOR-Serialisierung ---
        let mut payload = Vec::new();
        ciborium::into_writer(&working, &mut payload)
            .map_err(|e| LxpcError::Serialization(e.to_string()))?;

        let payload_len = payload.len() as u32;
        if payload_len > LXPC_MAX_MESSAGE_SIZE {
            return Err(LxpcError::MessageTooLarge(payload_len));
        }

        // --- 4. Header bauen (neues 12-Byte-Format) ---
        let header = encode_header(payload_len);

        // --- 5. Schreib-Lock holen (verhindert interleaved Writes) ---
        let _guard = self.write_lock.lock().unwrap();

        // --- 6. sendmsg: Header + Payload als Scatter/Gather, FDs als SCM_RIGHTS ---
        let iov = [IoSlice::new(&header), IoSlice::new(&payload)];
        let cmsgs: Vec<ControlMessage> = if !fds_to_beam.is_empty() {
            vec![ControlMessage::ScmRights(&fds_to_beam)]
        } else {
            vec![]
        };

        sendmsg::<()>(self.fd, &iov, &cmsgs, MsgFlags::empty(), None)
            .map_err(LxpcError::Nix)?;

        eprintln!("[lxpc DEBUG] Gesendet: msg_id={msg_id}, {payload_len} Bytes, {} FDs", fds_to_beam.len());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Empfangen (Lese-Thread)
    // -----------------------------------------------------------------------

    /// Startet den Hintergrund-Lese-Thread für diese Verbindung.
    /// Idempotent — zweiter Aufruf hat keine Wirkung.
    pub fn activate(&self) {
        let mut running = self.running.lock().unwrap();
        if *running { return; }
        *running = true;
        drop(running); // Lock freigeben bevor wir den Thread spawnen

        let fd              = self.fd;
        let handler_arc     = Arc::clone(&self.handler);
        let error_arc       = Arc::clone(&self.error_handler);
        let running_arc     = Arc::clone(&self.running);

        thread::spawn(move || {
            // UnixStream einmalig außerhalb der Schleife erzeugen.
            // mem::forget verhindert dass der Destruktor den FD schließt.
            let mut stream = unsafe { UnixStream::from_raw_fd(fd) };

            loop {
                match read_one_message(fd, &mut stream) {
                    Ok((obj, received_fds)) => {
                        // FD-Guard: schließt FDs falls der Handler panict
                        let guard = FdGuard::new(received_fds);

                        // Panic-Grenze: C-Handler-Abstürze dürfen den Lese-Thread nicht töten
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            // FDs konsumieren (Guard deaktivieren) bevor wir zu C gehen
                            let _fds = guard.take();
                            let obj_ptr = Box::into_raw(Box::new(obj));
                            if let Some(h) = *handler_arc.lock().unwrap() {
                                h(obj_ptr);
                                // HINWEIS: C-Code MUSS lxpc_object_release(obj_ptr) aufrufen!
                            } else {
                                // Kein Handler — Speicher selbst freigeben
                                unsafe { drop(Box::from_raw(obj_ptr)); }
                            }
                        }));

                        if let Err(e) = result {
                            eprintln!("[lxpc ERROR] Panic im Nachrichten-Handler: {e:?}");
                        }
                    }

                    Err(LxpcError::ConnectionClosed) => {
                        eprintln!("[lxpc DEBUG] Verbindung auf FD {fd} geschlossen");
                        fire_error(&error_arc, -1, "Verbindung geschlossen");
                        break;
                    }

                    Err(e) => {
                        eprintln!("[lxpc ERROR] Lesefehler auf FD {fd}: {e}");
                        fire_error(&error_arc, -2, &e.to_string());
                        break;
                    }
                }
            }

            // Aufräumen: running-Flag zurücksetzen
            *running_arc.lock().unwrap() = false;
            // stream wird jetzt gedroppt → FD wird geschlossen
        });
    }
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen (intern)
// ---------------------------------------------------------------------------

/// Liest genau eine LXPC-Nachricht vom Socket.
/// Gibt das fertige Objekt UND die empfangenen FDs zurück.
fn read_one_message(fd: RawFd, stream: &mut UnixStream) -> LxpcResult<(LxpcObject, Vec<RawFd>)> {
    // --- Header lesen via recvmsg (fängt auch SCM_RIGHTS auf) ---
    let mut header_buf = [0u8; HEADER_SIZE];
    let mut cmsg_space = nix::cmsg_space!([RawFd; LXPC_MAX_FDS_PER_MSG]);
    let mut iov = [IoSliceMut::new(&mut header_buf)];

    let msg = recvmsg::<()>(fd, &mut iov, Some(&mut cmsg_space), MsgFlags::empty())
        .map_err(LxpcError::Nix)?;

    if msg.bytes == 0 {
        return Err(LxpcError::ConnectionClosed);
    }

    // --- FDs aus Ancillary Data extrahieren (sofort in Guard) ---
    let mut raw_fds = Vec::new();
    if let Ok(cmsg_iter) = msg.cmsgs() {
        for cmsg in cmsg_iter {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                raw_fds.extend(fds);
            }
        }
    }
    let fd_guard = FdGuard::new(raw_fds);

    // --- Header validieren (Magic, Version, Größe) ---
    let payload_len = decode_header(&header_buf)?;

    // --- Payload lesen ---
    // read_exact liest exakt so viele Bytes wie angekündigt.
    // Weitere Nachrichten im Kernel-Puffer bleiben dort bis zur nächsten Iteration.
    let mut payload = vec![0u8; payload_len as usize];
    stream.read_exact(&mut payload).map_err(LxpcError::Io)?;

    // --- CBOR deserialisieren ---
    let obj: LxpcObject = ciborium::from_reader(&payload[..])
        .map_err(|e| LxpcError::Serialization(e.to_string()))?;

    // Alles erfolgreich — FDs konsumieren (nicht schließen)
    let fds = fd_guard.take();

    Ok((obj, fds))
}

/// Rekursiv alle FDs aus einem Dictionary sammeln.
fn collect_fds(map: &HashMap<String, LxpcValue>, out: &mut Vec<RawFd>) {
    for val in map.values() {
        match val {
            LxpcValue::Fd(fd) => out.push(*fd),
            LxpcValue::Dictionary(inner) => collect_fds(inner, out),
            LxpcValue::Array(arr) => collect_fds_array(arr, out),
            _ => {}
        }
    }
}

fn collect_fds_array(arr: &[LxpcValue], out: &mut Vec<RawFd>) {
    for val in arr {
        match val {
            LxpcValue::Fd(fd) => out.push(*fd),
            LxpcValue::Dictionary(inner) => collect_fds(inner, out),
            LxpcValue::Array(inner) => collect_fds_array(inner, out),
            _ => {}
        }
    }
}

/// Feuert den Error-Handler mit einem C-kompatiblen Fehlercode und einer Nachricht.
fn fire_error(error_arc: &Arc<Mutex<Option<ErrorHandler>>>, code: i32, msg: &str) {
    if let Some(h) = *error_arc.lock().unwrap() {
        // CString erzeugen — Null-Bytes werden durch '?' ersetzt
        let c_msg = std::ffi::CString::new(msg.replace('\0', "?")).unwrap();
        h(code, c_msg.as_ptr());
    }
}

// ---------------------------------------------------------------------------
// Bootstrap-Prüfung
// ---------------------------------------------------------------------------

/// Prüft fälschungssicher via Kernel ob FD 3 wirklich von syscored (PID 1, UID 0) kommt.
///
/// Rückgabewerte:
///  0  — OK
/// -1  — FD 3 ist kein Socket oder existiert nicht
/// -3  — Gegenstelle ist nicht PID 1
/// -4  — Gegenstelle läuft nicht als root (UID 0)
pub fn bootstrap_check() -> i32 {
    #[cfg(feature = "disable_pid_check")]
    {
        eprintln!("[lxpc WARN]  ACHTUNG: bootstrap_check deaktiviert (disable_pid_check Feature)!");
        return 0;
    }

    let fd = unsafe { BorrowedFd::borrow_raw(BOOTSTRAP_FD) };

    #[cfg(target_os = "linux")]
    {
        match getsockopt(&fd, PeerCredentials) {
            Ok(creds) => {
                if creds.pid() != 1 {
                    eprintln!("[lxpc ERROR] bootstrap_check: Gegenstelle ist PID {} (erwartet: 1)", creds.pid());
                    return -3;
                }
                if creds.uid() != 0 {
                    eprintln!("[lxpc ERROR] bootstrap_check: Gegenstelle läuft als UID {} (erwartet: 0)", creds.uid());
                    return -4;
                }
                0
            }
            Err(e) => {
                eprintln!("[lxpc ERROR] bootstrap_check: getsockopt fehlgeschlagen: {e}");
                -1
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        match getsockopt(&fd, LocalPeerPid) {
            Ok(pid) => {
                if pid != 1 {
                    eprintln!("[lxpc ERROR] bootstrap_check: Gegenstelle ist PID {pid} (erwartet: 1)");
                    return -3;
                }
                0
            }
            Err(e) => {
                eprintln!("[lxpc ERROR] bootstrap_check: getsockopt fehlgeschlagen: {e}");
                -1
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    { 0 }
}

// ---------------------------------------------------------------------------
// run_main — Daemon-Hauptschleife
// ---------------------------------------------------------------------------

/// Daemon-Einstiegspunkt. Ersetzt die C-main().
/// Blockiert bis syscored die Verbindung schließt.
pub fn run_main(
    handler: extern "C" fn(*mut LxpcConnection),
    event_handler: Option<extern "C" fn(*mut LxpcObject)>,
) {
    if bootstrap_check() != 0 {
        eprintln!("[lxpc ERROR] run_main: bootstrap_check fehlgeschlagen — Prozess wird beendet");
        std::process::exit(1);
    }

    // Stream einmalig außerhalb der Schleife erzeugen
    let mut stream = unsafe { UnixStream::from_raw_fd(BOOTSTRAP_FD) };

    loop {
        let mut header_buf = [0u8; HEADER_SIZE];
        let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
        let mut iov = [IoSliceMut::new(&mut header_buf)];

        match recvmsg::<()>(BOOTSTRAP_FD, &mut iov, Some(&mut cmsg_space), MsgFlags::empty()) {
            Ok(msg) if msg.bytes > 0 => {
                let mut got_client = false;

                // --- FALL A: Neuer Client-FD via SCM_RIGHTS ---
                if let Ok(cmsg_iter) = msg.cmsgs() {
                    for cmsg in cmsg_iter {
                        if let ControlMessageOwned::ScmRights(fds) = cmsg {
                            for client_fd in fds {
                                eprintln!("[lxpc DEBUG] run_main: Neuer Client auf FD {client_fd}");
                                let conn = Box::into_raw(Box::new(LxpcConnection::new(client_fd)));
                                handler(conn);
                                got_client = true;
                            }
                        }
                    }
                }

                // --- FALL B: Steuerbefehl von syscored ---
                if !got_client {
                    match decode_header(&header_buf) {
                        Ok(length) if length > 0 => {
                            let mut payload = vec![0u8; length as usize];
                            if stream.read_exact(&mut payload).is_ok() {
                                match ciborium::from_reader::<LxpcObject, _>(&payload[..]) {
                                    Ok(obj) => {
                                        if let Some(h) = event_handler {
                                            h(Box::into_raw(Box::new(obj)));
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[lxpc ERROR] run_main: CBOR-Deserialisierung fehlgeschlagen: {e}");
                                    }
                                }
                            }
                        }
                        Ok(_) => {} // length == 0, ignorieren
                        Err(e) => {
                            eprintln!("[lxpc ERROR] run_main: Ungültiger Header: {e}");
                        }
                    }
                }
            }

            // Verbindung geschlossen oder Fehler → sauber beenden
            Ok(_) => {
                eprintln!("[lxpc DEBUG] run_main: Bootstrap-Socket geschlossen (0 Bytes)");
                break;
            }
            Err(e) => {
                eprintln!("[lxpc ERROR] run_main: recvmsg fehlgeschlagen: {e}");
                break;
            }
        }
    }

    // stream wird jetzt gedroppt — FD wird geschlossen
}

// ---------------------------------------------------------------------------
// connect_to_service — Client-Routing
// ---------------------------------------------------------------------------

/// Verbindet einen Client mit einem benannten Dienst via syscored.
///
/// Rückgabe: `Ok(RawFd)` — Socket zur direkten Kommunikation mit dem Dienst
///           `Err(LxpcError)` — mit explizitem Fehlergrund
pub fn connect_to_service(name: &str) -> LxpcResult<RawFd> {
    // Pfad zur Kompilierzeit einbrennen, Fallback auf Default
    const SOCKET_PATH: &str = match option_env!("SYSCORED_PATH") {
        Some(path) => path,
        None => "/run/syscored.sock",
    };

    let stream = UnixStream::connect(SOCKET_PATH)
        .map_err(LxpcError::Io)?;

    let fd = stream.as_raw_fd();

    // Routing-Anfrage an syscored
    let mut routing_msg = LxpcObject::new_dictionary();
    routing_msg.set_string("lxpc_bootstrap_target", name);

    let temp_conn = LxpcConnection::new(fd);
    temp_conn.send_message(&routing_msg)?;

    // fd bleibt offen — stream nicht droppen
    std::mem::forget(stream);

    eprintln!("[lxpc DEBUG] connect_to_service: Verbunden mit '{name}' via {SOCKET_PATH}");
    Ok(fd)
}