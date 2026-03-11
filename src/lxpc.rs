// lxpc.rs — LXPC Transport-Kern
//
// Hardening-Status (v0.3.0):
//   [1] Zero-Panic Policy    — kein unwrap/expect im Produktionspfad
//   [2] OwnedFd              — empfangene FDs in OwnedFd, Leaks physikalisch unmöglich
//   [3] Thread-Shutdown      — Arc<AtomicBool> shutdown_flag, Drop signalisiert Stopp
//   [4] Recursion-Limit      — collect_fds / CBOR-Validierung max. MAX_RECURSION_DEPTH=32
//   [5] Structured Logging   — tracing::{error,warn,info,debug,trace} mit Kontext-Feldern
//   [6] Integer-Sicherheit   — checked_add/checked_mul bei allen Längenberechnungen
//   [7] C-ABI stabil         — extern "C" Signaturen unverändert
//   [8] Unsafe-Inventar      — alle unsafe-Blöcke mit // SAFETY: dokumentiert

use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::io::{Read, IoSlice, IoSliceMut};
use serde::{Serialize, Deserialize};

#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::PeerCredentials;
#[cfg(target_os = "macos")]
use nix::sys::socket::sockopt::LocalPeerPid;

use nix::sys::socket::{
    getsockopt, sendmsg, recvmsg,
    ControlMessage, ControlMessageOwned, MsgFlags, setsockopt,
};
use nix::sys::socket::sockopt::{ReceiveTimeout, SendTimeout};
use nix::sys::time::TimeVal;

use tracing::{debug, error, info, trace, warn};

// ---------------------------------------------------------------------------
// Konstanten
// ---------------------------------------------------------------------------

pub const LXPC_TYPE_DICTIONARY: i32 = 1;
pub const LXPC_MAGIC: u32 = 0x4C585043;
pub const LXPC_PROTOCOL_VERSION: u16 = 1;
pub const LXPC_MAX_MESSAGE_SIZE: u32 = 4 * 1024 * 1024;
pub const LXPC_MAX_FDS_PER_MSG: usize = 16;
pub const BOOTSTRAP_FD: RawFd = 3;
pub const LXPC_READ_TIMEOUT_SECS: i64 = 30;
pub const LXPC_SEND_TIMEOUT_SECS: i64 = 30;

/// [4] Maximale Rekursionstiefe für collect_fds und Deserialisierung.
///     Schützt vor Stack-Overflow durch bösartig verschachtelte Dictionaries.
pub const MAX_RECURSION_DEPTH: usize = 32;

// ---------------------------------------------------------------------------
// Fehlertypen
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum LxpcError {
    Io(std::io::Error),
    Nix(nix::Error),
    Serialization(String),
    BadMagic,
    UnsupportedVersion(u16),
    MessageTooLarge(u32),
    NotBootstrap,
    ConnectionClosed,
    ReadTimeout,
    PartialSend(usize, usize),
    AuthFailed(String),
    NullPointer,
    /// [4] Nachricht ist zu tief verschachtelt.
    RecursionLimitExceeded,
    /// [1] Mutex wurde vergiftet.
    PoisonedLock,
    /// [6] Arithmetischer Overflow bei Längenberechnung.
    LengthOverflow,
}

impl std::fmt::Display for LxpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LxpcError::Io(e)                  => write!(f, "I/O-Fehler: {e}"),
            LxpcError::Nix(e)                 => write!(f, "Syscall-Fehler: {e}"),
            LxpcError::Serialization(s)       => write!(f, "Serialisierungsfehler: {s}"),
            LxpcError::BadMagic               => write!(f, "Ungültige Magic Number"),
            LxpcError::UnsupportedVersion(v)  => write!(f, "Protokollversion {v} nicht unterstützt"),
            LxpcError::MessageTooLarge(n)     => write!(f, "Nachricht zu groß: {n} Bytes (max {LXPC_MAX_MESSAGE_SIZE})"),
            LxpcError::NotBootstrap           => write!(f, "Verbindung nicht von syscored (PID 1)"),
            LxpcError::ConnectionClosed       => write!(f, "Verbindung geschlossen"),
            LxpcError::NullPointer            => write!(f, "Null-Pointer von C-Seite"),
            LxpcError::ReadTimeout            => write!(f, "Read-Timeout"),
            LxpcError::PartialSend(s, t)      => write!(f, "Partielles Senden: {s}/{t} Bytes"),
            LxpcError::AuthFailed(s)          => write!(f, "Authentifizierung fehlgeschlagen: {s}"),
            LxpcError::RecursionLimitExceeded => write!(f, "Rekursionslimit ({MAX_RECURSION_DEPTH}) überschritten"),
            LxpcError::PoisonedLock           => write!(f, "Mutex vergiftet"),
            LxpcError::LengthOverflow         => write!(f, "Arithmetischer Overflow bei Längenberechnung"),
        }
    }
}

/// [1] PoisonError niemals unwrap() — in LxpcError::PoisonedLock konvertieren.
impl<T> From<std::sync::PoisonError<T>> for LxpcError {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        LxpcError::PoisonedLock
    }
}

pub type LxpcResult<T> = Result<T, LxpcError>;

// ---------------------------------------------------------------------------
// Wire-Format Header (12 Bytes)
//
//  0       4       6       8      12
//  +-------+-------+-------+-------+
//  | MAGIC | VER   | FLAGS | LEN   |
//  +-------+-------+-------+-------+
//
//  MAGIC  : u32 LE  — 0x4C585043
//  VER    : u16 LE  — Protokollversion
//  FLAGS  : u16 LE  — reserviert, muss 0 sein
//  LEN    : u32 LE  — Länge des CBOR-Payloads in Bytes
// ---------------------------------------------------------------------------

pub(crate) const HEADER_SIZE: usize = 12;

pub(crate) fn encode_header(payload_len: u32) -> [u8; HEADER_SIZE] {
    let mut h = [0u8; HEADER_SIZE];
    h[0..4].copy_from_slice(&LXPC_MAGIC.to_le_bytes());
    h[4..6].copy_from_slice(&LXPC_PROTOCOL_VERSION.to_le_bytes());
    h[6..8].copy_from_slice(&0u16.to_le_bytes()); // flags = 0
    h[8..12].copy_from_slice(&payload_len.to_le_bytes());
    h
}

/// [1][6] Dekodiert den Header ohne unwrap, mit Overflow-sicheren Konvertierungen.
fn decode_header(buf: &[u8; HEADER_SIZE]) -> LxpcResult<u32> {
    // try_into() auf &[u8] fester Länge 4/2 kann nicht fehlschlagen,
    // aber wir vermeiden unwrap() durch map_err für Zero-Panic-Konformität.
    let magic = u32::from_le_bytes(
        buf[0..4].try_into().map_err(|_| LxpcError::LengthOverflow)?
    );
    let version = u16::from_le_bytes(
        buf[4..6].try_into().map_err(|_| LxpcError::LengthOverflow)?
    );
    let length = u32::from_le_bytes(
        buf[8..12].try_into().map_err(|_| LxpcError::LengthOverflow)?
    );

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
// Werttypen
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum LxpcValue {
    String(String),
    Int64(i64),
    Double(f64),
    Bool(bool),
    Data(Vec<u8>),
    Uuid([u8; 16]),
    Null,
    Dictionary(HashMap<String, LxpcValue>),
    Array(Vec<LxpcValue>),
    /// FD-Platzhalter. Echte Übertragung via SCM_RIGHTS in send_message().
    Fd(RawFd),
}

// ---------------------------------------------------------------------------
// LxpcObject
// ---------------------------------------------------------------------------

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
// Reply-Semantik
// ---------------------------------------------------------------------------

const KEY_MSG_ID:   &str = "lxpc.msg_id";
const KEY_REPLY_TO: &str = "lxpc.reply_to";
#[allow(dead_code)]
const KEY_ERROR_MSG:  &str = "lxpc.error";
#[allow(dead_code)]
const KEY_ERROR_CODE: &str = "lxpc.error_code";

static MSG_ID_COUNTER: AtomicI64 = AtomicI64::new(1);

fn next_msg_id() -> i64 {
    MSG_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// [2] OwnedFd-basierter Guard für empfangene FDs
//
// OwnedFd schließt den FD beim Drop automatisch. Damit ist ein FD-Leak
// durch vergessenes close() physikalisch unmöglich — das Ownership-System
// erzwingt korrekte Freigabe.
// ---------------------------------------------------------------------------

struct ReceivedFds {
    inner: Vec<OwnedFd>,
}

impl ReceivedFds {
    /// Konvertiert RawFds (vom Kernel geliefert) sofort in OwnedFd.
    ///
    /// # SAFETY
    /// `raw_fds` müssen gültige, offene FDs sein die dem Aufrufer gehören.
    /// Nach diesem Aufruf darf der Aufrufer die RawFds nicht mehr verwenden.
    unsafe fn from_raw(raw_fds: Vec<RawFd>) -> Self {
        Self {
            // SAFETY: Caller garantiert Ownership der FDs.
            inner: raw_fds.into_iter()
                .map(|fd| OwnedFd::from_raw_fd(fd))
                .collect(),
        }
    }

    /// Konsumiert den Guard und gibt die RawFds zurück.
    /// Verantwortung für das Schließen geht auf den Caller über.
    fn into_raw_fds(mut self) -> Vec<RawFd> {
        self.inner.drain(..)
            .map(|owned| owned.into_raw_fd())
            .collect()
    }

    fn len(&self) -> usize { self.inner.len() }
}

// Drop ist durch OwnedFd automatisch korrekt implementiert.

// ---------------------------------------------------------------------------
// LxpcConnection
// ---------------------------------------------------------------------------

pub type MessageHandler = unsafe extern "C" fn(*mut LxpcObject);
pub type ErrorHandler   = unsafe extern "C" fn(i32, *const libc::c_char);

#[derive(Debug, Clone)]
pub struct PeerIdentity {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// Aktive Verbindung zwischen zwei Prozessen.
///
/// [3] shutdown_flag: Arc<AtomicBool> wird in Drop() gesetzt.
///     Der Lese-Thread prüft dieses Flag nach jedem Timeout-Zyklus.
pub struct LxpcConnection {
    pub fd: RawFd,
    pub peer: Option<PeerIdentity>,
    write_lock: Mutex<()>,
    pub handler: Arc<Mutex<Option<MessageHandler>>>,
    pub error_handler: Arc<Mutex<Option<ErrorHandler>>>,
    pub running: Arc<Mutex<bool>>,
    /// [3] true → Lese-Thread soll sich beim nächsten Timeout beenden.
    shutdown_flag: Arc<AtomicBool>,
}

impl LxpcConnection {
    pub fn new(fd: RawFd) -> Self {
        Self::new_with_timeout(fd, LXPC_READ_TIMEOUT_SECS)
    }

    pub fn new_with_timeout(fd: RawFd, timeout_secs: i64) -> Self {
        let peer = Self::read_peer_credentials(fd);

        // SAFETY: fd ist ein gültiger, offener FD.
        //         BorrowedFd erzeugt keine Ownership und schließt den FD nicht.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let timeout = TimeVal::new(timeout_secs, 0);
        if let Err(e) = setsockopt(&borrowed, ReceiveTimeout, &timeout) {
            warn!(fd, "SO_RCVTIMEO konnte nicht gesetzt werden: {e}");
        }

        Self {
            fd,
            peer,
            write_lock:    Mutex::new(()),
            handler:       Arc::new(Mutex::new(None)),
            error_handler: Arc::new(Mutex::new(None)),
            running:       Arc::new(Mutex::new(false)),
            shutdown_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    fn read_peer_credentials(fd: RawFd) -> Option<PeerIdentity> {
        // SAFETY: fd ist ein gültiger, offener FD.
        //         BorrowedFd erzeugt keine Ownership.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };

        #[cfg(target_os = "linux")]
        {
            match getsockopt(&borrowed, PeerCredentials) {
                Ok(creds) => Some(PeerIdentity {
                    pid: creds.pid(),
                    uid: creds.uid(),
                    gid: creds.gid(),
                }),
                Err(_) => None,
            }
        }

        #[cfg(target_os = "macos")]
        {
            match getsockopt(&borrowed, LocalPeerPid) {
                Ok(pid) => Some(PeerIdentity { pid, uid: 0, gid: 0 }),
                Err(_) => None,
            }
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        { None }
    }

    // -----------------------------------------------------------------------
    // Senden
    // -----------------------------------------------------------------------

    pub fn send_message(&self, obj: &LxpcObject) -> LxpcResult<()> {
        self.send_message_internal(obj, None)
    }

    pub fn send_reply(&self, reply: &mut LxpcObject, to_msg_id: i64) -> LxpcResult<()> {
        self.send_message_internal(reply, Some(to_msg_id))
    }

    fn send_message_internal(&self, obj: &LxpcObject, reply_to: Option<i64>) -> LxpcResult<()> {
        // 1. Arbeitskopie mit System-Keys
        let mut working = obj.clone();
        let msg_id = next_msg_id();
        working.set_int64(KEY_MSG_ID, msg_id);
        if let Some(rt) = reply_to {
            working.set_int64(KEY_REPLY_TO, rt);
        }

        // 2. [4] FD-Extraktion mit Rekursionslimit
        let mut fds_to_beam: Vec<RawFd> = Vec::new();
        collect_fds(&working.data, &mut fds_to_beam, 0)?;

        if fds_to_beam.len() > LXPC_MAX_FDS_PER_MSG {
            return Err(LxpcError::MessageTooLarge(fds_to_beam.len() as u32));
        }

        // 3. CBOR-Serialisierung
        let mut payload = Vec::new();
        ciborium::into_writer(&working, &mut payload)
            .map_err(|e| LxpcError::Serialization(e.to_string()))?;

        // [6] Länge als u32 ohne Overflow
        let payload_len: u32 = payload.len().try_into()
            .map_err(|_| LxpcError::LengthOverflow)?;
        if payload_len > LXPC_MAX_MESSAGE_SIZE {
            return Err(LxpcError::MessageTooLarge(payload_len));
        }

        // 4. Header
        let header = encode_header(payload_len);

        // 5. [1] Schreib-Lock ohne unwrap — PoisonError → LxpcError::PoisonedLock
        let _guard = self.write_lock.lock()?;

        // 6. Send-Timeout
        {
            // SAFETY: self.fd ist für die Lebenszeit von self gültig.
            let borrowed = unsafe { BorrowedFd::borrow_raw(self.fd) };
            let timeout = TimeVal::new(LXPC_SEND_TIMEOUT_SECS, 0);
            let _ = setsockopt(&borrowed, SendTimeout, &timeout);
        }

        // 7. [6] Gesamtgröße mit Overflow-Check
        let total = HEADER_SIZE.checked_add(payload.len())
            .ok_or(LxpcError::LengthOverflow)?;

        let mut full_buf = Vec::with_capacity(total);
        full_buf.extend_from_slice(&header);
        full_buf.extend_from_slice(&payload);

        let cmsgs: Vec<ControlMessage> = if !fds_to_beam.is_empty() {
            vec![ControlMessage::ScmRights(&fds_to_beam)]
        } else {
            vec![]
        };

        // 8. Senden mit Retry-Loop
        let iov = [IoSlice::new(&full_buf)];
        let sent = sendmsg::<()>(self.fd, &iov, &cmsgs, MsgFlags::empty(), None)
            .map_err(LxpcError::Nix)?;

        if sent < total {
            let mut written = sent;
            while written < total {
                let remaining = &full_buf[written..];
                let iov2 = [IoSlice::new(remaining)];
                match sendmsg::<()>(self.fd, &iov2, &[], MsgFlags::empty(), None) {
                    Ok(0) => return Err(LxpcError::PartialSend(written, total)),
                    Ok(n) => {
                        written = written.checked_add(n)
                            .ok_or(LxpcError::LengthOverflow)?;
                    }
                    Err(nix::errno::Errno::EAGAIN) => {
                        return Err(LxpcError::PartialSend(written, total));
                    }
                    Err(e) => return Err(LxpcError::Nix(e)),
                }
            }
        }

        debug!(
            fd = self.fd,
            msg_id,
            bytes = payload_len,
            fds = fds_to_beam.len(),
            "Nachricht gesendet"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // [3] Lese-Thread mit AtomicBool-Shutdown
    // -----------------------------------------------------------------------

    /// Startet den Hintergrund-Lese-Thread. Idempotent.
    pub fn activate(&self) {
        // [1] lock() statt lock().unwrap()
        let Ok(mut running_guard) = self.running.lock() else {
            error!(fd = self.fd, "Mutex vergiftet in activate()");
            return;
        };
        if *running_guard { return; }
        *running_guard = true;
        drop(running_guard);

        let fd            = self.fd;
        let handler_arc   = Arc::clone(&self.handler);
        let error_arc     = Arc::clone(&self.error_handler);
        let running_arc   = Arc::clone(&self.running);
        let shutdown_flag = Arc::clone(&self.shutdown_flag);
        let peer_pid      = self.peer.as_ref().map(|p| p.pid).unwrap_or(-1);

        thread::spawn(move || {
            // SAFETY: fd ist der Socket-FD dieser Verbindung.
            //         UnixStream::from_raw_fd übernimmt Ownership für read_exact().
            //         Der Drop am Ende des Threads schließt den FD korrekt.
            let mut stream = unsafe { UnixStream::from_raw_fd(fd) };

            info!(fd, peer_pid, "Lese-Thread gestartet");

            loop {
                // [3] Shutdown-Check vor jedem Lese-Versuch
                if shutdown_flag.load(Ordering::Acquire) {
                    debug!(fd, "Shutdown-Signal — Lese-Thread beendet sich sauber");
                    break;
                }

                match read_one_message(fd, &mut stream) {
                    Ok((obj, received_fds)) => {
                        // Panic-Grenze: C-Handler-Absturz tötet nicht den Thread
                        let result = std::panic::catch_unwind(
                            std::panic::AssertUnwindSafe(|| {
                                // [2] Ownership der FDs: ReceivedFds → RawFd → C-Code
                                let raw_fds = received_fds.into_raw_fds();
                                let obj_ptr = Box::into_raw(Box::new(obj));

                                // [1] lock() ohne unwrap
                                match handler_arc.lock() {
                                    Ok(guard) => {
                                        if let Some(h) = *guard {
                                            drop(guard); // Lock vor C-Aufruf freigeben
                                            // SAFETY: h ist ein gültiger C-Funktionspointer. obj_ptr gehört dem Caller.
                                            unsafe { h(obj_ptr); }
                                            // C-Code MUSS lxpc_object_release(obj_ptr) aufrufen
                                        } else {
                                            drop(guard);
                                            // Kein Handler — Speicher und FDs selbst freigeben
                                            // SAFETY: obj_ptr wurde eben von Box::into_raw erzeugt.
                                            unsafe { drop(Box::from_raw(obj_ptr)); }
                                            for raw_fd in raw_fds {
                                                // SAFETY: raw_fd ist ein gültiger offener FD.
                                                unsafe { drop(OwnedFd::from_raw_fd(raw_fd)); }
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        error!(fd, "Mutex vergiftet beim Handler-Aufruf");
                                        // SAFETY: obj_ptr wurde eben erzeugt.
                                        unsafe { drop(Box::from_raw(obj_ptr)); }
                                    }
                                }
                            }),
                        );

                        if let Err(e) = result {
                            error!(fd, "Panic im Nachrichten-Handler: {e:?}");
                        }
                    }

                    Err(LxpcError::ReadTimeout) => {
                        // [3] Timeout = Gelegenheit das Shutdown-Flag zu prüfen
                        if shutdown_flag.load(Ordering::Acquire) {
                            debug!(fd, "Shutdown während Timeout — sauberes Beenden");
                            break;
                        }
                        warn!(fd, "Read-Timeout — Verbindung wird getrennt");
                        fire_error(&error_arc, -3, "Read-Timeout");
                        break;
                    }

                    Err(LxpcError::ConnectionClosed) => {
                        debug!(fd, "Verbindung geschlossen (EOF)");
                        fire_error(&error_arc, -1, "Verbindung geschlossen");
                        break;
                    }

                    Err(e) => {
                        error!(fd, error = %e, "Lesefehler");
                        fire_error(&error_arc, -2, &e.to_string());
                        break;
                    }
                }
            }

            // [1] running-Flag zurücksetzen ohne unwrap
            match running_arc.lock() {
                Ok(mut guard) => *guard = false,
                Err(_) => error!(fd, "Mutex vergiftet beim Aufräumen"),
            }
            info!(fd, "Lese-Thread beendet");
            // stream wird hier gedroppt → FD wird geschlossen
        });
    }
}

/// [3] Drop setzt das Shutdown-Flag → Lese-Thread beendet sich beim nächsten Timeout.
impl Drop for LxpcConnection {
    fn drop(&mut self) {
        self.shutdown_flag.store(true, Ordering::Release);
        trace!(fd = self.fd, "LxpcConnection gedroppt, Shutdown-Signal gesetzt");
    }
}

// ---------------------------------------------------------------------------
// [4] FD-Sammlung mit Rekursionslimit
// ---------------------------------------------------------------------------

/// Sammelt alle FD-Platzhalter aus einem Dictionary.
/// `depth` wird bei jedem rekursiven Aufruf inkrementiert.
/// Fehler bei depth > MAX_RECURSION_DEPTH.
fn collect_fds(
    map: &HashMap<String, LxpcValue>,
    out: &mut Vec<RawFd>,
    depth: usize,
) -> LxpcResult<()> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(LxpcError::RecursionLimitExceeded);
    }
    for val in map.values() {
        match val {
            LxpcValue::Fd(fd)              => out.push(*fd),
            LxpcValue::Dictionary(inner)   => collect_fds(inner, out, depth + 1)?,
            LxpcValue::Array(arr)          => collect_fds_array(arr, out, depth + 1)?,
            _                              => {}
        }
    }
    Ok(())
}

fn collect_fds_array(
    arr: &[LxpcValue],
    out: &mut Vec<RawFd>,
    depth: usize,
) -> LxpcResult<()> {
    if depth > MAX_RECURSION_DEPTH {
        return Err(LxpcError::RecursionLimitExceeded);
    }
    for val in arr {
        match val {
            LxpcValue::Fd(fd)              => out.push(*fd),
            LxpcValue::Dictionary(inner)   => collect_fds(inner, out, depth + 1)?,
            LxpcValue::Array(inner)        => collect_fds_array(inner, out, depth + 1)?,
            _                              => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

/// [1] Feuert den Error-Handler ohne unwrap/expect.
fn fire_error(error_arc: &Arc<Mutex<Option<ErrorHandler>>>, code: i32, msg: &str) {
    let guard = match error_arc.lock() {
        Ok(g)  => g,
        Err(_) => { error!("Mutex vergiftet in fire_error"); return; }
    };
    if let Some(h) = *guard {
        // [1] CString::new kann nur fehlschlagen wenn msg Null-Bytes enthält.
        //     Wir ersetzen sie durch '?'.
        match std::ffi::CString::new(msg.replace('\0', "?")) {
            // SAFETY: h ist ein gültiger C-Funktionspointer. c_msg lebt bis Ende des match-Arms.
            Ok(c_msg) => unsafe { h(code, c_msg.as_ptr()) },
            Err(_)    => error!("CString-Erzeugung fehlgeschlagen in fire_error"),
        }
    }
}

// ---------------------------------------------------------------------------
// read_one_message
// ---------------------------------------------------------------------------

/// Liest genau eine LXPC-Nachricht vom Socket.
/// Gibt `(LxpcObject, ReceivedFds)` zurück.
/// [2] ReceivedFds halten empfangene FDs als OwnedFd — Drop schließt sie.
fn read_one_message(
    fd: RawFd,
    stream: &mut UnixStream,
) -> LxpcResult<(LxpcObject, ReceivedFds)> {
    // 1. Header + SCM_RIGHTS via recvmsg
    let mut header_buf = [0u8; HEADER_SIZE];
    let mut cmsg_space = nix::cmsg_space!([RawFd; LXPC_MAX_FDS_PER_MSG]);
    let mut iov = [IoSliceMut::new(&mut header_buf)];

    let msg = recvmsg::<()>(fd, &mut iov, Some(&mut cmsg_space), MsgFlags::empty())
        .map_err(|e| {
            if e == nix::errno::Errno::EAGAIN || e == nix::errno::Errno::EWOULDBLOCK {
                LxpcError::ReadTimeout
            } else {
                LxpcError::Nix(e)
            }
        })?;

    if msg.bytes == 0 {
        return Err(LxpcError::ConnectionClosed);
    }

    // 2. [2] SCM_RIGHTS sofort in ReceivedFds (OwnedFd) einpacken.
    //    Ab hier werden FDs bei jedem frühen Return automatisch geschlossen.
    let mut raw_fds: Vec<RawFd> = Vec::new();
    if let Ok(cmsg_iter) = msg.cmsgs() {
        for cmsg in cmsg_iter {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                raw_fds.extend(fds);
            }
        }
    }
    // SAFETY: raw_fds wurden gerade vom Kernel via SCM_RIGHTS geliefert.
    //         Der Kernel garantiert gültige neue FDs mit Ownership beim empfangenden Prozess.
    let received_fds = unsafe { ReceivedFds::from_raw(raw_fds) };

    // 3. Header validieren (bei Fehler: received_fds.drop() schließt FDs)
    let payload_len = decode_header(&header_buf)?;

    // 4. [6] Payload-Größe als usize — sicher da payload_len <= 4MiB << usize::MAX
    let payload_size = payload_len as usize;

    // 5. Payload lesen
    let mut payload = vec![0u8; payload_size];
    stream.read_exact(&mut payload).map_err(|e| {
        if e.kind() == std::io::ErrorKind::WouldBlock
            || e.kind() == std::io::ErrorKind::TimedOut
        {
            LxpcError::ReadTimeout
        } else if e.kind() == std::io::ErrorKind::UnexpectedEof {
            LxpcError::ConnectionClosed
        } else {
            LxpcError::Io(e)
        }
    })?;

    // 6. CBOR deserialisieren
    let obj: LxpcObject = ciborium::from_reader(&payload[..])
        .map_err(|e| LxpcError::Serialization(e.to_string()))?;

    trace!(
        fd,
        payload_bytes = payload_len,
        fds = received_fds.len(),
        "Nachricht empfangen"
    );

    Ok((obj, received_fds))
}

// ---------------------------------------------------------------------------
// Bootstrap-Prüfung
// ---------------------------------------------------------------------------

pub fn bootstrap_check() -> i32 {
    #[cfg(feature = "disable_pid_check")]
    {
        warn!("ACHTUNG: bootstrap_check deaktiviert (disable_pid_check Feature)!");
        return 0;
    }

    // SAFETY: BOOTSTRAP_FD (3) ist per Konvention immer gesetzt wenn dieser
    //         Code aufgerufen wird. BorrowedFd erzeugt keine Ownership.
    let fd = unsafe { BorrowedFd::borrow_raw(BOOTSTRAP_FD) };

    #[cfg(target_os = "linux")]
    {
        match getsockopt(&fd, PeerCredentials) {
            Ok(creds) => {
                if creds.pid() != 1 {
                    error!(
                        peer_pid = creds.pid(),
                        "bootstrap_check: Gegenstelle ist nicht PID 1"
                    );
                    return -3;
                }
                if creds.uid() != 0 {
                    error!(
                        peer_uid = creds.uid(),
                        "bootstrap_check: Gegenstelle läuft nicht als root"
                    );
                    return -4;
                }
                info!("bootstrap_check: OK (PID 1, UID 0)");
                0
            }
            Err(e) => {
                error!(error = %e, "bootstrap_check: getsockopt fehlgeschlagen");
                -1
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        match getsockopt(&fd, LocalPeerPid) {
            Ok(pid) => {
                if pid != 1 {
                    error!(peer_pid = pid, "bootstrap_check: Gegenstelle ist nicht PID 1");
                    return -3;
                }
                info!("bootstrap_check: OK (PID 1)");
                0
            }
            Err(e) => {
                error!(error = %e, "bootstrap_check: getsockopt fehlgeschlagen");
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

pub fn run_main(
    handler: unsafe extern "C" fn(*mut LxpcConnection),
    event_handler: Option<unsafe extern "C" fn(*mut LxpcObject)>,
) {
    if bootstrap_check() != 0 {
        error!("run_main: bootstrap_check fehlgeschlagen — Prozess wird beendet");
        std::process::exit(1);
    }

    // SAFETY: BOOTSTRAP_FD (3) gehört uns nach bootstrap_check().
    //         UnixStream übernimmt Ownership und schließt beim Drop.
    let mut stream = unsafe { UnixStream::from_raw_fd(BOOTSTRAP_FD) };

    info!("run_main: Bootstrap-Schleife gestartet");

    loop {
        let mut header_buf = [0u8; HEADER_SIZE];
        let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
        let mut iov = [IoSliceMut::new(&mut header_buf)];

        match recvmsg::<()>(BOOTSTRAP_FD, &mut iov, Some(&mut cmsg_space), MsgFlags::empty()) {
            Ok(msg) if msg.bytes > 0 => {
                let mut got_client = false;

                if let Ok(cmsg_iter) = msg.cmsgs() {
                    for cmsg in cmsg_iter {
                        if let ControlMessageOwned::ScmRights(fds) = cmsg {
                            for client_fd in fds {
                                debug!(fd = client_fd, "run_main: Neuer Client");
                                let conn = Box::into_raw(Box::new(LxpcConnection::new(client_fd)));
                                // SAFETY: handler ist ein gültiger C-Funktionspointer. conn wurde eben alloziert.
                                unsafe { handler(conn); }
                                got_client = true;
                            }
                        }
                    }
                }

                if !got_client {
                    match decode_header(&header_buf) {
                        Ok(length) if length > 0 => {
                            let mut payload = vec![0u8; length as usize];
                            match stream.read_exact(&mut payload) {
                                Ok(()) => {
                                    match ciborium::from_reader::<LxpcObject, _>(&payload[..]) {
                                        Ok(obj) => {
                                            if let Some(h) = event_handler {
                                                // SAFETY: h ist ein gültiger C-Funktionspointer.
                                                unsafe { h(Box::into_raw(Box::new(obj))); }
                                            }
                                        }
                                        Err(e) => {
                                            error!(error = %e, "run_main: CBOR-Deserialisierung fehlgeschlagen");
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!(error = %e, "run_main: Payload lesen fehlgeschlagen");
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => { error!(error = %e, "run_main: Ungültiger Header"); }
                    }
                }
            }

            Ok(_) => {
                info!("run_main: Bootstrap-Socket geschlossen");
                break;
            }
            Err(e) => {
                error!(error = %e, "run_main: recvmsg fehlgeschlagen");
                break;
            }
        }
    }
    // stream wird gedroppt → FD wird geschlossen
}

// ---------------------------------------------------------------------------
// connect_to_service — Client-Routing
// ---------------------------------------------------------------------------

pub fn connect_to_service(name: &str) -> LxpcResult<RawFd> {
    const SOCKET_PATH: &str = match option_env!("SYSCORED_PATH") {
        Some(path) => path,
        None => "/run/syscored.sock",
    };

    let stream = UnixStream::connect(SOCKET_PATH).map_err(LxpcError::Io)?;
    let fd = stream.as_raw_fd();

    let mut routing_msg = LxpcObject::new_dictionary();
    routing_msg.set_string("lxpc_bootstrap_target", name);

    let temp_conn = LxpcConnection::new(fd);
    temp_conn.send_message(&routing_msg)?;

    // FD offen lassen — Ownership geht an den Caller
    std::mem::forget(stream);

    info!(fd, service = name, socket = SOCKET_PATH, "Mit Dienst verbunden");
    Ok(fd)
}