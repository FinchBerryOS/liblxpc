mod lxpc;


use std::ffi::{CStr, CString};
use std::os::unix::io::RawFd;
use std::ptr;

use crate::lxpc::{LxpcConnection, LxpcObject};

#[allow(non_camel_case_types)]
pub type lxpc_object     = LxpcObject;
#[allow(non_camel_case_types)]
pub type lxpc_connection = LxpcConnection;

// ---------------------------------------------------------------------------
// Speicherverwaltung
// ---------------------------------------------------------------------------

/// Gibt ein LxpcObject frei das von LXPC auf dem Heap alloziert wurde.
///
/// MUSS nach jedem Aufruf eines Message-Handlers genau einmal aufgerufen werden.
/// Doppelter Aufruf ist undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn lxpc_object_release(ptr: *mut lxpc_object) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

/// Gibt einen String frei der von lxpc_dictionary_get_string zurückgegeben wurde.
///
/// MUSS für jeden von LXPC zurückgegebenen String genau einmal aufgerufen werden.
#[no_mangle]
pub unsafe extern "C" fn lxpc_string_release(ptr: *mut libc::c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

/// Gibt eine LxpcConnection frei.
///
/// Sollte erst aufgerufen werden wenn der Lese-Thread nicht mehr läuft.
#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_release(ptr: *mut lxpc_connection) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

// ---------------------------------------------------------------------------
// Dictionary API
// ---------------------------------------------------------------------------

/// Erzeugt ein neues, leeres Dictionary. Gibt NULL zurück wenn die Allokation scheitert.
/// Muss mit lxpc_object_release() freigegeben werden.
#[no_mangle]
pub extern "C" fn lxpc_dictionary_create() -> *mut lxpc_object {
    Box::into_raw(Box::new(LxpcObject::new_dictionary()))
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_string(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
    value: *const libc::c_char,
) {
    let (Some(dict), false, false) = (obj.as_mut(), key.is_null(), value.is_null()) else { return };
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    let v = CStr::from_ptr(value).to_string_lossy().into_owned();
    dict.set_string(k, v);
}

/// Gibt den Wert als neu allozierter C-String zurück.
/// MUSS mit lxpc_string_release() freigegeben werden.
/// Gibt NULL zurück wenn der Key nicht existiert oder kein String ist.
#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_get_string(
    obj: *const lxpc_object,
    key: *const libc::c_char,
) -> *mut libc::c_char {
    let (Some(dict), false) = (obj.as_ref(), key.is_null()) else { return ptr::null_mut() };
    let k = CStr::from_ptr(key).to_string_lossy();
    match dict.get_string(&k) {
        Some(s) => CString::new(s).map(CString::into_raw).unwrap_or(ptr::null_mut()),
        None    => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_int64(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
    value: i64,
) {
    let (Some(dict), false) = (obj.as_mut(), key.is_null()) else { return };
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    dict.set_int64(k, value);
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_get_int64(
    obj: *const lxpc_object,
    key: *const libc::c_char,
    out: *mut i64,
) -> bool {
    let (Some(dict), false, false) = (obj.as_ref(), key.is_null(), out.is_null()) else { return false };
    let k = CStr::from_ptr(key).to_string_lossy();
    match dict.get_int64(&k) {
        Some(v) => { *out = v; true }
        None    => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_double(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
    value: f64,
) {
    let (Some(dict), false) = (obj.as_mut(), key.is_null()) else { return };
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    dict.set_double(k, value);
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_get_double(
    obj: *const lxpc_object,
    key: *const libc::c_char,
    out: *mut f64,
) -> bool {
    let (Some(dict), false, false) = (obj.as_ref(), key.is_null(), out.is_null()) else { return false };
    let k = CStr::from_ptr(key).to_string_lossy();
    match dict.get_double(&k) {
        Some(v) => { *out = v; true }
        None    => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_bool(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
    value: bool,
) {
    let (Some(dict), false) = (obj.as_mut(), key.is_null()) else { return };
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    dict.set_bool(k, value);
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_get_bool(
    obj: *const lxpc_object,
    key: *const libc::c_char,
    out: *mut bool,
) -> bool {
    let (Some(dict), false, false) = (obj.as_ref(), key.is_null(), out.is_null()) else { return false };
    let k = CStr::from_ptr(key).to_string_lossy();
    match dict.get_bool(&k) {
        Some(v) => { *out = v; true }
        None    => false,
    }
}

/// Setzt einen rohen Byte-Blob. Die Daten werden kopiert.
#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_data(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
    data: *const u8,
    len: libc::size_t,
) {
    let (Some(dict), false, false) = (obj.as_mut(), key.is_null(), data.is_null()) else { return };
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    let bytes = std::slice::from_raw_parts(data, len).to_vec();
    dict.set_data(k, bytes);
}

/// Setzt eine UUID (genau 16 Bytes). Gibt false zurück wenn uuid_ptr NULL ist.
#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_uuid(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
    uuid_ptr: *const u8, // Muss auf genau 16 Bytes zeigen
) -> bool {
    let (Some(dict), false, false) = (obj.as_mut(), key.is_null(), uuid_ptr.is_null()) else { return false };
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    let bytes: [u8; 16] = std::slice::from_raw_parts(uuid_ptr, 16).try_into().unwrap();
    dict.set_uuid(k, bytes);
    true
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_null(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
) {
    let (Some(dict), false) = (obj.as_mut(), key.is_null()) else { return };
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    dict.set_null(k);
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_fd(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
    fd: RawFd,
) {
    let (Some(dict), false) = (obj.as_mut(), key.is_null()) else { return };
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    dict.set_fd(k, fd);
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_get_fd(
    obj: *const lxpc_object,
    key: *const libc::c_char,
) -> RawFd {
    let (Some(dict), false) = (obj.as_ref(), key.is_null()) else { return -1 };
    let k = CStr::from_ptr(key).to_string_lossy();
    dict.get_fd(&k).unwrap_or(-1)
}

/// Gibt die Message-ID zurück die LXPC automatisch gesetzt hat.
/// Nützlich um Antworten zuzuordnen.
#[no_mangle]
pub unsafe extern "C" fn lxpc_object_get_msg_id(obj: *const lxpc_object) -> i64 {
    obj.as_ref()
        .and_then(|o| o.get_int64("lxpc.msg_id"))
        .unwrap_or(-1)
}

/// Gibt die Reply-To-ID zurück (oder -1 wenn das kein Reply ist).
#[no_mangle]
pub unsafe extern "C" fn lxpc_object_get_reply_to(obj: *const lxpc_object) -> i64 {
    obj.as_ref()
        .and_then(|o| o.get_int64("lxpc.reply_to"))
        .unwrap_or(-1)
}

// ---------------------------------------------------------------------------
// Verbindungs-API
// ---------------------------------------------------------------------------

/// Verbindet sich mit einem benannten Dienst via syscored.
/// Gibt NULL zurück wenn die Verbindung fehlschlägt.
/// Muss mit lxpc_connection_release() freigegeben werden.
#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_create(name: *const libc::c_char) -> *mut lxpc_connection {
    if name.is_null() { return ptr::null_mut(); }
    let name_str = CStr::from_ptr(name).to_string_lossy();
    match crate::lxpc::connect_to_service(&name_str) {
        Ok(fd)  => Box::into_raw(Box::new(LxpcConnection::new(fd))),
        Err(e)  => {
            eprintln!("[lxpc ERROR] lxpc_connection_create('{name_str}'): {e}");
            ptr::null_mut()
        }
    }
}

/// Sendet eine Nachricht. Gibt 0 bei Erfolg, -1 bei Fehler zurück.
#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_send_message(
    conn: *mut lxpc_connection,
    obj: *const lxpc_object,
) -> libc::c_int {
    let (Some(conn_ref), Some(obj_ref)) = (conn.as_ref(), obj.as_ref()) else { return -1 };
    match conn_ref.send_message(obj_ref) {
        Ok(())  => 0,
        Err(e)  => { eprintln!("[lxpc ERROR] send_message: {e}"); -1 }
    }
}

/// Sendet eine Antwort auf eine empfangene Nachricht.
/// `reply_to_msg_id` ist der Wert von lxpc_object_get_msg_id() der Anfrage.
#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_send_reply(
    conn: *mut lxpc_connection,
    reply: *mut lxpc_object,
    reply_to_msg_id: i64,
) -> libc::c_int {
    let (Some(conn_ref), Some(obj_ref)) = (conn.as_ref(), reply.as_mut()) else { return -1 };
    match conn_ref.send_reply(obj_ref, reply_to_msg_id) {
        Ok(())  => 0,
        Err(e)  => { eprintln!("[lxpc ERROR] send_reply: {e}"); -1 }
    }
}

/// Startet den Lese-Thread. Muss vor dem Empfangen von Nachrichten aufgerufen werden.
#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_resume(conn: *mut lxpc_connection) {
    if let Some(conn_ref) = conn.as_ref() {
        conn_ref.activate();
    }
}

/// Setzt den Handler für eingehende Nachrichten.
/// Der Handler wird aus einem Hintergrund-Thread aufgerufen.
/// WICHTIG: Der Handler MUSS lxpc_object_release() auf dem übergebenen Pointer aufrufen.
#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_set_event_handler(
    conn: *mut lxpc_connection,
    handler: extern "C" fn(*mut lxpc_object),
) {
    if let Some(conn_ref) = conn.as_mut() {
        *conn_ref.handler.lock().unwrap() = Some(handler);
    }
}

/// Setzt den Handler für Verbindungsfehler (Verbindung getrennt, Protokollfehler, …).
/// code: Fehlercode (immer negativ), msg: lesbare Fehlerbeschreibung (UTF-8, NULL-terminiert).
/// Der String msg ist nur für die Dauer des Handler-Aufrufs gültig — nicht speichern ohne zu kopieren!
#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_set_error_handler(
    conn: *mut lxpc_connection,
    handler: extern "C" fn(libc::c_int, *const libc::c_char),
) {
    if let Some(conn_ref) = conn.as_mut() {
        *conn_ref.error_handler.lock().unwrap() = Some(handler);
    }
}

// ---------------------------------------------------------------------------
// Bootstrap & Daemon-Main
// ---------------------------------------------------------------------------

/// Prüft ob der Prozess korrekt von syscored (PID 1) gestartet wurde.
/// Gibt 0 zurück bei Erfolg, negativen Fehlercode bei Misserfolg.
#[no_mangle]
pub extern "C" fn lxpc_bootstrap_connection_activate() -> libc::c_int {
    crate::lxpc::bootstrap_check()
}

/// Daemon-Hauptschleife. Ersetzt die normale main() in C-Daemons.
/// Blockiert bis syscored die Verbindung schließt.
///
/// handler:       Wird für jede neue Client-Verbindung aufgerufen.
/// event_handler: Wird für Steuerbefehle von syscored aufgerufen (optional, kann NULL sein).
#[no_mangle]
pub unsafe extern "C" fn lxpc_main(
    handler: extern "C" fn(*mut lxpc_connection),
    event_handler: Option<extern "C" fn(*mut lxpc_object)>,
) {
    crate::lxpc::run_main(handler, event_handler);
}