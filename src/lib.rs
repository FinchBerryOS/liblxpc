// lib.rs — C-ABI Schnittstelle für liblxpc
//
// Edition 2024: extern "C" fn ist nicht mehr implizit unsafe.
// Alle C-Callback-Typen und FFI-Funktionen sind explizit als
// `unsafe extern "C"` deklariert.

mod lxpc;

#[path = "tests.rs"]
#[cfg(test)]
mod tests_module;

use std::ffi::{CStr, CString};
use std::os::unix::io::RawFd;
use std::ptr;

use tracing::error;

use crate::lxpc::{LxpcConnection, LxpcObject};

#[allow(non_camel_case_types)]
pub type lxpc_object     = LxpcObject;
#[allow(non_camel_case_types)]
pub type lxpc_connection = LxpcConnection;

// ---------------------------------------------------------------------------
// Speicherverwaltung
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn lxpc_object_release(ptr: *mut lxpc_object) {
    if !ptr.is_null() {
        // SAFETY: ptr wurde von LXPC via Box::into_raw erzeugt. Caller hat Ownership.
        drop(Box::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_string_release(ptr: *mut libc::c_char) {
    if !ptr.is_null() {
        // SAFETY: ptr wurde von CString::into_raw erzeugt.
        drop(CString::from_raw(ptr));
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_release(ptr: *mut lxpc_connection) {
    if !ptr.is_null() {
        // SAFETY: ptr wurde von LXPC via Box::into_raw erzeugt. Caller hat Ownership.
        drop(Box::from_raw(ptr));
    }
}

// ---------------------------------------------------------------------------
// Dictionary API
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn lxpc_dictionary_create() -> *mut lxpc_object {
    Box::into_raw(Box::new(LxpcObject::new_dictionary()))
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_string(
    obj: *mut lxpc_object, key: *const libc::c_char, value: *const libc::c_char,
) {
    let (Some(dict), false, false) = (obj.as_mut(), key.is_null(), value.is_null()) else { return };
    // SAFETY: key und value sind nicht null, gültige C-Strings (Caller-Garantie).
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    let v = CStr::from_ptr(value).to_string_lossy().into_owned();
    dict.set_string(k, v);
}

/// Rückgabe MUSS mit lxpc_string_release() freigegeben werden. NULL = Key fehlt.
#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_get_string(
    obj: *const lxpc_object, key: *const libc::c_char,
) -> *mut libc::c_char {
    let (Some(dict), false) = (obj.as_ref(), key.is_null()) else { return ptr::null_mut() };
    // SAFETY: key ist nicht null.
    let k = CStr::from_ptr(key).to_string_lossy();
    match dict.get_string(&k) {
        Some(s) => CString::new(s).map(CString::into_raw).unwrap_or(ptr::null_mut()),
        None    => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_int64(
    obj: *mut lxpc_object, key: *const libc::c_char, value: i64,
) {
    let (Some(dict), false) = (obj.as_mut(), key.is_null()) else { return };
    // SAFETY: key ist nicht null.
    dict.set_int64(CStr::from_ptr(key).to_string_lossy().into_owned(), value);
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_get_int64(
    obj: *const lxpc_object, key: *const libc::c_char, out: *mut i64,
) -> bool {
    let (Some(dict), false, false) = (obj.as_ref(), key.is_null(), out.is_null()) else { return false };
    // SAFETY: key und out sind nicht null.
    match dict.get_int64(&CStr::from_ptr(key).to_string_lossy()) {
        Some(v) => { *out = v; true }
        None    => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_double(
    obj: *mut lxpc_object, key: *const libc::c_char, value: f64,
) {
    let (Some(dict), false) = (obj.as_mut(), key.is_null()) else { return };
    // SAFETY: key ist nicht null.
    dict.set_double(CStr::from_ptr(key).to_string_lossy().into_owned(), value);
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_get_double(
    obj: *const lxpc_object, key: *const libc::c_char, out: *mut f64,
) -> bool {
    let (Some(dict), false, false) = (obj.as_ref(), key.is_null(), out.is_null()) else { return false };
    // SAFETY: key und out sind nicht null.
    match dict.get_double(&CStr::from_ptr(key).to_string_lossy()) {
        Some(v) => { *out = v; true }
        None    => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_bool(
    obj: *mut lxpc_object, key: *const libc::c_char, value: bool,
) {
    let (Some(dict), false) = (obj.as_mut(), key.is_null()) else { return };
    // SAFETY: key ist nicht null.
    dict.set_bool(CStr::from_ptr(key).to_string_lossy().into_owned(), value);
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_get_bool(
    obj: *const lxpc_object, key: *const libc::c_char, out: *mut bool,
) -> bool {
    let (Some(dict), false, false) = (obj.as_ref(), key.is_null(), out.is_null()) else { return false };
    // SAFETY: key und out sind nicht null.
    match dict.get_bool(&CStr::from_ptr(key).to_string_lossy()) {
        Some(v) => { *out = v; true }
        None    => false,
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_data(
    obj: *mut lxpc_object, key: *const libc::c_char, data: *const u8, len: libc::size_t,
) {
    let (Some(dict), false, false) = (obj.as_mut(), key.is_null(), data.is_null()) else { return };
    // SAFETY: key nicht null; data zeigt auf len Bytes (Caller-Garantie).
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    let bytes = std::slice::from_raw_parts(data, len).to_vec();
    dict.set_data(k, bytes);
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_uuid(
    obj: *mut lxpc_object, key: *const libc::c_char, uuid_ptr: *const u8,
) -> bool {
    let (Some(dict), false, false) = (obj.as_mut(), key.is_null(), uuid_ptr.is_null()) else { return false };
    // SAFETY: key nicht null; uuid_ptr zeigt per Vertrag auf genau 16 Bytes.
    let k = CStr::from_ptr(key).to_string_lossy().into_owned();
    let bytes: [u8; 16] = match std::slice::from_raw_parts(uuid_ptr, 16).try_into() {
        Ok(b)  => b,
        Err(_) => return false,
    };
    dict.set_uuid(k, bytes);
    true
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_null(
    obj: *mut lxpc_object, key: *const libc::c_char,
) {
    let (Some(dict), false) = (obj.as_mut(), key.is_null()) else { return };
    // SAFETY: key ist nicht null.
    dict.set_null(CStr::from_ptr(key).to_string_lossy().into_owned());
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_set_fd(
    obj: *mut lxpc_object, key: *const libc::c_char, fd: RawFd,
) {
    let (Some(dict), false) = (obj.as_mut(), key.is_null()) else { return };
    // SAFETY: key ist nicht null.
    dict.set_fd(CStr::from_ptr(key).to_string_lossy().into_owned(), fd);
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_dictionary_get_fd(
    obj: *const lxpc_object, key: *const libc::c_char,
) -> RawFd {
    let (Some(dict), false) = (obj.as_ref(), key.is_null()) else { return -1 };
    // SAFETY: key ist nicht null.
    dict.get_fd(&CStr::from_ptr(key).to_string_lossy()).unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_object_get_msg_id(obj: *const lxpc_object) -> i64 {
    // SAFETY: obj kann null sein — geprüft via as_ref().
    obj.as_ref().and_then(|o| o.get_int64("lxpc.msg_id")).unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_object_get_reply_to(obj: *const lxpc_object) -> i64 {
    // SAFETY: obj kann null sein — geprüft via as_ref().
    obj.as_ref().and_then(|o| o.get_int64("lxpc.reply_to")).unwrap_or(-1)
}

// ---------------------------------------------------------------------------
// Verbindungs-API
// ---------------------------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_create(
    name: *const libc::c_char,
) -> *mut lxpc_connection {
    if name.is_null() { return ptr::null_mut(); }
    // SAFETY: name ist nicht null, gültiger C-String.
    let name_str = CStr::from_ptr(name).to_string_lossy();
    match crate::lxpc::connect_to_service(&name_str) {
        Ok(fd)  => Box::into_raw(Box::new(LxpcConnection::new(fd))),
        Err(e)  => {
            error!(service = %name_str, error = %e, "lxpc_connection_create fehlgeschlagen");
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_get_peer_pid(conn: *const lxpc_connection) -> libc::pid_t {
    // SAFETY: conn kann null sein.
    conn.as_ref().and_then(|c| c.peer.as_ref()).map(|p| p.pid).unwrap_or(-1)
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_get_peer_uid(conn: *const lxpc_connection) -> libc::uid_t {
    // SAFETY: conn kann null sein.
    conn.as_ref().and_then(|c| c.peer.as_ref()).map(|p| p.uid).unwrap_or(libc::uid_t::MAX)
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_get_peer_gid(conn: *const lxpc_connection) -> libc::gid_t {
    // SAFETY: conn kann null sein.
    conn.as_ref().and_then(|c| c.peer.as_ref()).map(|p| p.gid).unwrap_or(libc::gid_t::MAX)
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_send_message(
    conn: *mut lxpc_connection, obj: *const lxpc_object,
) -> libc::c_int {
    let (Some(conn_ref), Some(obj_ref)) = (conn.as_ref(), obj.as_ref()) else { return -1 };
    match conn_ref.send_message(obj_ref) {
        Ok(())  => 0,
        Err(e)  => { error!(error = %e, "send_message fehlgeschlagen"); -1 }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_send_reply(
    conn: *mut lxpc_connection, reply: *mut lxpc_object, reply_to_msg_id: i64,
) -> libc::c_int {
    let (Some(conn_ref), Some(obj_ref)) = (conn.as_ref(), reply.as_mut()) else { return -1 };
    match conn_ref.send_reply(obj_ref, reply_to_msg_id) {
        Ok(())  => 0,
        Err(e)  => { error!(error = %e, "send_reply fehlgeschlagen"); -1 }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_resume(conn: *mut lxpc_connection) {
    // SAFETY: conn kann null sein.
    if let Some(conn_ref) = conn.as_ref() { conn_ref.activate(); }
}

/// WICHTIG: Handler MUSS lxpc_object_release() auf dem übergebenen Pointer aufrufen.
#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_set_event_handler(
    conn:    *mut lxpc_connection,
    // Edition 2024: Callback-Pointer zu unsafe extern "C" fn
    handler: unsafe extern "C" fn(*mut lxpc_object),
) {
    if let Some(conn_ref) = conn.as_mut() {
        match conn_ref.handler.lock() {
            Ok(mut g)  => *g = Some(handler),
            Err(_)     => error!("Mutex vergiftet in set_event_handler"),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_connection_set_error_handler(
    conn:    *mut lxpc_connection,
    handler: unsafe extern "C" fn(libc::c_int, *const libc::c_char),
) {
    if let Some(conn_ref) = conn.as_mut() {
        match conn_ref.error_handler.lock() {
            Ok(mut g)  => *g = Some(handler),
            Err(_)     => error!("Mutex vergiftet in set_error_handler"),
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap & Daemon-Main
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn lxpc_bootstrap_connection_activate() -> libc::c_int {
    crate::lxpc::bootstrap_check()
}

#[no_mangle]
pub unsafe extern "C" fn lxpc_main(
    handler:       unsafe extern "C" fn(*mut lxpc_connection),
    event_handler: Option<unsafe extern "C" fn(*mut lxpc_object)>,
) {
    crate::lxpc::run_main(handler, event_handler);
}