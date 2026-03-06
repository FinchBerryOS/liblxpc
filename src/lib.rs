use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::unix::io::{FromRawFd, RawFd, BorrowedFd}; 
use std::os::unix::net::{UnixListener, UnixStream};
use std::ptr;
use std::thread;
use std::io::{Read, IoSlice, IoSliceMut}; 
use std::sync::{Arc, Mutex};
use serde::{Serialize, Deserialize};

#[cfg(target_os = "linux")]
use nix::sys::socket::sockopt::PeerCredentials;
use nix::sys::socket::{
    getsockopt, sendmsg, recvmsg, ControlMessage, ControlMessageOwned, MsgFlags
};

// --- Konstanten & Definitionen ---
pub const LXPC_TYPE_ERROR: i32 = 0;
pub const LXPC_TYPE_DICTIONARY: i32 = 1;
const LXPC_MAGIC: u32 = 0x4C585043; 

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct lxpc_connection {
    fd: RawFd,
    handler: Arc<Mutex<Option<extern "C" fn(*mut lxpc_object)>>>,
    running: Arc<Mutex<bool>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum LxpcValue {
    String(String),
    Int64(i64),
    Bool(bool),
    Dictionary(HashMap<String, LxpcValue>), 
    Fd(RawFd), 
}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize, Clone)]
#[repr(C)]
pub struct lxpc_object {
    pub obj_type: i32,
    pub data: HashMap<String, LxpcValue>, 
}

// --- Speicherverwaltung ---

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_object_release(ptr: *mut lxpc_object) {
    if !ptr.is_null() {
        let _ = unsafe { Box::from_raw(ptr) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_string_release(ptr: *mut libc::c_char) {
    if !ptr.is_null() {
        let _ = unsafe { CString::from_raw(ptr) };
    }
}

// --- Dictionary API ---

#[unsafe(no_mangle)]
pub extern "C" fn lxpc_dictionary_create() -> *mut lxpc_object {
    Box::into_raw(Box::new(lxpc_object {
        obj_type: LXPC_TYPE_DICTIONARY,
        data: HashMap::new(),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_dictionary_set_string(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
    value: *const libc::c_char,
) {
    if obj.is_null() || key.is_null() || value.is_null() { return; }
    let dict = unsafe { &mut *obj };
    let k = unsafe { CStr::from_ptr(key) }.to_string_lossy().into_owned();
    let v = unsafe { CStr::from_ptr(value) }.to_string_lossy().into_owned();
    dict.data.insert(k, LxpcValue::String(v));
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_dictionary_get_string(
    obj: *mut lxpc_object,
    key: *const libc::c_char,
) -> *mut libc::c_char {
    if obj.is_null() || key.is_null() { return ptr::null_mut(); }
    let dict = unsafe { &*obj };
    let k = unsafe { CStr::from_ptr(key) }.to_string_lossy();
    if let Some(LxpcValue::String(val)) = dict.data.get(k.as_ref()) {
        return CString::new(val.as_str()).unwrap().into_raw();
    }
    ptr::null_mut()
}

// --- Netzwerk & Framing ---

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_connection_send_message(conn: *mut lxpc_connection, obj: *mut lxpc_object) {
    if conn.is_null() || obj.is_null() { return; }
    let conn = unsafe { &mut *conn };
    let dict = unsafe { &*obj };

    let mut fds_to_beam = Vec::new();
    for val in dict.data.values() {
        if let LxpcValue::Fd(fd) = val {
            fds_to_beam.push(*fd);
        }
    }

    let mut payload = Vec::new();
    if ciborium::into_writer(dict, &mut payload).is_ok() {
        let mut header = Vec::with_capacity(8);
        header.extend_from_slice(&LXPC_MAGIC.to_le_bytes());
        header.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        
        let iov = [IoSlice::new(&header), IoSlice::new(&payload)];
        
        let cmsgs = if !fds_to_beam.is_empty() {
            vec![ControlMessage::ScmRights(&fds_to_beam)]
        } else {
            vec![]
        };

        let _ = sendmsg::<()>(conn.fd, &iov, &cmsgs, MsgFlags::empty(), None);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_connection_resume(conn: *mut lxpc_connection) {
    if conn.is_null() { return; }
    let conn = unsafe { &mut *conn };
    let mut running = conn.running.lock().unwrap();
    if *running { return; }
    *running = true;

    let fd = conn.fd;
    let handler_arc = Arc::clone(&conn.handler);
    let running_arc = Arc::clone(&conn.running);

    thread::spawn(move || {
        while *running_arc.lock().unwrap() {
            let mut header_buf = [0u8; 8];
            let mut cmsg_space = nix::cmsg_space!([RawFd; 10]);
            let mut iov = [IoSliceMut::new(&mut header_buf)];

            match recvmsg::<()>(fd, &mut iov, Some(&mut cmsg_space), MsgFlags::empty()) {
                Ok(msg) if msg.bytes > 0 => {
                    
                    let mut received_fds = Vec::new();
                    
                    // FIX: Ok() anstelle von Some(), da msg.cmsgs() nun ein Result zurückgibt!
                    if let Ok(cmsg_iter) = msg.cmsgs() {
                        for cmsg in cmsg_iter {
                            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                                received_fds.extend(fds);
                            }
                        }
                    }

                    let magic = u32::from_le_bytes(header_buf[0..4].try_into().unwrap());
                    let length = u32::from_le_bytes(header_buf[4..8].try_into().unwrap());
                    
                    if magic == LXPC_MAGIC {
                        let mut payload = vec![0u8; length as usize];
                        let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
                        
                        if stream.read_exact(&mut payload).is_ok() {
                            if let Ok(obj_data) = ciborium::from_reader::<lxpc_object, _>(&payload[..]) {
                                let obj_ptr = Box::into_raw(Box::new(obj_data));
                                let h_lock = handler_arc.lock().unwrap();
                                if let Some(h) = *h_lock { h(obj_ptr); }
                            }
                        }
                        std::mem::forget(stream); 
                    }
                }
                _ => break, 
            }
        }
    });
}

// --- Bootstrap (Sicherheits-Check) ---

#[unsafe(no_mangle)]
pub extern "C" fn lxpc_bootstrap_connection_activate() -> i32 {
    let fd_raw: RawFd = 3;
    let fd = unsafe { BorrowedFd::borrow_raw(fd_raw) };

    #[cfg(target_os = "linux")]
    {
        if let Ok(creds) = getsockopt(&fd, PeerCredentials) {
            if creds.pid() != 1 { return -3; }
            return 0;
        }
        return -1;
    }

    #[cfg(not(target_os = "linux"))]
    {
        0 
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn lxpc_main(handler: extern "C" fn(*mut lxpc_connection)) {
    if lxpc_bootstrap_connection_activate() != 0 {
        unsafe { libc::exit(1) };
    }

    let listener = unsafe { UnixListener::from_raw_fd(3) };
    for stream in listener.incoming() {
        if let Ok(s) = stream {
            use std::os::unix::io::AsRawFd;
            let client_fd = s.as_raw_fd();
            std::mem::forget(s); 
            let conn = Box::into_raw(Box::new(lxpc_connection {
                fd: client_fd,
                handler: Arc::new(Mutex::new(None)),
                running: Arc::new(Mutex::new(false)),
            }));
            handler(conn);
        }
    }
}