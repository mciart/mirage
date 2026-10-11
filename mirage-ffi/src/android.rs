#![cfg(target_os = "android")]
//! Android JNI bindings for Mirage VPN.
//!
//! Thin layer over `MirageRuntime` (same as the C FFI in `lib.rs`), exposing the
//! `com.mirage.vpn.MirageNative` external functions to Kotlin.

use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::sync::{Mutex, OnceLock};

use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jlong, jlongArray, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};

use crate::runtime::MirageRuntime;
use crate::types::*;

static JVM: OnceLock<JavaVM> = OnceLock::new();
static LAST_ERROR: Mutex<String> = Mutex::new(String::new());
/// handle -> `*mut AndroidCtx` (stored as usize so the map is Send).
static CONTEXTS: Mutex<Option<HashMap<jlong, usize>>> = Mutex::new(None);

/// Context passed to the C-style trampolines.
struct AndroidCtx {
    vm: JavaVM,
    cb: GlobalRef,
}

fn set_last_error(msg: &str) {
    if let Ok(mut e) = LAST_ERROR.lock() {
        *e = msg.to_string();
    }
}

/// Reads a NUL-terminated C char buffer into a String (lossy).
fn buf_to_string(buf: &[c_char]) -> String {
    let bytes: Vec<u8> = buf
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Exclusive borrow — only for lifecycle calls (`nativeStart`/`nativeStop`) that
/// Kotlin serializes. Must NOT be used by the read-only accessors, which can run
/// concurrently with the packet thread.
unsafe fn handle_ref<'a>(handle: jlong) -> Option<&'a mut MirageHandle> {
    if handle == 0 {
        None
    } else {
        Some(&mut *(handle as *mut MirageHandle))
    }
}

/// Shared borrow — for the read-only accessors (`nativeSendPacket`,
/// `nativeGetStatus`, `nativeGetMetrics`, `nativeGetActiveProtocol`). These hit
/// only `&self` runtime methods (atomics / channel sends), so concurrent shared
/// borrows from different threads are sound.
unsafe fn handle_shared<'a>(handle: jlong) -> Option<&'a MirageHandle> {
    if handle == 0 {
        None
    } else {
        Some(&*(handle as *const MirageHandle))
    }
}

fn clear_exception(env: &mut JNIEnv) {
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
    }
}

// ─── Trampolines ───────────────────────────────────────────────────────────────

unsafe extern "C" fn packet_tramp(data: *const u8, len: usize, context: *mut c_void) {
    if data.is_null() || context.is_null() {
        return;
    }
    let ctx = &*(context as *const AndroidCtx);
    let Ok(mut env) = ctx.vm.attach_current_thread() else {
        return;
    };
    let slice = std::slice::from_raw_parts(data, len);
    if let Ok(arr) = env.byte_array_from_slice(slice) {
        let _ = env.call_method(
            ctx.cb.as_obj(),
            "onPacketWrite",
            "([B)V",
            &[JValue::Object(&arr)],
        );
        let _ = env.delete_local_ref(arr);
    }
    clear_exception(&mut env);
}

unsafe extern "C" fn status_tramp(status: MirageStatus, message: *const c_char, context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let ctx = &*(context as *const AndroidCtx);
    let Ok(mut env) = ctx.vm.attach_current_thread() else {
        return;
    };
    let msg = if message.is_null() {
        String::new()
    } else {
        CStr::from_ptr(message).to_string_lossy().into_owned()
    };
    if let Ok(jmsg) = env.new_string(msg) {
        let _ = env.call_method(
            ctx.cb.as_obj(),
            "onStatusChange",
            "(ILjava/lang/String;)V",
            &[JValue::Int(status as jint), JValue::Object(&jmsg)],
        );
        let _ = env.delete_local_ref(jmsg);
    }
    clear_exception(&mut env);
}

unsafe extern "C" fn config_tramp(config: *const MirageTunnelConfig, context: *mut c_void) {
    if config.is_null() || context.is_null() {
        return;
    }
    let ctx = &*(context as *const AndroidCtx);
    let cfg = &*config;
    let Ok(mut env) = ctx.vm.attach_current_thread() else {
        return;
    };
    let strs = [
        buf_to_string(&cfg.client_address),
        buf_to_string(&cfg.client_address_v6),
        buf_to_string(&cfg.dns_servers_json),
        buf_to_string(&cfg.routes_json),
        buf_to_string(&cfg.excluded_routes_json),
    ];
    let mut jstrs: Vec<JObject> = Vec::with_capacity(strs.len());
    for s in &strs {
        match env.new_string(s) {
            Ok(js) => jstrs.push(JObject::from(js)),
            Err(_) => {
                clear_exception(&mut env);
                return;
            }
        }
    }
    let _ = env.call_method(
        ctx.cb.as_obj(),
        "onTunnelConfig",
        "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        &[
            JValue::Object(&jstrs[0]),
            JValue::Object(&jstrs[1]),
            JValue::Int(cfg.mtu as jint),
            JValue::Object(&jstrs[2]),
            JValue::Object(&jstrs[3]),
            JValue::Object(&jstrs[4]),
        ],
    );
    for o in jstrs {
        let _ = env.delete_local_ref(o);
    }
    clear_exception(&mut env);
}

// ─── JNI entry points ──────────────────────────────────────────────────────────

#[no_mangle]
pub extern "system" fn Java_com_mirage_vpn_MirageNative_nativeCreate(
    mut env: JNIEnv,
    _class: JClass,
    config_toml: JString,
) -> jlong {
    let toml: String = match env.get_string(&config_toml) {
        Ok(s) => s.into(),
        Err(_) => {
            set_last_error("config_toml is invalid");
            return 0;
        }
    };
    let config = match crate::parse_config_from_toml(&toml) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&e);
            return 0;
        }
    };
    match MirageRuntime::new(config) {
        Ok(rt) => {
            set_last_error("");
            Box::into_raw(Box::new(MirageHandle { inner: Some(rt) })) as jlong
        }
        Err(e) => {
            set_last_error(&e);
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mirage_vpn_MirageNative_nativeLastError(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let msg = LAST_ERROR.lock().map(|e| e.clone()).unwrap_or_default();
    match env.new_string(msg) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mirage_vpn_MirageNative_nativeStart(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    callback: JObject,
) {
    let Some(h) = (unsafe { handle_ref(handle) }) else {
        return;
    };
    let Some(rt) = h.inner.as_mut() else {
        return;
    };
    let Ok(vm) = env.get_java_vm() else {
        set_last_error("failed to get JavaVM");
        return;
    };
    let Ok(cb) = env.new_global_ref(&callback) else {
        set_last_error("failed to create global ref");
        return;
    };
    // Cache a JavaVM globally (JavaVM is a thin pointer wrapper; a second copy is
    // obtained below for the context).
    if JVM.get().is_none() {
        if let Ok(vm2) = env.get_java_vm() {
            let _ = JVM.set(vm2);
        }
    }
    let ctx_ptr = Box::into_raw(Box::new(AndroidCtx { vm, cb }));

    // Replace (and free) any previous context for this handle.
    if let Ok(mut map) = CONTEXTS.lock() {
        let old = map
            .get_or_insert_with(HashMap::new)
            .insert(handle, ctx_ptr as usize);
        if let Some(old) = old {
            // Safety: created by Box::into_raw above in an earlier nativeStart.
            drop(unsafe { Box::from_raw(old as *mut AndroidCtx) });
        }
    }

    rt.start(
        Some(packet_tramp),
        Some(status_tramp),
        Some(config_tramp),
        ctx_ptr as *mut c_void,
    );
}

#[no_mangle]
pub extern "system" fn Java_com_mirage_vpn_MirageNative_nativeSendPacket(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    packet: JByteArray,
    len: jint,
) -> jboolean {
    let Some(h) = (unsafe { handle_shared(handle) }) else {
        return JNI_FALSE;
    };
    let Some(rt) = h.inner.as_ref() else {
        return JNI_FALSE;
    };
    if len <= 0 {
        return JNI_FALSE;
    }
    // convert_byte_array copies the whole array; truncate to `len`.
    let Ok(mut bytes) = env.convert_byte_array(&packet) else {
        return JNI_FALSE;
    };
    bytes.truncate(len as usize);
    if bytes.is_empty() {
        return JNI_FALSE;
    }
    if rt.write_packet(&bytes) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mirage_vpn_MirageNative_nativeStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if let Some(h) = unsafe { handle_ref(handle) } {
        if let Some(rt) = h.inner.as_mut() {
            rt.stop();
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mirage_vpn_MirageNative_nativeDestroy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // Safety: handle came from nativeCreate.
    let mut boxed = unsafe { Box::from_raw(handle as *mut MirageHandle) };
    if let Some(rt) = boxed.inner.as_mut() {
        rt.stop();
    }
    // Dropping the handle shuts down the Tokio runtime, so no callback can fire
    // after this point; only then free the callback context.
    drop(boxed);
    let ctx = CONTEXTS
        .lock()
        .ok()
        .and_then(|mut m| m.as_mut().and_then(|m| m.remove(&handle)));
    if let Some(p) = ctx {
        // Dropping AndroidCtx releases the GlobalRef.
        drop(unsafe { Box::from_raw(p as *mut AndroidCtx) });
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mirage_vpn_MirageNative_nativeGetStatus(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    match unsafe { handle_shared(handle) }.and_then(|h| h.inner.as_ref()) {
        Some(rt) => rt.status() as jint,
        None => MirageStatus::Disconnected as jint,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mirage_vpn_MirageNative_nativeGetMetrics(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jlongArray {
    let m = unsafe { handle_shared(handle) }
        .and_then(|h| h.inner.as_ref())
        .map(|rt| rt.metrics_snapshot())
        .unwrap_or_default();
    let vals: [jlong; 5] = [
        m.bytes_sent as jlong,
        m.bytes_received as jlong,
        m.packets_sent as jlong,
        m.packets_received as jlong,
        m.uptime_seconds as jlong,
    ];
    let Ok(arr) = env.new_long_array(5) else {
        return std::ptr::null_mut();
    };
    if env.set_long_array_region(&arr, 0, &vals).is_err() {
        return std::ptr::null_mut();
    }
    arr.into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_mirage_vpn_MirageNative_nativeGetActiveProtocol(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jstring {
    let proto = unsafe { handle_shared(handle) }
        .and_then(|h| h.inner.as_ref())
        .map(|rt| buf_to_string(&rt.metrics_snapshot().active_protocol))
        .unwrap_or_default();
    match env.new_string(proto) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ─── Config parse / serialize helpers ──────────────────────────────────────────

/// Reads a Java string argument, runs `f` on it (never unwinding across FFI) and
/// returns a `{"ok": ...}` / `{"error": "..."}` JSON envelope as a Java string.
fn envelope_call(
    env: &mut JNIEnv,
    input: &JString,
    f: impl FnOnce(&str) -> Result<serde_json::Value, String>,
) -> jstring {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let s: String = match env.get_string(input) {
            Ok(s) => s.into(),
            Err(_) => return Err("input string is invalid".to_string()),
        };
        f(&s)
    }));
    let envelope = match result {
        Ok(Ok(v)) => serde_json::json!({ "ok": v }),
        Ok(Err(e)) => serde_json::json!({ "error": e }),
        Err(_) => serde_json::json!({ "error": "internal error (panic)" }),
    };
    match env.new_string(envelope.to_string()) {
        Ok(s) => s.into_raw(),
        Err(_) => {
            clear_exception(env);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_mirage_vpn_MirageNative_nativeParseConfig(
    mut env: JNIEnv,
    _class: JClass,
    toml: JString,
) -> jstring {
    envelope_call(&mut env, &toml, |s| {
        let config = crate::parse_config_from_toml(s)?;
        serde_json::to_value(&config).map_err(|e| format!("Failed to serialize config: {e}"))
    })
}

#[no_mangle]
pub extern "system" fn Java_com_mirage_vpn_MirageNative_nativeConfigToToml(
    mut env: JNIEnv,
    _class: JClass,
    json: JString,
) -> jstring {
    envelope_call(&mut env, &json, |s| {
        let config: mirage::config::ClientConfig =
            serde_json::from_str(s).map_err(|e| format!("Invalid config JSON: {e}"))?;
        let toml = toml::to_string_pretty(&config)
            .map_err(|e| format!("Failed to serialize config to TOML: {e}"))?;
        Ok(serde_json::Value::String(toml))
    })
}
