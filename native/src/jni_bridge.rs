use crate::engine::{Engine, Event, Observer};
use jni::objects::{GlobalRef, JByteArray, JClass, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jlong};
use jni::{JNIEnv, JavaVM};
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::sync::{
    atomic::{AtomicI64, Ordering},
    Arc, Mutex, OnceLock,
};
use std::time::Duration;
use tokio::runtime::Builder;

static NEXT_ID: AtomicI64 = AtomicI64::new(1);

fn engines() -> &'static Mutex<HashMap<jlong, Arc<Engine>>> {
    static ENGINES: OnceLock<Mutex<HashMap<jlong, Arc<Engine>>>> = OnceLock::new();
    ENGINES.get_or_init(|| Mutex::new(HashMap::new()))
}

struct LogTarget {
    vm: JavaVM,
    receiver: GlobalRef,
}

impl Observer for LogTarget {
    fn log(&self, message: &str) {
        if let Ok(mut env) = self.vm.attach_current_thread() {
            let result = env.with_local_frame(4, |env| -> jni::errors::Result<()> {
                let text = JObject::from(env.new_string(message)?);
                env.call_method(
                    self.receiver.as_obj(),
                    "log",
                    "(Ljava/lang/String;)V",
                    &[JValue::Object(&text)],
                )?;
                Ok(())
            });
            if result.is_err() && env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
        }
    }

    fn is_probe(&self, port: u16) -> bool {
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return false;
        };
        let result = env
            .call_method(
                self.receiver.as_obj(),
                "isProbe",
                "(I)Z",
                &[JValue::Int(i32::from(port))],
            )
            .and_then(|value| value.z());
        if result.is_err() && env.exception_check().unwrap_or(false) {
            let _ = env.exception_clear();
        }
        result.unwrap_or(false)
    }

    fn record(&self, probe: bool, event: Event) {
        if let Ok(mut env) = self.vm.attach_current_thread() {
            let result = env.call_method(
                self.receiver.as_obj(),
                "record",
                "(ZI)V",
                &[JValue::Bool(u8::from(probe)), JValue::Int(event as i32)],
            );
            if result.is_err() && env.exception_check().unwrap_or(false) {
                let _ = env.exception_clear();
            }
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_app_telegramws_proxy_RustProxyEngine_nativeBind(
    mut env: JNIEnv,
    _class: JClass,
    port: jint,
    secret: JByteArray,
    config: JString,
    logger: JObject,
) -> jlong {
    let mut parse = || -> Result<Engine, io::Error> {
        let port = u16::try_from(port)
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "Неверный порт"))?;
        let secret = read_secret(&mut env, &secret)?;
        let json: String = env.get_string(&config).map_err(jni_error)?.into();
        let config = serde_json::from_str(&json)
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "Неверные настройки маршрутов"))?;
        let target = LogTarget {
            vm: env.get_java_vm().map_err(jni_error)?,
            receiver: env.new_global_ref(&logger).map_err(jni_error)?,
        };
        Engine::bind(port, secret, config, Arc::new(target))
    };
    match parse() {
        Ok(engine) => {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            engines().lock().unwrap().insert(id, Arc::new(engine));
            id
        }
        Err(err) => {
            let class = if err.kind() == ErrorKind::AddrInUse {
                "java/net/BindException"
            } else {
                "java/io/IOException"
            };
            let _ = env.throw_new(class, "Не удалось создать локальный сервер");
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_app_telegramws_proxy_RustProxyEngine_nativeServe(
    mut env: JNIEnv,
    _class: JClass,
    id: jlong,
) {
    let engine = engines().lock().unwrap().get(&id).cloned();
    let Some(engine) = engine else { return };
    let result = run_runtime(engine.serve());
    if result.is_err() {
        let _ = env.throw_new(
            "java/io/IOException",
            "Не удалось запустить локальный сервер",
        );
    }
}

#[no_mangle]
pub extern "system" fn Java_app_telegramws_proxy_RustProxyEngine_nativeClose(
    _env: JNIEnv,
    _class: JClass,
    id: jlong,
) {
    let engine = engines().lock().unwrap().remove(&id);
    if let Some(engine) = engine {
        engine.close();
    }
}

#[no_mangle]
pub extern "system" fn Java_app_telegramws_proxy_RustProxyEngine_nativeNetworkChanged(
    _env: JNIEnv,
    _class: JClass,
    id: jlong,
    cellular: jboolean,
) {
    let engine = engines().lock().unwrap().get(&id).cloned();
    if let Some(engine) = engine {
        engine.network_changed(cellular != 0);
    }
}

fn read_secret(env: &mut JNIEnv, secret: &JByteArray) -> io::Result<[u8; 16]> {
    env.convert_byte_array(secret)
        .map_err(jni_error)?
        .try_into()
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "Неверный секрет MTProto"))
}

fn jni_error(_: jni::errors::Error) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "Ошибка параметров прокси")
}

fn run_runtime<T>(future: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(8)
        .build()?;
    let result = runtime.block_on(future);
    runtime.shutdown_timeout(Duration::from_millis(250));
    result
}
