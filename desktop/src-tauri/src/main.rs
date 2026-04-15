#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use axum::{
    body::{to_bytes, Body},
    extract::State as AxumState,
    http::{HeaderName, Request, Response, StatusCode},
    routing::any,
    Router,
};
use chrono::Local;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Manager, State};
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::Shell::ShellExecuteW;
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

const MAX_BODY_SIZE: usize = 50 * 1024 * 1024; // 50 MB

// ── State ──────────────────────────────────────────

#[derive(Clone)]
struct ProxyServerState {
    client: Client,
    routes: HashMap<String, String>, // domain -> upstream URL
    logs: Arc<Mutex<Vec<LogEntry>>>,
}

struct AppState {
    logs: Arc<Mutex<Vec<LogEntry>>>,
    proxy_status: Arc<Mutex<String>>,
    proxy_handle: Arc<Mutex<Option<axum_server::Handle>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            logs: Arc::new(Mutex::new(Vec::new())),
            proxy_status: Arc::new(Mutex::new("stopped".into())),
            proxy_handle: Arc::new(Mutex::new(None)),
        }
    }
}

// ── Data structures ────────────────────────────────

#[derive(Debug, Clone, Serialize)]
struct LogEntry {
    time: String,
    level: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct CommandResult<T: Serialize> {
    ok: bool,
    message: String,
    data: T,
}

#[derive(Debug, Serialize)]
struct ProxyStatus {
    running: bool,
    status: String,
    pid: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RouteConfig {
    domain: String,
    upstream: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct FileConfig {
    listen: ListenConfig,
    routes: Vec<RouteConfig>,
    upstream: UpstreamSharedConfig,
    tls: TlsConfig,
    logging: Option<LoggingConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ListenConfig {
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpstreamSharedConfig {
    timeout_ms: u64,
    reject_unauthorized: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TlsConfig {
    cert_path: String,
    key_path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct LoggingConfig {
    verbose: bool,
}

#[derive(Debug, Clone)]
struct ResolvedProxyConfig {
    listen: ListenConfig,
    routes: HashMap<String, String>,
    upstream: UpstreamSharedConfig,
    tls_cert_path: PathBuf,
    tls_key_path: PathBuf,
}

// ── Helpers ────────────────────────────────────────

fn now_string() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn add_log_arc(logs: &Arc<Mutex<Vec<LogEntry>>>, level: &str, message: impl Into<String>) {
    let entry = LogEntry {
        time: now_string(),
        level: level.to_string(),
        message: message.into(),
    };
    if let Ok(mut logs) = logs.lock() {
        logs.push(entry);
        if logs.len() > 300 {
            let keep_from = logs.len().saturating_sub(300);
            *logs = logs.split_off(keep_from);
        }
    }
}

fn add_log(state: &AppState, level: &str, message: impl Into<String>) {
    add_log_arc(&state.logs, level, message);
}

// ── Windows helpers ────────────────────────────────

#[cfg(target_os = "windows")]
fn to_wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn hosts_file_path() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    PathBuf::from(root)
        .join("System32")
        .join("drivers")
        .join("etc")
        .join("hosts")
}

#[cfg(target_os = "windows")]
fn update_hosts_native(domains: &[String], address: &str, add: bool) -> Result<(), String> {
    let path = hosts_file_path();
    let existing = fs::read_to_string(&path).map_err(|e| e.to_string())?;

    let targets: Vec<String> = domains
        .iter()
        .map(|d| format!("{} {}", address.trim(), d.trim()))
        .collect();

    let mut lines: Vec<String> = existing
        .lines()
        .filter(|line| !targets.iter().any(|t| line.trim() == t.as_str()))
        .map(|line| line.to_string())
        .collect();

    if add {
        for target in &targets {
            lines.push(target.clone());
        }
    }

    let mut next = lines.join("\r\n");
    if !next.ends_with("\r\n") {
        next.push_str("\r\n");
    }
    fs::write(&path, next).map_err(|e| e.to_string())
}

#[cfg(target_os = "windows")]
fn relaunch_elevated(action: &str, domains: &[String], address: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let domains_joined = domains.join(",");
    let params = format!(
        "--hosts-action \"{}\" --domains \"{}\" --address \"{}\"",
        action, domains_joined, address
    );
    let verb = to_wide(OsStr::new("runas"));
    let file = to_wide(exe.as_os_str());
    let parameters = to_wide(OsStr::new(&params));
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            parameters.as_ptr(),
            std::ptr::null(),
            SW_HIDE,
        )
    };
    if result as isize <= 32 {
        Err(format!("无法请求管理员权限，错误码 {}", result as isize))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn maybe_handle_cli_actions() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return None;
    }

    // Handle hosts action: --hosts-action add|remove --domains <d> --address <a>
    if args.get(1).map(String::as_str) == Some("--hosts-action") {
        let action = args.get(2).cloned().unwrap_or_default();
        let domains_raw = args
            .iter()
            .position(|item| item == "--domains")
            .and_then(|idx| args.get(idx + 1))
            .cloned()
            .unwrap_or_else(|| "api.openai.com".into());
        let address = args
            .iter()
            .position(|item| item == "--address")
            .and_then(|idx| args.get(idx + 1))
            .cloned()
            .unwrap_or_else(|| "127.0.0.1".into());

        let domains: Vec<String> = domains_raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let result = match action.as_str() {
            "add" => update_hosts_native(&domains, &address, true),
            "remove" => update_hosts_native(&domains, &address, false),
            "cert-install" => {
                // domains[0] is actually the CA PEM path
                let ca_path = Path::new(&domains_raw);
                install_ca_to_store(ca_path)
            }
            "cert-uninstall" => uninstall_ca_from_store(),
            _ => Err("未知的动作".into()),
        };

        return Some(if result.is_ok() { 0 } else { 1 });
    }

    None
}

// ── Resource management ────────────────────────────

fn resource_root(app: &AppHandle) -> Result<PathBuf, String> {
    app.path().resource_dir().map_err(|e| e.to_string())
}

fn runtime_root(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| e.to_string())?
        .join("runtime");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dst.join(entry.file_name()))?;
        } else {
            fs::copy(entry.path(), dst.join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn ensure_runtime_assets(app: &AppHandle) -> Result<PathBuf, String> {
    let runtime = runtime_root(app)?;
    let target_proxy = runtime.join("proxy-core");
    let target_config_dir = target_proxy.join("config");
    let target_certs_dir = target_proxy.join("certs");
    let config_file = target_config_dir.join("config.json");
    let version_file = target_proxy.join(".version");
    let current_version = env!("CARGO_PKG_VERSION");

    let needs_update = if !target_proxy.exists() {
        true
    } else if let Ok(existing) = fs::read_to_string(&version_file) {
        existing.trim() != current_version
    } else {
        true
    };

    if needs_update {
        // Try to copy from bundled resources (best-effort)
        if let Ok(res) = resource_root(app) {
            let bundled_proxy = res.join("proxy-core");
            if bundled_proxy.is_dir() {
                if target_proxy.exists() {
                    let _ = fs::remove_dir_all(&target_proxy);
                }
                let _ = copy_dir_all(&bundled_proxy, &target_proxy);
            } else {
                // Resources might be at <res>/config/* and <res>/certs/*
                let _ = fs::create_dir_all(&target_config_dir);
                let _ = fs::create_dir_all(&target_certs_dir);
                let src_config = res.join("config");
                let src_certs = res.join("certs");
                if src_config.is_dir() {
                    let _ = copy_dir_all(&src_config, &target_config_dir);
                }
                if src_certs.is_dir() {
                    let _ = copy_dir_all(&src_certs, &target_certs_dir);
                }
            }
        }

        // Ensure directories always exist
        let _ = fs::create_dir_all(&target_config_dir);
        let _ = fs::create_dir_all(&target_certs_dir);

        // If config.json still missing, write a sensible default
        if !config_file.exists() {
            let default_config = serde_json::json!({
                "listen": { "host": "127.0.0.1", "port": 443 },
                "routes": [{ "domain": "api.openai.com", "upstream": "https://proxy-ai.example.com" }],
                "upstream": { "timeoutMs": 600000, "rejectUnauthorized": true },
                "tls": { "certPath": "../certs/cert.pem", "keyPath": "../certs/key.pem" },
                "logging": { "verbose": true }
            });
            let _ = fs::write(&config_file, serde_json::to_string_pretty(&default_config).unwrap_or_default());
        }

        let _ = fs::write(&version_file, current_version);
    }

    Ok(runtime)
}

fn proxy_root(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(ensure_runtime_assets(app)?.join("proxy-core"))
}

fn config_path(app: &AppHandle) -> Result<PathBuf, String> {
    Ok(proxy_root(app)?.join("config").join("config.json"))
}

// ── Config I/O ─────────────────────────────────────

fn read_file_config(app: &AppHandle) -> Result<FileConfig, String> {
    let path = config_path(app)?;
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}

fn write_file_config(app: &AppHandle, value: &Value) -> Result<(), String> {
    let path = config_path(app)?;
    let raw = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    fs::write(path, raw).map_err(|e| e.to_string())
}

fn resolve_proxy_config(app: &AppHandle) -> Result<ResolvedProxyConfig, String> {
    let file = read_file_config(app)?;
    let base_dir = config_path(app)?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "无法确定配置目录".to_string())?;

    let tls_cert_path = resolve_file_path(&base_dir, &file.tls.cert_path)?;
    let tls_key_path = resolve_file_path(&base_dir, &file.tls.key_path)?;

    if !tls_cert_path.exists() {
        return Err(format!("未找到证书文件: {}", tls_cert_path.display()));
    }
    if !tls_key_path.exists() {
        return Err(format!("未找到私钥文件: {}", tls_key_path.display()));
    }

    let mut routes = HashMap::new();
    for route in &file.routes {
        let domain = route.domain.trim().to_lowercase();
        if !domain.is_empty() && !route.upstream.trim().is_empty() {
            routes.insert(domain, route.upstream.trim().to_string());
        }
    }

    if routes.is_empty() {
        return Err("至少需要配置一条有效的路由规则".into());
    }

    Ok(ResolvedProxyConfig {
        listen: file.listen,
        routes,
        upstream: file.upstream,
        tls_cert_path,
        tls_key_path,
    })
}

fn resolve_file_path(base_dir: &Path, raw: &str) -> Result<PathBuf, String> {
    if raw.trim().is_empty() {
        return Err("证书路径未配置".into());
    }
    let path = PathBuf::from(raw);
    Ok(if path.is_absolute() {
        path
    } else {
        base_dir.join(path)
    })
}

// ── Certificate generation ─────────────────────────

fn generate_certs_to_dir(domains: &[String], certs_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(certs_dir).map_err(|e| format!("创建证书目录失败: {e}"))?;

    // Generate CA key pair and self-signed certificate
    let ca_key = KeyPair::generate().map_err(|e| format!("生成 CA 密钥失败: {e}"))?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "DevProxy Local CA");
    ca_params
        .distinguished_name
        .push(DnType::OrganizationName, "DevProxy");
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .map_err(|e| format!("生成 CA 证书失败: {e}"))?;

    // Generate server key pair and certificate signed by the CA
    let server_key = KeyPair::generate().map_err(|e| format!("生成服务器密钥失败: {e}"))?;
    let domain_list: Vec<String> = domains.to_vec();
    if domain_list.is_empty() {
        return Err("没有有效的域名用于生成证书".into());
    }
    let mut server_params =
        CertificateParams::new(domain_list).map_err(|e| format!("创建证书参数失败: {e}"))?;
    if let Some(first) = domains.first() {
        server_params
            .distinguished_name
            .push(DnType::CommonName, first.as_str());
    }
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .map_err(|e| format!("签发服务器证书失败: {e}"))?;

    // Write PEM files
    fs::write(certs_dir.join("ca.pem"), ca_cert.pem())
        .map_err(|e| format!("写入 CA 证书失败: {e}"))?;
    fs::write(certs_dir.join("cert.pem"), server_cert.pem())
        .map_err(|e| format!("写入服务器证书失败: {e}"))?;
    fs::write(certs_dir.join("key.pem"), server_key.serialize_pem())
        .map_err(|e| format!("写入私钥失败: {e}"))?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn install_ca_to_store(ca_pem_path: &Path) -> Result<(), String> {
    let output = ProcessCommand::new("certutil")
        .args(["-addstore", "Root", &ca_pem_path.to_string_lossy()])
        .output()
        .map_err(|e| format!("执行 certutil 失败: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("安装 CA 证书失败: {stderr}"))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn uninstall_ca_from_store() -> Result<(), String> {
    // Use PowerShell to find and remove by subject name
    let script = r#"Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*DevProxy Local CA*' } | Remove-Item -Force"#;
    let output = ProcessCommand::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output()
        .map_err(|e| format!("执行 PowerShell 失败: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(format!("卸载 CA 证书失败: {stderr}"))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn is_ca_installed() -> bool {
    let script = r#"(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*DevProxy Local CA*' }).Count"#;
    let output = ProcessCommand::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .output();
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).trim().to_string();
            stdout.parse::<u32>().unwrap_or(0) > 0
        }
        Err(_) => false,
    }
}

fn get_proxy_status_inner(state: &AppState) -> ProxyStatus {
    let running = state
        .proxy_handle
        .lock()
        .ok()
        .and_then(|handle| handle.as_ref().cloned())
        .is_some();
    let status = state
        .proxy_status
        .lock()
        .map(|s| s.clone())
        .unwrap_or_else(|_| "unknown".into());

    ProxyStatus {
        running,
        status,
        pid: if running { Some(std::process::id()) } else { None },
    }
}

// ── Tauri commands ─────────────────────────────────

#[tauri::command]
fn load_config(app: AppHandle) -> Result<CommandResult<Value>, String> {
    let config = serde_json::to_value(read_file_config(&app)?).map_err(|e| e.to_string())?;
    Ok(CommandResult {
        ok: true,
        message: String::new(),
        data: config,
    })
}

#[tauri::command]
fn save_config(
    app: AppHandle,
    config: Value,
    state: State<AppState>,
) -> Result<CommandResult<Value>, String> {
    write_file_config(&app, &config)?;
    add_log(&state, "INFO", "配置已保存");
    Ok(CommandResult {
        ok: true,
        message: "配置已保存".into(),
        data: config,
    })
}

#[tauri::command]
fn get_status(state: State<AppState>) -> Result<CommandResult<ProxyStatus>, String> {
    Ok(CommandResult {
        ok: true,
        message: String::new(),
        data: get_proxy_status_inner(&state),
    })
}

#[tauri::command]
fn get_logs(state: State<AppState>) -> Result<CommandResult<Vec<LogEntry>>, String> {
    let logs = state
        .logs
        .lock()
        .map(|logs| logs.clone())
        .unwrap_or_default();
    Ok(CommandResult {
        ok: true,
        message: String::new(),
        data: logs,
    })
}

#[tauri::command]
fn clear_logs(state: State<AppState>) -> Result<CommandResult<()>, String> {
    if let Ok(mut logs) = state.logs.lock() {
        logs.clear();
    }
    Ok(CommandResult {
        ok: true,
        message: "日志已清空".into(),
        data: (),
    })
}

#[tauri::command]
fn generate_certs(
    app: AppHandle,
    state: State<AppState>,
) -> Result<CommandResult<()>, String> {
    // Read config to get domains
    let config = read_file_config(&app)?;
    let domains: Vec<String> = config
        .routes
        .iter()
        .map(|r| r.domain.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    if domains.is_empty() {
        return Ok(CommandResult {
            ok: false,
            message: "请先添加至少一条路由规则".into(),
            data: (),
        });
    }

    let certs_dir = proxy_root(&app)?.join("certs");
    generate_certs_to_dir(&domains, &certs_dir)?;

    // Update config.json to point to generated certs
    let mut config_val =
        serde_json::to_value(&config).map_err(|e| e.to_string())?;
    if let Some(tls) = config_val.get_mut("tls").and_then(|v| v.as_object_mut()) {
        tls.insert("certPath".into(), json!("../certs/cert.pem"));
        tls.insert("keyPath".into(), json!("../certs/key.pem"));
    }
    write_file_config(&app, &config_val)?;

    // Try to install CA to trust store (needs admin)
    #[cfg(target_os = "windows")]
    {
        let ca_path = certs_dir.join("ca.pem");
        match install_ca_to_store(&ca_path) {
            Ok(()) => {
                add_log(
                    &state,
                    "INFO",
                    format!("证书已生成并信任 ({})", domains.join(", ")),
                );
                return Ok(CommandResult {
                    ok: true,
                    message: "证书已生成并安装到系统信任库".into(),
                    data: (),
                });
            }
            Err(_) => {
                // Permission denied → try elevated
                let ca_path_str = ca_path.to_string_lossy().to_string();
                relaunch_elevated("cert-install", &[ca_path_str], "")?;
                add_log(&state, "INFO", "证书已生成，正在请求管理员安装信任");
                return Ok(CommandResult {
                    ok: true,
                    message: "证书已生成，已请求管理员确认安装".into(),
                    data: (),
                });
            }
        }
    }

    #[allow(unreachable_code)]
    {
        add_log(
            &state,
            "INFO",
            format!("证书已生成 ({})", domains.join(", ")),
        );
        Ok(CommandResult {
            ok: true,
            message: "证书已生成".into(),
            data: (),
        })
    }
}

#[tauri::command]
fn delete_certs(
    app: AppHandle,
    state: State<AppState>,
) -> Result<CommandResult<()>, String> {
    // Try to remove CA from trust store (needs admin)
    #[cfg(target_os = "windows")]
    {
        match uninstall_ca_from_store() {
            Ok(()) => {
                add_log(&state, "INFO", "已从系统信任库移除 CA 证书");
            }
            Err(_) => {
                // Permission denied → try elevated
                relaunch_elevated("cert-uninstall", &[], "")?;
                add_log(&state, "INFO", "已请求管理员移除 CA 证书");
            }
        }
    }

    // Delete cert files
    let certs_dir = proxy_root(&app)?.join("certs");
    for name in &["ca.pem", "cert.pem", "key.pem"] {
        let _ = fs::remove_file(certs_dir.join(name));
    }

    add_log(&state, "INFO", "本地证书文件已删除");
    Ok(CommandResult {
        ok: true,
        message: "证书已删除并从系统信任库移除".into(),
        data: (),
    })
}

#[tauri::command]
fn check_cert_installed() -> Result<CommandResult<bool>, String> {
    #[cfg(target_os = "windows")]
    {
        let installed = is_ca_installed();
        return Ok(CommandResult {
            ok: true,
            message: String::new(),
            data: installed,
        });
    }

    #[allow(unreachable_code)]
    Ok(CommandResult {
        ok: true,
        message: String::new(),
        data: false,
    })
}

#[tauri::command]
fn check_hosts_written(app: AppHandle) -> Result<CommandResult<bool>, String> {
    let config = match read_file_config(&app) {
        Ok(c) => c,
        Err(_) => {
            return Ok(CommandResult {
                ok: true,
                message: String::new(),
                data: false,
            })
        }
    };

    let domains: Vec<String> = config
        .routes
        .iter()
        .map(|r| r.domain.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    if domains.is_empty() {
        return Ok(CommandResult {
            ok: true,
            message: String::new(),
            data: false,
        });
    }

    #[cfg(target_os = "windows")]
    {
        let hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
        let content = match fs::read_to_string(hosts_path) {
            Ok(c) => c.to_lowercase(),
            Err(_) => {
                return Ok(CommandResult {
                    ok: true,
                    message: String::new(),
                    data: false,
                })
            }
        };
        let all_written = domains.iter().all(|d| {
            content.lines().any(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with('#') {
                    return false;
                }
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                parts.len() >= 2 && parts[1..].iter().any(|p| *p == d.as_str())
            })
        });
        return Ok(CommandResult {
            ok: true,
            message: String::new(),
            data: all_written,
        });
    }

    #[allow(unreachable_code)]
    Ok(CommandResult {
        ok: true,
        message: String::new(),
        data: false,
    })
}

#[tauri::command]
fn start_proxy(
    app: AppHandle,
    state: State<AppState>,
) -> Result<CommandResult<ProxyStatus>, String> {
    if state
        .proxy_handle
        .lock()
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Ok(CommandResult {
            ok: true,
            message: "代理已在运行".into(),
            data: get_proxy_status_inner(&state),
        });
    }

    let config = resolve_proxy_config(&app)?;
    let addr = format!("{}:{}", config.listen.host, config.listen.port)
        .parse()
        .map_err(|e| format!("监听地址无效: {e}"))?;

    let client = Client::builder()
        .timeout(Duration::from_millis(config.upstream.timeout_ms))
        .danger_accept_invalid_certs(!config.upstream.reject_unauthorized)
        .build()
        .map_err(|e| e.to_string())?;

    let route_display: Vec<String> = config
        .routes
        .iter()
        .map(|(d, u)| format!("{d} -> {u}"))
        .collect();

    let server_state = ProxyServerState {
        client,
        routes: config.routes.clone(),
        logs: state.logs.clone(),
    };

    let app_router = Router::new()
        .fallback(any(proxy_handler))
        .with_state(server_state);

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    let status = state.proxy_status.clone();
    let logs = state.logs.clone();
    let proxy_handle_ref = state.proxy_handle.clone();
    let cert_path = config.tls_cert_path.clone();
    let key_path = config.tls_key_path.clone();

    if let Ok(mut slot) = state.proxy_handle.lock() {
        *slot = Some(shutdown_handle);
    }
    if let Ok(mut current) = status.lock() {
        *current = "running".into();
    }

    add_log(
        &state,
        "INFO",
        format!(
            "正在启动原生代理 -> https://{}:{}",
            config.listen.host, config.listen.port
        ),
    );
    for line in &route_display {
        add_log(&state, "INFO", format!("路由: {line}"));
    }

    tauri::async_runtime::spawn(async move {
        let tls = match axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
            .await
        {
            Ok(value) => value,
            Err(error) => {
                add_log_arc(&logs, "ERROR", format!("加载 TLS 证书失败: {error}"));
                if let Ok(mut current) = status.lock() {
                    *current = "stopped".into();
                }
                if let Ok(mut slot) = proxy_handle_ref.lock() {
                    *slot = None;
                }
                return;
            }
        };

        add_log_arc(&logs, "INFO", "代理已启动");
        let result = axum_server::bind_rustls(addr, tls)
            .handle(handle)
            .serve(app_router.into_make_service())
            .await;

        if let Err(error) = result {
            add_log_arc(&logs, "ERROR", format!("原生代理运行异常: {error}"));
        }

        if let Ok(mut current) = status.lock() {
            *current = "stopped".into();
        }
        if let Ok(mut slot) = proxy_handle_ref.lock() {
            *slot = None;
        }
        add_log_arc(&logs, "INFO", "原生代理已停止");
    });

    Ok(CommandResult {
        ok: true,
        message: "代理启动命令已发送".into(),
        data: get_proxy_status_inner(&state),
    })
}

#[tauri::command]
fn stop_proxy(state: State<AppState>) -> Result<CommandResult<ProxyStatus>, String> {
    if let Ok(mut handle) = state.proxy_handle.lock() {
        if let Some(existing) = handle.take() {
            existing.graceful_shutdown(Some(Duration::from_secs(2)));
        }
    }
    if let Ok(mut current) = state.proxy_status.lock() {
        *current = "stopping".into();
    }
    add_log(&state, "INFO", "正在停止代理");
    Ok(CommandResult {
        ok: true,
        message: "代理停止命令已发送".into(),
        data: get_proxy_status_inner(&state),
    })
}

#[tauri::command]
fn add_hosts(
    app: AppHandle,
    state: State<AppState>,
) -> Result<CommandResult<ProxyStatus>, String> {
    handle_hosts_action(&app, &state, true, "写入 hosts")
}

#[tauri::command]
fn remove_hosts(
    app: AppHandle,
    state: State<AppState>,
) -> Result<CommandResult<ProxyStatus>, String> {
    handle_hosts_action(&app, &state, false, "恢复 hosts")
}

fn handle_hosts_action(
    app: &AppHandle,
    state: &AppState,
    add: bool,
    action_name: &str,
) -> Result<CommandResult<ProxyStatus>, String> {
    let config = read_file_config(app)?;
    let address = &config.listen.host;
    let domains: Vec<String> = config
        .routes
        .iter()
        .map(|r| r.domain.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    if domains.is_empty() {
        return Ok(CommandResult {
            ok: false,
            message: "没有配置任何路由域名".into(),
            data: get_proxy_status_inner(state),
        });
    }

    #[cfg(target_os = "windows")]
    {
        match update_hosts_native(&domains, address, add) {
            Ok(()) => {
                for domain in &domains {
                    add_log(
                        state,
                        "INFO",
                        format!("{action_name}: {domain} -> {address}"),
                    );
                }
                return Ok(CommandResult {
                    ok: true,
                    message: format!("{action_name} 已完成 ({} 条)", domains.len()),
                    data: get_proxy_status_inner(state),
                });
            }
            Err(error)
                if error.contains("拒绝访问") || error.contains("Access is denied") =>
            {
                relaunch_elevated(
                    if add { "add" } else { "remove" },
                    &domains,
                    address,
                )?;
                add_log(state, "INFO", format!("{action_name}: 已请求管理员确认"));
                return Ok(CommandResult {
                    ok: true,
                    message: format!("{action_name} 已请求管理员确认"),
                    data: get_proxy_status_inner(state),
                });
            }
            Err(error) => {
                add_log(state, "ERROR", format!("{action_name} 失败: {error}"));
                return Ok(CommandResult {
                    ok: false,
                    message: error,
                    data: get_proxy_status_inner(state),
                });
            }
        }
    }

    #[allow(unreachable_code)]
    Ok(CommandResult {
        ok: false,
        message: "当前平台暂不支持 hosts 原生管理".into(),
        data: get_proxy_status_inner(state),
    })
}

// ── Proxy handler ──────────────────────────────────

async fn proxy_handler(
    AxumState(state): AxumState<ProxyServerState>,
    req: Request<Body>,
) -> Response<Body> {
    let request_id = Local::now().format("%H%M%S%3f").to_string();
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    let body_bytes = match to_bytes(req.into_body(), MAX_BODY_SIZE).await {
        Ok(bytes) => bytes,
        Err(error) => {
            add_log_arc(
                &state.logs,
                "ERROR",
                format!("[{request_id}] 读取请求体失败: {error}"),
            );
            return json_error(
                StatusCode::BAD_REQUEST,
                format!("读取请求体失败: {error}"),
            );
        }
    };

    let host_header = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(':').next().unwrap_or_default().to_lowercase())
        .or_else(|| {
            uri.host().map(|h| h.to_lowercase())
        })
        .unwrap_or_default();

    let upstream_base = match state.routes.get(&host_header) {
        Some(url) => url.clone(),
        None => {
            add_log_arc(
                &state.logs,
                "WARN",
                format!("[{request_id}] 未匹配路由 Host: {host_header}"),
            );
            return json_error(
                StatusCode::NOT_FOUND,
                format!("未配置域名路由: {host_header}"),
            );
        }
    };

    let upstream_url = build_upstream_url(&upstream_base, &uri);
    let upstream_url_string = upstream_url.to_string();
    let mut builder = state
        .client
        .request(method.clone(), upstream_url_string.clone());

    for (name, value) in headers.iter() {
        let key = name.as_str();
        if key.eq_ignore_ascii_case("host") || key.eq_ignore_ascii_case("content-length") {
            continue;
        }
        builder = builder.header(name, value);
    }

    if let Some(host) = upstream_url.host_str() {
        builder = builder.header("host", host);
    }
    builder = builder.header("x-forwarded-proto", "https");

    let upstream_response = match builder.body(body_bytes).send().await {
        Ok(value) => value,
        Err(error) => {
            add_log_arc(
                &state.logs,
                "ERROR",
                format!("[{request_id}] 上游请求失败: {error}"),
            );
            return json_error(
                if error.is_timeout() {
                    StatusCode::GATEWAY_TIMEOUT
                } else {
                    StatusCode::BAD_GATEWAY
                },
                error.to_string(),
            );
        }
    };

    let status = upstream_response.status();
    let upstream_headers = upstream_response.headers().clone();
    let stream = upstream_response.bytes_stream();

    add_log_arc(
        &state.logs,
        "INFO",
        format!(
            "[{request_id}] {} {} -> {} {}",
            method, uri, upstream_url_string, status
        ),
    );

    let mut response = Response::builder().status(status);
    for (name, value) in upstream_headers.iter() {
        if should_skip_response_header(name) {
            continue;
        }
        response = response.header(name, value);
    }

    response
        .body(Body::from_stream(stream))
        .unwrap_or_else(|error| json_error(StatusCode::BAD_GATEWAY, error.to_string()))
}

fn build_upstream_url(base_url: &str, uri: &axum::http::Uri) -> reqwest::Url {
    let base = if base_url.ends_with('/') {
        base_url.to_string()
    } else {
        format!("{base_url}/")
    };
    let mut upstream = reqwest::Url::parse(&base).expect("上游地址格式无效");
    let path = uri.path().trim_start_matches('/');
    upstream.set_path(path);
    upstream.set_query(uri.query());
    upstream
}

fn should_skip_response_header(name: &HeaderName) -> bool {
    let lower = name.as_str();
    lower == "content-length" || lower == "transfer-encoding"
}

fn json_error(status: StatusCode, message: String) -> Response<Body> {
    let body = json!({
        "error": {
            "message": message,
            "type": "proxy_error"
        }
    })
    .to_string();

    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
}

// ── Entry point ────────────────────────────────────

fn main() {
    #[cfg(target_os = "windows")]
    if let Some(code) = maybe_handle_cli_actions() {
        std::process::exit(code);
    }

    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            load_config,
            save_config,
            get_status,
            get_logs,
            clear_logs,
            generate_certs,
            delete_certs,
            check_cert_installed,
            check_hosts_written,
            start_proxy,
            stop_proxy,
            add_hosts,
            remove_hosts
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let state: tauri::State<AppState> = window.state();
                let shutdown_handle = state.proxy_handle.lock().ok()
                    .and_then(|mut g| g.take());
                if let Some(h) = shutdown_handle {
                    h.graceful_shutdown(Some(std::time::Duration::from_millis(800)));
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
