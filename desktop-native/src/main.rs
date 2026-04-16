#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use axum::{
    body::{to_bytes, Body},
    extract::State as AxumState,
    http::{HeaderName, Request, Response, StatusCode},
    routing::any,
    Router,
};
use chrono::Local;
use eframe::egui;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::Shell::ShellExecuteW;
#[cfg(target_os = "windows")]
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

const MAX_BODY_SIZE: usize = 50 * 1024 * 1024;
const HOSTS_BEGIN_MARKER: &str = "# >>> DEVPROXY MANAGED START >>>";
const HOSTS_END_MARKER: &str = "# <<< DEVPROXY MANAGED END <<<";

fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

// ── Data structures ────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LogEntry {
    time: String,
    level: String,
    message: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct UiConfigSnapshot {
    routes: Vec<(String, String)>,
    listen_host: String,
    listen_port: String,
    timeout_ms: String,
    reject_unauthorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedHostsState {
    address: String,
    domains: Vec<String>,
}

// ── Proxy server state ────────────────────────────

#[derive(Clone)]
struct ProxyServerState {
    client: Client,
    routes: HashMap<String, String>,
    logs: Arc<Mutex<Vec<LogEntry>>>,
}

// ── Shared app state ──────────────────────────────

struct SharedState {
    logs: Arc<Mutex<Vec<LogEntry>>>,
    proxy_status: Arc<Mutex<String>>,
    proxy_handle: Arc<Mutex<Option<axum_server::Handle>>>,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            logs: Arc::new(Mutex::new(Vec::new())),
            proxy_status: Arc::new(Mutex::new("stopped".into())),
            proxy_handle: Arc::new(Mutex::new(None)),
        }
    }
}

// ── Helpers ────────────────────────────────────────

fn now_string() -> String {
    Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn add_log_arc(logs: &Arc<Mutex<Vec<LogEntry>>>, level: &str, message: impl Into<String>) {
    if let Ok(mut logs) = logs.lock() {
        logs.push(LogEntry {
            time: now_string(),
            level: level.to_string(),
            message: message.into(),
        });
        if logs.len() > 300 {
            let keep_from = logs.len().saturating_sub(300);
            *logs = logs.split_off(keep_from);
        }
    }
}

fn normalize_domains_from_inputs(domains: &[String]) -> Vec<String> {
    let mut ordered = Vec::new();
    let mut seen = HashSet::new();
    for domain in domains {
        let normalized = domain.trim().to_lowercase();
        if !normalized.is_empty() && seen.insert(normalized.clone()) {
            ordered.push(normalized);
        }
    }
    ordered
}

fn normalize_domains_from_routes(routes: &[(String, String)]) -> Vec<String> {
    let raw: Vec<String> = routes.iter().map(|(domain, _)| domain.clone()).collect();
    normalize_domains_from_inputs(&raw)
}

fn normalize_domains_from_config(routes: &[RouteConfig]) -> Vec<String> {
    let raw: Vec<String> = routes.iter().map(|route| route.domain.clone()).collect();
    normalize_domains_from_inputs(&raw)
}

fn cert_files_exist() -> bool {
    let dir = certs_dir();
    dir.join("ca.pem").exists() && dir.join("cert.pem").exists() && dir.join("key.pem").exists()
}

// ── Path helpers ──────────────────────────────────

fn data_dir() -> PathBuf {
    let base = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::current_dir().unwrap_or_default());
    let dir = base.join("devproxy").join("runtime").join("proxy-core");
    let _ = fs::create_dir_all(&dir);
    let _ = fs::create_dir_all(dir.join("config"));
    let _ = fs::create_dir_all(dir.join("certs"));
    dir
}

fn config_path() -> PathBuf {
    data_dir().join("config").join("config.json")
}

fn certs_dir() -> PathBuf {
    data_dir().join("certs")
}

#[cfg(target_os = "windows")]
fn check_cert_ready() -> bool {
    cert_files_exist() && is_ca_installed()
}

#[cfg(not(target_os = "windows"))]
fn check_cert_ready() -> bool {
    cert_files_exist()
}

// ── Config I/O ────────────────────────────────────

fn read_config() -> Result<FileConfig, String> {
    let path = config_path();
    if !path.exists() {
        let default = default_config();
        let raw = serde_json::to_string_pretty(&default).unwrap();
        let _ = fs::write(&path, &raw);
        return Ok(default);
    }
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&raw).map_err(|e| e.to_string())
}

fn write_config(config: &FileConfig) -> Result<(), String> {
    let path = config_path();
    let raw = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    fs::write(path, raw).map_err(|e| e.to_string())
}

fn default_config() -> FileConfig {
    FileConfig {
        listen: ListenConfig {
            host: "127.0.0.1".into(),
            port: 443,
        },
        routes: vec![RouteConfig {
            domain: "api.openai.com".into(),
            upstream: "https://proxy-ai.example.com".into(),
        }],
        upstream: UpstreamSharedConfig {
            timeout_ms: 600000,
            reject_unauthorized: true,
        },
        tls: TlsConfig {
            cert_path: "../certs/cert.pem".into(),
            key_path: "../certs/key.pem".into(),
        },
        logging: Some(LoggingConfig { verbose: true }),
    }
}

// ── Certificate generation ────────────────────────

fn generate_certs(domains: &[String]) -> Result<(), String> {
    let dir = certs_dir();
    fs::create_dir_all(&dir).map_err(|e| format!("创建证书目录失败: {e}"))?;

    let ca_key = KeyPair::generate().map_err(|e| format!("生成 CA 密钥失败: {e}"))?;
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name.push(DnType::CommonName, "DevProxy Local CA");
    ca_params.distinguished_name.push(DnType::OrganizationName, "DevProxy");
    let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| format!("生成 CA 证书失败: {e}"))?;

    let server_key = KeyPair::generate().map_err(|e| format!("生成服务器密钥失败: {e}"))?;
    let mut server_params = CertificateParams::new(domains.to_vec()).map_err(|e| format!("创建证书参数失败: {e}"))?;
    if let Some(first) = domains.first() {
        server_params.distinguished_name.push(DnType::CommonName, first.as_str());
    }
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key).map_err(|e| format!("签发服务器证书失败: {e}"))?;

    fs::write(dir.join("ca.pem"), ca_cert.pem()).map_err(|e| format!("写入 CA 证书失败: {e}"))?;
    fs::write(dir.join("cert.pem"), server_cert.pem()).map_err(|e| format!("写入服务器证书失败: {e}"))?;
    fs::write(dir.join("key.pem"), server_key.serialize_pem()).map_err(|e| format!("写入私钥失败: {e}"))?;

    Ok(())
}

// ── Windows-specific ──────────────────────────────

#[cfg(target_os = "windows")]
fn to_wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn hosts_file_path() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
    PathBuf::from(root).join("System32").join("drivers").join("etc").join("hosts")
}

#[cfg(target_os = "windows")]
fn hosts_line_matches_domains(line: &str, domains: &HashSet<String>) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    parts.len() >= 2 && parts[1..].iter().any(|part| domains.contains(&part.to_lowercase()))
}

#[cfg(target_os = "windows")]
fn update_hosts_native(domains: &[String], address: &str, add: bool) -> Result<(), String> {
    let path = hosts_file_path();
    let existing = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let normalized_domains = normalize_domains_from_inputs(domains);
    if normalized_domains.is_empty() {
        return Ok(());
    }

    let domain_set: HashSet<String> = normalized_domains.iter().cloned().collect();
    let normalized_address = address.trim().to_lowercase();
    let mut lines = Vec::new();
    let mut in_managed_block = false;

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed == HOSTS_BEGIN_MARKER {
            in_managed_block = true;
            continue;
        }
        if trimmed == HOSTS_END_MARKER {
            in_managed_block = false;
            continue;
        }
        if in_managed_block || hosts_line_matches_domains(trimmed, &domain_set) {
            continue;
        }
        lines.push(line.to_string());
    }

    if add {
        if lines.last().map(|line| !line.trim().is_empty()).unwrap_or(false) {
            lines.push(String::new());
        }
        lines.push(HOSTS_BEGIN_MARKER.to_string());
        for domain in &normalized_domains {
            lines.push(format!("{} {}", normalized_address, domain));
        }
        lines.push(HOSTS_END_MARKER.to_string());
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
    let params = format!("--hosts-action \"{}\" --domains \"{}\" --address \"{}\"", action, domains_joined, address);
    let verb = to_wide(OsStr::new("runas"));
    let file = to_wide(exe.as_os_str());
    let parameters = to_wide(OsStr::new(&params));
    let result = unsafe {
        ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), parameters.as_ptr(), std::ptr::null(), SW_HIDE)
    };
    if result as isize <= 32 {
        Err(format!("无法请求管理员权限，错误码 {}", result as isize))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn install_ca_to_store(ca_pem_path: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let output = ProcessCommand::new("certutil")
        .args(["-addstore", "Root", &ca_pem_path.to_string_lossy()])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("执行 certutil 失败: {e}"))?;
    if !output.status.success() {
        Err(format!("安装 CA 证书失败: {}", String::from_utf8_lossy(&output.stderr)))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn uninstall_ca_from_store() -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let script = r#"
$ErrorActionPreference = 'Stop'
$stores = @('Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root')

foreach ($store in $stores) {
    $matches = @(Get-ChildItem $store | Where-Object { $_.Subject -like '*DevProxy Local CA*' })
    foreach ($item in $matches) {
        Remove-Item -LiteralPath $item.PSPath -Force -ErrorAction Stop
    }
}

$remaining = @()
foreach ($store in $stores) {
    $remaining += Get-ChildItem $store | Where-Object { $_.Subject -like '*DevProxy Local CA*' }
}

if ($remaining.Count -gt 0) {
    Write-Error "仍有 $($remaining.Count) 张 DevProxy CA 未删除"
}
"#;
    let output = ProcessCommand::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("执行 PowerShell 失败: {e}"))?;
    if !output.status.success() {
        Err(format!("卸载 CA 证书失败: {}", String::from_utf8_lossy(&output.stderr)))
    } else {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn is_ca_installed() -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    let script = r#"
$machine = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like '*DevProxy Local CA*' }).Count
$user = @(Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -like '*DevProxy Local CA*' }).Count
$machine + $user
"#;
    let output = ProcessCommand::new("powershell")
        .args(["-NoProfile", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match output {
        Ok(o) => String::from_utf8_lossy(&o.stdout).trim().parse::<u32>().unwrap_or(0) > 0,
        Err(_) => false,
    }
}

#[cfg(target_os = "windows")]
fn check_hosts_written(domains: &[String], address: &str) -> bool {
    let hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    let content = match fs::read_to_string(hosts_path) {
        Ok(c) => c.to_lowercase(),
        Err(_) => return false,
    };
    let normalized_domains = normalize_domains_from_inputs(domains);
    let normalized_address = address.trim().to_lowercase();
    normalized_domains.iter().all(|d| {
        content.lines().any(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('#') { return false; }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            parts.len() >= 2
                && parts[0] == normalized_address
                && parts[1..].iter().any(|p| *p == d.as_str())
        })
    })
}

#[cfg(target_os = "windows")]
fn maybe_handle_cli_actions() -> Option<i32> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { return None; }
    if args.get(1).map(String::as_str) != Some("--hosts-action") { return None; }

    let action = args.get(2).cloned().unwrap_or_default();
    let domains_raw = args.iter().position(|item| item == "--domains")
        .and_then(|idx| args.get(idx + 1)).cloned().unwrap_or_else(|| "api.openai.com".into());
    let address = args.iter().position(|item| item == "--address")
        .and_then(|idx| args.get(idx + 1)).cloned().unwrap_or_else(|| "127.0.0.1".into());
    let domains: Vec<String> = domains_raw.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();

    let result = match action.as_str() {
        "add" => update_hosts_native(&domains, &address, true),
        "remove" => update_hosts_native(&domains, &address, false),
        "cert-install" => install_ca_to_store(Path::new(&domains_raw)),
        "cert-uninstall" => uninstall_ca_from_store(),
        _ => Err("未知的动作".into()),
    };
    Some(if result.is_ok() { 0 } else { 1 })
}

// ── Proxy handler ─────────────────────────────────

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
            add_log_arc(&state.logs, "ERROR", format!("[{request_id}] 读取请求体失败: {error}"));
            return json_error(StatusCode::BAD_REQUEST, format!("读取请求体失败: {error}"));
        }
    };

    let host_header = headers.get("host")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(':').next().unwrap_or_default().to_lowercase())
        .or_else(|| uri.host().map(|h| h.to_lowercase()))
        .unwrap_or_default();

    let upstream_base = match state.routes.get(&host_header) {
        Some(url) => url.clone(),
        None => {
            add_log_arc(&state.logs, "WARN", format!("[{request_id}] 未匹配路由 Host: {host_header}"));
            return json_error(StatusCode::NOT_FOUND, format!("未配置域名路由: {host_header}"));
        }
    };

    let upstream_url = match build_upstream_url(&upstream_base, &uri) {
        Ok(url) => url,
        Err(error) => {
            add_log_arc(&state.logs, "ERROR", format!("[{request_id}] 构造上游地址失败: {error}"));
            return json_error(StatusCode::BAD_GATEWAY, error);
        }
    };
    let upstream_url_string = upstream_url.to_string();
    let mut builder = state.client.request(method.clone(), upstream_url_string.clone());

    for (name, value) in headers.iter() {
        let key = name.as_str();
        if key.eq_ignore_ascii_case("host") || key.eq_ignore_ascii_case("content-length") { continue; }
        builder = builder.header(name, value);
    }
    if let Some(host) = upstream_url.host_str() {
        builder = builder.header("host", host);
    }
    builder = builder.header("x-forwarded-proto", "https");

    let upstream_response = match builder.body(body_bytes).send().await {
        Ok(value) => value,
        Err(error) => {
            add_log_arc(&state.logs, "ERROR", format!("[{request_id}] 上游请求失败: {error}"));
            return json_error(
                if error.is_timeout() { StatusCode::GATEWAY_TIMEOUT } else { StatusCode::BAD_GATEWAY },
                error.to_string(),
            );
        }
    };

    let status = upstream_response.status();
    let upstream_headers = upstream_response.headers().clone();
    let stream = upstream_response.bytes_stream();

    add_log_arc(&state.logs, "INFO", format!("[{request_id}] {} {} -> {} {}", method, uri, upstream_url_string, status));

    let mut response = Response::builder().status(status);
    for (name, value) in upstream_headers.iter() {
        if should_skip_response_header(name) { continue; }
        response = response.header(name, value);
    }
    response.body(Body::from_stream(stream)).unwrap_or_else(|error| json_error(StatusCode::BAD_GATEWAY, error.to_string()))
}

fn build_upstream_url(base_url: &str, uri: &axum::http::Uri) -> Result<reqwest::Url, String> {
    let base = if base_url.ends_with('/') { base_url.to_string() } else { format!("{base_url}/") };
    let mut upstream = reqwest::Url::parse(&base).map_err(|error| format!("上游地址格式无效: {error}"))?;
    upstream.set_path(uri.path().trim_start_matches('/'));
    upstream.set_query(uri.query());
    Ok(upstream)
}

fn should_skip_response_header(name: &HeaderName) -> bool {
    let lower = name.as_str();
    lower == "content-length" || lower == "transfer-encoding"
}

fn json_error(status: StatusCode, message: String) -> Response<Body> {
    let body = json!({ "error": { "message": message, "type": "proxy_error" } }).to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
}

// ── egui App ──────────────────────────────────────

struct DevProxyApp {
    state: Arc<SharedState>,
    runtime: tokio::runtime::Runtime,
    // UI state
    routes: Vec<(String, String)>,
    listen_host: String,
    listen_port: String,
    timeout_ms: String,
    reject_unauthorized: bool,
    notice: String,
    notice_type: String, // "success", "error", ""
    notice_time: std::time::Instant,
    show_advanced: bool,
    cert_installed: bool,
    cert_domains: Vec<String>,
    hosts_written: bool,
    hosts_state: Option<ManagedHostsState>,
    config_saved: bool,
    saved_ui_snapshot: UiConfigSnapshot,
}

impl DevProxyApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_fonts(&cc.egui_ctx);
        let (config, config_saved) = match read_config() {
            Ok(config) => (config, true),
            Err(_) => (default_config(), false),
        };
        let routes: Vec<(String, String)> = if config.routes.is_empty() {
            vec![("api.openai.com".into(), String::new())]
        } else {
            config.routes.iter().map(|r| (r.domain.clone(), r.upstream.clone())).collect()
        };

        let state = Arc::new(SharedState::default());
        let domains = normalize_domains_from_config(&config.routes);

        #[cfg(target_os = "windows")]
        let cert_installed = check_cert_ready();
        #[cfg(not(target_os = "windows"))]
        let cert_installed = check_cert_ready();
        let cert_domains = if cert_installed { domains.clone() } else { Vec::new() };
        #[cfg(target_os = "windows")]
        let hosts_written = if !domains.is_empty() {
            check_hosts_written(&domains, &config.listen.host)
        } else {
            false
        };
        #[cfg(not(target_os = "windows"))]
        let hosts_written = false;
        let hosts_state = if hosts_written {
            Some(ManagedHostsState {
                address: config.listen.host.trim().to_lowercase(),
                domains: domains.clone(),
            })
        } else {
            None
        };

        let saved_ui_snapshot = UiConfigSnapshot {
            routes: routes.clone(),
            listen_host: config.listen.host.clone(),
            listen_port: config.listen.port.to_string(),
            timeout_ms: config.upstream.timeout_ms.to_string(),
            reject_unauthorized: config.upstream.reject_unauthorized,
        };
        Self {
            state,
            runtime: tokio::runtime::Runtime::new().unwrap(),
            routes,
            listen_host: config.listen.host,
            listen_port: config.listen.port.to_string(),
            timeout_ms: config.upstream.timeout_ms.to_string(),
            reject_unauthorized: config.upstream.reject_unauthorized,
            notice: String::new(),
            notice_type: String::new(),
            notice_time: std::time::Instant::now(),
            show_advanced: false,
            cert_installed,
            cert_domains,
            hosts_written,
            hosts_state,
            config_saved,
            saved_ui_snapshot,
        }
    }

    fn set_notice(&mut self, msg: &str, ntype: &str) {
        self.notice = msg.into();
        self.notice_type = ntype.into();
        self.notice_time = std::time::Instant::now();
    }

    fn current_ui_snapshot(&self) -> UiConfigSnapshot {
        UiConfigSnapshot {
            routes: self.routes.clone(),
            listen_host: self.listen_host.clone(),
            listen_port: self.listen_port.clone(),
            timeout_ms: self.timeout_ms.clone(),
            reject_unauthorized: self.reject_unauthorized,
        }
    }

    fn build_managed_hosts_state(&self) -> Result<ManagedHostsState, String> {
        let address = self.listen_host.trim().to_lowercase();
        if address.is_empty() {
            return Err("监听地址不能为空".into());
        }

        let mut domains = Vec::new();
        let mut seen = HashSet::new();
        for (idx, (domain_input, upstream_input)) in self.routes.iter().enumerate() {
            let domain = domain_input.trim().to_lowercase();
            let upstream = upstream_input.trim();
            if domain.is_empty() && upstream.is_empty() {
                continue;
            }
            if domain.is_empty() {
                return Err(format!("第 {} 条路由缺少域名", idx + 1));
            }
            if !seen.insert(domain.clone()) {
                return Err(format!("域名 \"{}\" 重复，每个域名只能配置一条规则", domain));
            }
            domains.push(domain);
        }

        if domains.is_empty() {
            return Err("至少需要一条路由规则".into());
        }

        Ok(ManagedHostsState { address, domains })
    }

    fn build_validated_config(&self) -> Result<FileConfig, String> {
        let listen_host = self.listen_host.trim();
        if listen_host.is_empty() {
            return Err("监听地址不能为空".into());
        }

        let listen_port: u16 = self.listen_port
            .trim()
            .parse()
            .map_err(|_| "监听端口必须是 1-65535 之间的数字".to_string())?;
        if listen_port == 0 {
            return Err("监听端口必须是 1-65535 之间的数字".into());
        }

        let timeout_ms: u64 = self.timeout_ms
            .trim()
            .parse()
            .map_err(|_| "上游超时必须是正整数(ms)".to_string())?;
        if timeout_ms == 0 {
            return Err("上游超时必须大于 0".into());
        }

        let mut routes = Vec::new();
        let mut seen = HashSet::new();
        for (idx, (domain_input, upstream_input)) in self.routes.iter().enumerate() {
            let domain = domain_input.trim().to_lowercase();
            let upstream = upstream_input.trim();
            if domain.is_empty() && upstream.is_empty() {
                continue;
            }
            if domain.is_empty() {
                return Err(format!("第 {} 条路由缺少域名", idx + 1));
            }
            if upstream.is_empty() {
                return Err(format!("域名 {} 的上游地址不能为空", domain));
            }
            if !seen.insert(domain.clone()) {
                return Err(format!("域名 \"{}\" 重复，每个域名只能配置一条规则", domain));
            }

            let parsed = reqwest::Url::parse(upstream)
                .map_err(|error| format!("第 {} 条路由的上游地址无效: {error}", idx + 1))?;
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(format!("域名 {} 的上游地址必须以 http:// 或 https:// 开头", domain));
            }
            if parsed.host_str().is_none() {
                return Err(format!("域名 {} 的上游地址缺少主机名", domain));
            }

            routes.push(RouteConfig {
                domain,
                upstream: upstream.to_string(),
            });
        }

        if routes.is_empty() {
            return Err("至少需要一条路由规则".into());
        }

        Ok(FileConfig {
            listen: ListenConfig {
                host: listen_host.to_string(),
                port: listen_port,
            },
            routes,
            upstream: UpstreamSharedConfig {
                timeout_ms,
                reject_unauthorized: self.reject_unauthorized,
            },
            tls: TlsConfig {
                cert_path: "../certs/cert.pem".into(),
                key_path: "../certs/key.pem".into(),
            },
            logging: Some(LoggingConfig { verbose: true }),
        })
    }

    fn is_proxy_running(&self) -> bool {
        self.state.proxy_handle.lock().ok().and_then(|h| h.as_ref().cloned()).is_some()
    }

    fn proxy_status_text(&self) -> &str {
        if self.is_proxy_running() { "运行中" } else {
            let s = self.state.proxy_status.lock().ok().map(|s| s.clone()).unwrap_or_default();
            if s == "stopping" { "停止中" } else { "未启动" }
        }
    }

    fn do_save_config(&mut self) {
        let config = match self.build_validated_config() {
            Ok(config) => config,
            Err(error) => {
                self.set_notice(&error, "error");
                return;
            }
        };
        let domains_changed = normalize_domains_from_config(&config.routes) != self.cert_domains;
        match write_config(&config) {
            Ok(()) => {
                self.routes = config.routes.iter()
                    .map(|route| (route.domain.clone(), route.upstream.clone()))
                    .collect();
                self.listen_host = config.listen.host.clone();
                self.listen_port = config.listen.port.to_string();
                self.timeout_ms = config.upstream.timeout_ms.to_string();
                self.reject_unauthorized = config.upstream.reject_unauthorized;
                self.config_saved = true;
                self.saved_ui_snapshot = self.current_ui_snapshot();
                if domains_changed {
                    self.cert_installed = false;
                } else {
                    self.cert_installed = check_cert_ready();
                }

                #[cfg(target_os = "windows")]
                {
                    let new_domains = normalize_domains_from_config(&config.routes);
                    self.hosts_written = if !new_domains.is_empty() {
                        check_hosts_written(&new_domains, &config.listen.host)
                    } else {
                        false
                    };
                    self.hosts_state = if self.hosts_written {
                        Some(ManagedHostsState {
                            address: config.listen.host.trim().to_lowercase(),
                            domains: new_domains,
                        })
                    } else {
                        None
                    };
                }
                #[cfg(not(target_os = "windows"))]
                {
                    self.hosts_written = false;
                    self.hosts_state = None;
                }

                if domains_changed {
                    self.set_notice("配置已保存；域名变更后请重新生成证书", "success");
                } else {
                    self.set_notice("配置已保存", "success");
                }
            }
            Err(e) => self.set_notice(&format!("保存失败: {e}"), "error"),
        }
    }

    fn do_generate_certs(&mut self) {
        // Always allow regeneration (new domains need new cert even if CA is already trusted)
        let domains = match self.build_managed_hosts_state() {
            Ok(state) => state.domains,
            Err(error) => {
                self.set_notice(&error, "error");
                return;
            }
        };
        if let Err(e) = generate_certs(&domains) {
            self.set_notice(&format!("生成证书失败: {e}"), "error");
            return;
        }
        #[cfg(target_os = "windows")]
        {
            let ca_path = certs_dir().join("ca.pem");
            match install_ca_to_store(&ca_path) {
                Ok(()) => {
                    self.cert_domains = domains.clone();
                    self.cert_installed = true;
                    add_log_arc(&self.state.logs, "INFO", format!("证书已生成并信任 ({})", domains.join(", ")));
                    self.set_notice("证书已生成并安装到系统信任库", "success");
                }
                Err(_) => {
                    self.cert_domains = domains.clone();
                    self.cert_installed = false;
                    let ca_path_str = ca_path.to_string_lossy().to_string();
                    let _ = relaunch_elevated("cert-install", &[ca_path_str], "");
                    add_log_arc(&self.state.logs, "INFO", "证书已生成，正在请求管理员安装信任");
                    self.set_notice("证书已生成，已请求管理员确认安装；确认完成后可直接启动", "success");
                }
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            self.cert_domains = domains.clone();
            self.cert_installed = true;
            add_log_arc(&self.state.logs, "INFO", format!("证书已生成 ({})", domains.join(", ")));
            self.set_notice("证书已生成", "success");
        }
    }

    fn do_delete_certs(&mut self) {
        let mut notice_message = "证书已删除".to_string();
        let mut notice_type = "success";

        #[cfg(target_os = "windows")]
        {
            match uninstall_ca_from_store() {
                Ok(()) => {
                    add_log_arc(&self.state.logs, "INFO", "已从系统信任库移除 DevProxy CA 证书");
                }
                Err(error) => {
                    if error.contains("拒绝访问") || error.contains("Access is denied") {
                        match relaunch_elevated("cert-uninstall", &[], "") {
                            Ok(()) => {
                                add_log_arc(&self.state.logs, "INFO", "已请求管理员移除系统 CA 证书");
                                notice_message = "本地证书文件已删除；系统 CA 删除已请求管理员确认".into();
                            }
                            Err(request_error) => {
                                add_log_arc(&self.state.logs, "ERROR", format!("请求管理员移除 CA 证书失败: {request_error}"));
                                notice_message = format!("本地证书文件已删除，但系统 CA 删除失败: {error}");
                                notice_type = "error";
                            }
                        }
                    } else {
                        add_log_arc(&self.state.logs, "ERROR", format!("移除系统 CA 证书失败: {error}"));
                        notice_message = format!("本地证书文件已删除，但系统 CA 删除失败: {error}");
                        notice_type = "error";
                    }
                }
            }
        }
        let dir = certs_dir();
        for name in &["ca.pem", "cert.pem", "key.pem"] {
            let _ = fs::remove_file(dir.join(name));
        }
        self.cert_domains.clear();
        self.cert_installed = check_cert_ready();
        add_log_arc(&self.state.logs, "INFO", "本地证书文件已删除");
        self.set_notice(&notice_message, notice_type);
    }

    fn do_add_hosts(&mut self) {
        let state = match self.build_managed_hosts_state() {
            Ok(state) => state,
            Err(error) => {
                self.set_notice(&error, "error");
                return;
            }
        };
        #[cfg(target_os = "windows")]
        {
            match update_hosts_native(&state.domains, &state.address, true) {
                Ok(()) => {
                    self.hosts_written = check_hosts_written(&state.domains, &state.address);
                    self.hosts_state = if self.hosts_written { Some(state.clone()) } else { None };
                    for d in &state.domains {
                        add_log_arc(&self.state.logs, "INFO", format!("写入 hosts: {} -> {}", d, state.address));
                    }
                    self.set_notice(&format!("写入 hosts 已完成 ({} 条)", state.domains.len()), "success");
                }
                Err(e) if e.contains("拒绝访问") || e.contains("Access is denied") => {
                    let _ = relaunch_elevated("add", &state.domains, &state.address);
                    self.set_notice("写入 hosts 已请求管理员确认；完成后请重新检查当前状态", "success");
                }
                Err(e) => self.set_notice(&format!("写入 hosts 失败: {e}"), "error"),
            }
        }
        #[cfg(not(target_os = "windows"))]
        self.set_notice("当前平台暂不支持 hosts 管理", "error");
    }

    fn do_remove_hosts(&mut self) {
        let state = match self.build_managed_hosts_state() {
            Ok(state) => state,
            Err(error) => {
                self.set_notice(&error, "error");
                return;
            }
        };
        #[cfg(target_os = "windows")]
        {
            match update_hosts_native(&state.domains, &state.address, false) {
                Ok(()) => {
                    self.hosts_written = check_hosts_written(&state.domains, &state.address);
                    self.hosts_state = None;
                    self.set_notice("hosts 已恢复", "success");
                }
                Err(e) if e.contains("拒绝访问") || e.contains("Access is denied") => {
                    let _ = relaunch_elevated("remove", &state.domains, &state.address);
                    self.set_notice("恢复 hosts 已请求管理员确认；完成后请重新检查当前状态", "success");
                }
                Err(e) => self.set_notice(&format!("恢复 hosts 失败: {e}"), "error"),
            }
        }
        #[cfg(not(target_os = "windows"))]
        self.set_notice("当前平台暂不支持 hosts 管理", "error");
    }

    fn do_start_proxy(&mut self) {
        if self.is_proxy_running() {
            self.set_notice("代理已在运行", "success");
            return;
        }

        let config = match self.build_validated_config() {
            Ok(config) => config,
            Err(error) => {
                self.set_notice(&error, "error");
                return;
            }
        };
        let addr_str = format!("{}:{}", config.listen.host, config.listen.port);
        let addr: std::net::SocketAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(e) => { self.set_notice(&format!("监听地址无效: {e}"), "error"); return; }
        };

        // Pre-check: try binding to catch "access denied" / "in use" before async spawn
        match std::net::TcpListener::bind(addr) {
            Ok(listener) => drop(listener), // release immediately
            Err(e) => {
                let msg = format!("无法绑定 {addr}: {e}");
                self.set_notice(&msg, "error");
                add_log_arc(&self.state.logs, "ERROR", msg);
                return;
            }
        }

        let base_dir = config_path().parent().map(Path::to_path_buf).unwrap_or_default();
        let cert_path = if Path::new(&config.tls.cert_path).is_absolute() {
            PathBuf::from(&config.tls.cert_path)
        } else {
            base_dir.join(&config.tls.cert_path)
        };
        let key_path = if Path::new(&config.tls.key_path).is_absolute() {
            PathBuf::from(&config.tls.key_path)
        } else {
            base_dir.join(&config.tls.key_path)
        };

        if !cert_path.exists() {
            self.set_notice(&format!("未找到证书文件: {}", cert_path.display()), "error");
            return;
        }
        if !key_path.exists() {
            self.set_notice(&format!("未找到私钥文件: {}", key_path.display()), "error");
            return;
        }

        let mut routes = HashMap::new();
        for r in &config.routes {
            let d = r.domain.trim().to_lowercase();
            if !d.is_empty() && !r.upstream.trim().is_empty() {
                routes.insert(d, r.upstream.trim().to_string());
            }
        }
        if routes.is_empty() {
            self.set_notice("至少需要一条有效路由", "error");
            return;
        }

        let client = match Client::builder()
            .timeout(Duration::from_millis(config.upstream.timeout_ms))
            .danger_accept_invalid_certs(!config.upstream.reject_unauthorized)
            .build()
        {
            Ok(c) => c,
            Err(e) => { self.set_notice(&format!("创建 HTTP 客户端失败: {e}"), "error"); return; }
        };

        let route_display: Vec<String> = routes.iter().map(|(d, u)| format!("{d} -> {u}")).collect();

        let server_state = ProxyServerState {
            client,
            routes,
            logs: self.state.logs.clone(),
        };

        let app_router = Router::new().fallback(any(proxy_handler)).with_state(server_state);
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        let status = self.state.proxy_status.clone();
        let logs = self.state.logs.clone();
        let proxy_handle_ref = self.state.proxy_handle.clone();

        if let Ok(mut slot) = self.state.proxy_handle.lock() {
            *slot = Some(shutdown_handle);
        }
        if let Ok(mut current) = status.lock() {
            *current = "running".into();
        }

        add_log_arc(&self.state.logs, "INFO", format!("正在启动代理 -> https://{}", addr_str));
        for line in &route_display {
            add_log_arc(&self.state.logs, "INFO", format!("路由: {line}"));
        }

        self.runtime.spawn(async move {
            let tls = match axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await {
                Ok(value) => value,
                Err(error) => {
                    add_log_arc(&logs, "ERROR", format!("加载 TLS 证书失败: {error}"));
                    if let Ok(mut current) = status.lock() { *current = "stopped".into(); }
                    if let Ok(mut slot) = proxy_handle_ref.lock() { *slot = None; }
                    return;
                }
            };
            add_log_arc(&logs, "INFO", "代理已启动");
            let result = axum_server::bind_rustls(addr, tls).handle(handle).serve(app_router.into_make_service()).await;
            if let Err(error) = result {
                add_log_arc(&logs, "ERROR", format!("代理运行异常: {error}"));
            }
            if let Ok(mut current) = status.lock() { *current = "stopped".into(); }
            if let Ok(mut slot) = proxy_handle_ref.lock() { *slot = None; }
            add_log_arc(&logs, "INFO", "代理已停止");
        });

        self.set_notice("代理启动命令已发送", "success");
    }

    fn do_stop_proxy(&mut self) {
        if !self.is_proxy_running() {
            self.set_notice("代理当前未运行", "error");
            return;
        }
        if let Ok(mut handle) = self.state.proxy_handle.lock() {
            if let Some(existing) = handle.take() {
                existing.graceful_shutdown(Some(Duration::from_secs(2)));
            }
        }
        if let Ok(mut current) = self.state.proxy_status.lock() {
            *current = "stopping".into();
        }
        add_log_arc(&self.state.logs, "INFO", "正在停止代理");
        self.set_notice("代理停止命令已发送", "success");
    }
}

impl eframe::App for DevProxyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(std::time::Duration::from_secs(1));

        if self.current_ui_snapshot() != self.saved_ui_snapshot {
            self.config_saved = false;
        }
        let current_domains = normalize_domains_from_routes(&self.routes);
        if current_domains != self.cert_domains {
            self.cert_installed = false;
        }
        self.hosts_written = self.hosts_state.as_ref().map(|state| {
            state.address.eq_ignore_ascii_case(self.listen_host.trim()) && state.domains == current_domains
        }).unwrap_or(false);

        if !self.notice.is_empty() {
            let timeout = if self.notice_type == "error" { 8 } else { 4 };
            if self.notice_time.elapsed().as_secs() > timeout {
                self.notice.clear();
            }
        }

        let running = self.is_proxy_running();

        // Color palette
        let accent      = egui::Color32::from_rgb(0, 200, 160);
        let accent_dim  = egui::Color32::from_rgb(0, 130, 105);
        let surface     = egui::Color32::from_rgb(24, 36, 50);
        let surface2    = egui::Color32::from_rgb(32, 48, 64);
        let surface3    = egui::Color32::from_rgb(42, 62, 82);
        let ink         = egui::Color32::from_rgb(215, 228, 240);
        let muted       = egui::Color32::from_rgb(115, 138, 158);
        let danger      = egui::Color32::from_rgb(220, 85, 85);
        let warn        = egui::Color32::from_rgb(230, 160, 50);
        let dimmed      = egui::Color32::from_rgb(55, 75, 95);

        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill                             = egui::Color32::from_rgb(13, 22, 32);
        visuals.window_fill                            = surface;
        visuals.widgets.noninteractive.bg_fill         = surface;
        visuals.widgets.noninteractive.fg_stroke.color = ink;
        visuals.widgets.inactive.bg_fill               = surface2;
        visuals.widgets.inactive.fg_stroke.color       = ink;
        visuals.widgets.hovered.bg_fill                = surface3;
        visuals.widgets.hovered.fg_stroke.color        = ink;
        visuals.widgets.active.bg_fill                 = accent;
        visuals.widgets.active.fg_stroke.color         = egui::Color32::from_rgb(5, 25, 20);
        visuals.override_text_color                    = Some(ink);
        visuals.selection.bg_fill                      = egui::Color32::from_rgb(0, 100, 80);
        ctx.set_visuals(visuals);

        // ── Top bar ──
        egui::TopBottomPanel::top("topbar")
            .frame(egui::Frame::none().fill(surface).inner_margin(egui::Margin::symmetric(16.0, 9.0)))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let dot_color = if running { accent } else { egui::Color32::from_rgb(75, 85, 100) };
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 5.0, dot_color);
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("DevProxy").strong().size(15.0).color(ink));
                    ui.add_space(6.0);
                    // GitHub link
                    ui.add(
                        egui::Hyperlink::from_label_and_url(
                            egui::RichText::new("GitHub").size(12.0).color(egui::Color32::from_rgb(100, 160, 220)),
                            "https://github.com/Qhaozhan/DevProxy",
                        )
                    );
                    ui.colored_label(muted, egui::RichText::new("<- star").size(11.0));
                    ui.separator();
                    let status_color = if running { accent } else { muted };
                    ui.colored_label(status_color, egui::RichText::new(self.proxy_status_text()).size(13.5));
                    ui.separator();
                    ui.colored_label(muted, egui::RichText::new(
                        format!("PID: {}", if running { std::process::id().to_string() } else { "-".into() })
                    ).monospace().size(12.0));
                });
            });

        // ── Notice bar ──
        if !self.notice.is_empty() {
            egui::TopBottomPanel::top("notice")
                .frame(egui::Frame::none().inner_margin(egui::Margin::symmetric(16.0, 0.0)))
                .show(ctx, |ui| {
                    let (bg, fg) = match self.notice_type.as_str() {
                        "success" => (egui::Color32::from_rgb(5, 52, 42), accent),
                        "error"   => (egui::Color32::from_rgb(55, 18, 18), danger),
                        _         => (egui::Color32::from_rgb(15, 38, 68), egui::Color32::from_rgb(110, 180, 255)),
                    };
                    egui::Frame::none().fill(bg).inner_margin(egui::Margin::symmetric(12.0, 7.0)).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.colored_label(fg, egui::RichText::new(&self.notice).size(13.0));
                    });
                });
        }

        // ── Left panel ──
        egui::SidePanel::left("left_panel")
            .min_width(410.0)
            .max_width(450.0)
            .frame(egui::Frame::none()
                .fill(egui::Color32::from_rgb(13, 22, 32))
                .inner_margin(egui::Margin::same(14.0)))
            .show(ctx, |ui| {
                ui.style_mut().spacing.item_spacing = egui::vec2(8.0, 8.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.set_width(ui.available_width());

                    // Section: 路由规则
                    ui.colored_label(muted, egui::RichText::new("路由规则").size(11.5).strong());
                    ui.add_space(2.0);

                    let mut remove_idx = None;
                    let routes_len = self.routes.len();
                    for (i, (domain, upstream)) in self.routes.iter_mut().enumerate() {
                        egui::Frame::none()
                            .fill(surface)
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 58, 78)))
                            .rounding(egui::Rounding::same(7.0))
                            .inner_margin(egui::Margin::same(10.0))
                            .show(ui, |ui| {
                                // Domain row: button on right, text fills rest
                                ui.horizontal(|ui| {
                                    ui.colored_label(muted, egui::RichText::new("域名").size(11.0).strong());
                                    ui.add_space(2.0);
                                    if routes_len > 1 {
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            if ui.add(
                                                egui::Button::new(
                                                    egui::RichText::new("x").color(egui::Color32::from_rgb(200, 100, 100)).size(13.0)
                                                )
                                                .fill(egui::Color32::from_rgb(48, 25, 25))
                                                .min_size(egui::vec2(26.0, 26.0)),
                                            ).clicked() {
                                                remove_idx = Some(i);
                                            }
                                            ui.add(
                                                egui::TextEdit::singleline(domain)
                                                    .hint_text("域名，如 api.example.com")
                                                    .text_color(egui::Color32::from_rgb(220, 220, 220))
                                                    .desired_width(f32::INFINITY)
                                                    .font(egui::TextStyle::Body),
                                            );
                                        });
                                    } else {
                                        ui.add(
                                            egui::TextEdit::singleline(domain)
                                                .hint_text("域名，如 api.example.com")
                                                .text_color(egui::Color32::from_rgb(220, 220, 220))
                                                .desired_width(f32::INFINITY)
                                                .font(egui::TextStyle::Body),
                                        );
                                    }
                                });
                                ui.add_space(4.0);
                                // Upstream row
                                ui.horizontal(|ui| {
                                    ui.colored_label(muted, egui::RichText::new("上游").size(11.0).strong());
                                    ui.add_space(2.0);
                                    ui.add(
                                        egui::TextEdit::singleline(upstream)
                                            .hint_text("https://proxy-ai.example.com")
                                            .desired_width(f32::INFINITY)
                                            .font(egui::TextStyle::Body),
                                    );
                                });
                            });
                        ui.add_space(2.0);
                    }
                    if let Some(idx) = remove_idx { self.routes.remove(idx); }

                    // Add route button
                    let add_w = ui.available_width();
                    if ui.add_sized(
                        [add_w, 30.0],
                        egui::Button::new(egui::RichText::new("+ 添加路由").color(accent).size(13.0))
                            .fill(egui::Color32::from_rgb(0, 45, 36))
                            .stroke(egui::Stroke::new(1.0, accent_dim)),
                    ).clicked() {
                        self.routes.push((String::new(), String::new()));
                    }

                    ui.add_space(6.0);

                    // Section: 高级设置
                    ui.checkbox(&mut self.show_advanced,
                        egui::RichText::new("高级设置").size(13.0).color(muted));

                    if self.show_advanced {
                        egui::Frame::none()
                            .fill(surface)
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(38, 58, 78)))
                            .rounding(egui::Rounding::same(7.0))
                            .inner_margin(egui::Margin::same(10.0))
                            .show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.checkbox(&mut self.reject_unauthorized,
                                    egui::RichText::new("校验上游 HTTPS 证书").size(13.0));
                                ui.add_space(6.0);
                                ui.horizontal(|ui| {
                                    ui.colored_label(muted, egui::RichText::new("监听地址").size(12.0));
                                    ui.add(egui::TextEdit::singleline(&mut self.listen_host)
                                        .hint_text("127.0.0.1").desired_width(115.0).font(egui::TextStyle::Body));
                                    ui.colored_label(muted, egui::RichText::new("端口").size(12.0));
                                    ui.add(egui::TextEdit::singleline(&mut self.listen_port)
                                        .hint_text("443").desired_width(60.0).font(egui::TextStyle::Body));
                                });
                                ui.add_space(4.0);
                                ui.horizontal(|ui| {
                                    ui.colored_label(muted, egui::RichText::new("上游超时(ms)").size(12.0));
                                    ui.add(egui::TextEdit::singleline(&mut self.timeout_ms)
                                        .hint_text("600000").desired_width(110.0).font(egui::TextStyle::Body));
                                });
                            });
                    }

                    ui.add_space(8.0);

                    // ── Buttons ──
                    let bw = ui.available_width();
                    let half = (bw - 8.0) / 2.0;
                    let bh = 34.0;
                    let can_write_hosts = self.config_saved;
                    let can_stop_proxy = running;
                    let can_remove_hosts = self.hosts_written;

                    // Row 1: 保存配置 | 生成证书
                    // Logic: NOT done = bright (call-to-action), DONE = dimmed grey
                    ui.horizontal(|ui| {
                        let (save_label, save_fill, save_color) = if self.config_saved {
                            ("已保存配置", egui::Color32::from_rgb(28, 40, 52), dimmed)
                        } else {
                            ("保存配置", egui::Color32::from_rgb(0, 145, 115), egui::Color32::WHITE)
                        };
                        if ui.add_sized(
                            [half, bh],
                            egui::Button::new(egui::RichText::new(save_label).color(save_color).size(13.5))
                                .fill(save_fill),
                        ).clicked() { self.do_save_config(); }

                        let (cert_label, cert_fill, cert_color) = if self.cert_installed {
                            ("已生成证书", egui::Color32::from_rgb(28, 40, 52), dimmed)
                        } else {
                            ("生成证书", egui::Color32::from_rgb(0, 125, 98), egui::Color32::WHITE)
                        };
                        if ui.add_sized(
                            [half, bh],
                            egui::Button::new(egui::RichText::new(cert_label).color(cert_color).size(13.5))
                                .fill(cert_fill),
                        ).clicked() { self.do_generate_certs(); }
                    });
                    ui.add_space(5.0);

                    // Row 2: 写入 hosts | 启动代理
                    ui.horizontal(|ui| {
                        let (hosts_label, hosts_fill, hosts_color) = if self.hosts_written {
                            ("已写入 hosts", egui::Color32::from_rgb(28, 40, 52), dimmed)
                        } else if self.config_saved {
                            // Config saved → next step is writing hosts
                            ("写入 hosts", egui::Color32::from_rgb(0, 125, 98), egui::Color32::WHITE)
                        } else {
                            // Config not saved yet → writing hosts makes no sense yet
                            ("写入 hosts", egui::Color32::from_rgb(28, 40, 52), dimmed)
                        };
                        if ui.add_enabled(
                            can_write_hosts,
                            egui::Button::new(egui::RichText::new(hosts_label).color(hosts_color).size(13.5))
                                .fill(hosts_fill)
                                .min_size(egui::vec2(half, bh)),
                        ).clicked() { self.do_add_hosts(); }

                        let (start_label, start_fill, start_color) = if running {
                            ("代理运行中", egui::Color32::from_rgb(28, 40, 52), dimmed)
                        } else {
                            ("启动代理", egui::Color32::from_rgb(0, 145, 115), egui::Color32::WHITE)
                        };
                        if ui.add_sized(
                            [half, bh],
                            egui::Button::new(egui::RichText::new(start_label).color(start_color).size(13.5))
                                .fill(start_fill),
                        ).clicked() { self.do_start_proxy(); }
                    });
                    ui.add_space(5.0);

                    // Row 3: 停止代理 | 去除 hosts
                    // Bright when there's something to undo (running / hosts written)
                    ui.horizontal(|ui| {
                        let (stop_label, stop_fill, stop_color) = if running {
                            ("停止代理", egui::Color32::from_rgb(140, 95, 20), egui::Color32::WHITE)
                        } else {
                            ("停止代理", egui::Color32::from_rgb(28, 40, 52), dimmed)
                        };
                        if ui.add_enabled(
                            can_stop_proxy,
                            egui::Button::new(egui::RichText::new(stop_label).color(stop_color).size(13.5))
                                .fill(stop_fill)
                                .min_size(egui::vec2(half, bh)),
                        ).clicked() { self.do_stop_proxy(); }

                        let (rh_label, rh_fill, rh_color) = if self.hosts_written {
                            ("去除 hosts", egui::Color32::from_rgb(140, 95, 20), egui::Color32::WHITE)
                        } else {
                            ("去除 hosts", egui::Color32::from_rgb(28, 40, 52), dimmed)
                        };
                        if ui.add_enabled(
                            can_remove_hosts,
                            egui::Button::new(egui::RichText::new(rh_label).color(rh_color).size(13.5))
                                .fill(rh_fill)
                                .min_size(egui::vec2(half, bh)),
                        ).clicked() { self.do_remove_hosts(); }
                    });
                    ui.add_space(5.0);

                    // Row 4: 删除证书 (full width, danger)
                    if ui.add_sized(
                        [bw, bh],
                        egui::Button::new(egui::RichText::new("删除证书").color(danger).size(13.5))
                            .fill(egui::Color32::from_rgb(42, 18, 18))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(95, 38, 38))),
                    ).clicked() { self.do_delete_certs(); }

                    ui.add_space(14.0);

                    // Section: 使用流程
                    ui.colored_label(muted, egui::RichText::new("使用流程").size(11.5).strong());
                    ui.add_space(4.0);
                    for step in &[
                        "1. 添加路由 — 填写域名和上游地址",
                        "2. 保存配置 — 将路由规则写入磁盘",
                        "3. 生成证书 — 生成 TLS 证书并安装信任",
                        "4. 写入 hosts — 域名指向本地(需管理员)",
                        "5. 启动代理 — 开始监听转发 HTTPS 请求",
                        "6. 正常使用 — 请求经本地代理转发至上游",
                        "7. 停止时 — 停止代理 → 恢复 hosts",
                    ] {
                        ui.colored_label(muted, egui::RichText::new(*step).size(12.5));
                    }
                });
            });

        // ── Right panel: Logs ──
        egui::CentralPanel::default()
            .frame(egui::Frame::none()
                .fill(egui::Color32::from_rgb(10, 18, 28))
                .inner_margin(egui::Margin::same(14.0)))
            .show(ctx, |ui| {
                ui.style_mut().spacing.item_spacing = egui::vec2(6.0, 4.0);
                ui.horizontal(|ui| {
                    ui.colored_label(muted, egui::RichText::new("运行日志").size(11.5).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(
                            egui::Button::new(egui::RichText::new("清空").size(12.0).color(muted))
                                .fill(egui::Color32::TRANSPARENT)
                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(48, 68, 88))),
                        ).clicked() {
                            if let Ok(mut logs) = self.state.logs.lock() { logs.clear(); }
                        }
                    });
                });
                ui.separator();

                let logs = self.state.logs.lock().ok().map(|l| l.clone()).unwrap_or_default();
                egui::ScrollArea::vertical().auto_shrink([false; 2]).stick_to_bottom(true).show(ui, |ui| {
                    if logs.is_empty() {
                        ui.colored_label(egui::Color32::from_rgb(55, 78, 100), "暂无日志");
                    } else {
                        for entry in &logs {
                            let level_color = match entry.level.as_str() {
                                "ERROR" => danger,
                                "WARN"  => warn,
                                "INFO"  => accent,
                                "PROXY" => egui::Color32::from_rgb(185, 145, 255),
                                _       => muted,
                            };
                            ui.horizontal_wrapped(|ui| {
                                ui.colored_label(
                                    egui::Color32::from_rgb(88, 155, 215),
                                    egui::RichText::new(format!("[{}]", entry.time)).monospace().size(12.0),
                                );
                                ui.colored_label(level_color,
                                    egui::RichText::new(format!("[{}]", entry.level)).size(12.0));
                                ui.colored_label(egui::Color32::from_rgb(205, 218, 230),
                                    egui::RichText::new(&entry.message).size(12.5));
                            });
                        }
                    }
                });
            });
    }
}

// ── Entry point ───────────────────────────────────

fn main() {
    install_crypto_provider();

    // Panic hook to show errors (windows_subsystem="windows" hides console)
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("DevProxy crashed:\n{info}");
        let log_path = data_dir().join("crash.log");
        let _ = fs::write(&log_path, &msg);
        #[cfg(target_os = "windows")]
        {
            let wide_msg: Vec<u16> = OsStr::new(&msg).encode_wide().chain(Some(0)).collect();
            let wide_title: Vec<u16> = OsStr::new("DevProxy Error").encode_wide().chain(Some(0)).collect();
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
                    std::ptr::null_mut(), wide_msg.as_ptr(), wide_title.as_ptr(), 0x10,
                );
            }
        }
    }));

    #[cfg(target_os = "windows")]
    if let Some(code) = maybe_handle_cli_actions() {
        std::process::exit(code);
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([820.0, 720.0])
            .with_min_inner_size([640.0, 480.0])
            .with_icon(std::sync::Arc::new(create_window_icon()))
            .with_title("DevProxy"),
        ..Default::default()
    };

    let _ = eframe::run_native(
        "DevProxy",
        options,
        Box::new(|cc| -> Result<Box<dyn eframe::App>, Box<dyn std::error::Error + Send + Sync>> {
            Ok(Box::new(DevProxyApp::new(cc)))
        }),
    );
}

fn create_window_icon() -> egui::IconData {
    // 64x64: dark navy background + teal circle, matching the ICO
    let size: u32 = 64;
    let cf = size as f32 / 2.0;
    let r = cf - 2.0;
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 + 0.5 - cf;
            let dy = y as f32 + 0.5 - cf;
            let dist = (dx * dx + dy * dy).sqrt();
            let idx = ((y * size + x) * 4) as usize;
            if dist < r {
                // Teal fill
                rgba[idx]   = 0;
                rgba[idx+1] = 180;
                rgba[idx+2] = 145;
                rgba[idx+3] = 255;
            } else {
                // Dark navy background (matches ICO)
                rgba[idx]   = 12;
                rgba[idx+1] = 22;
                rgba[idx+2] = 35;
                rgba[idx+3] = 255;
            }
        }
    }
    egui::IconData { rgba, width: size, height: size }
}

fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    let candidates = [
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\simhei.ttf",
        "C:\\Windows\\Fonts\\simsun.ttc",
        "C:\\Windows\\Fonts\\simkai.ttf",
    ];

    for path in &candidates {
        if let Ok(data) = std::fs::read(path) {
            fonts.font_data.insert("cjk".to_owned(), egui::FontData::from_owned(data));
            fonts.families.entry(egui::FontFamily::Proportional).or_default().push("cjk".to_owned());
            fonts.families.entry(egui::FontFamily::Monospace).or_default().push("cjk".to_owned());
            break;
        }
    }

    ctx.set_fonts(fonts);

    ctx.style_mut(|style| {
        use egui::{FontFamily, FontId, TextStyle};
        style.text_styles = [
            (TextStyle::Heading,   FontId::new(16.0, FontFamily::Proportional)),
            (TextStyle::Body,      FontId::new(14.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
            (TextStyle::Button,    FontId::new(13.5, FontFamily::Proportional)),
            (TextStyle::Small,     FontId::new(11.5, FontFamily::Proportional)),
        ].into();
        style.spacing.item_spacing    = egui::vec2(8.0, 6.0);
        style.spacing.button_padding  = egui::vec2(10.0, 5.0);
        style.spacing.interact_size.y = 30.0;
    });
}
