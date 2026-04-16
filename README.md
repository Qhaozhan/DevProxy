# DevProxy

<p align="center">
  <a href="https://github.com/Qhaozhan/DevProxy/releases"><img src="https://img.shields.io/github/v/release/Qhaozhan/DevProxy?style=flat-square&label=Release" alt="Release"/></a>
  <img src="https://img.shields.io/badge/Platform-Windows-blue?style=flat-square&logo=windows" alt="Windows"/>
  <img src="https://img.shields.io/badge/GUI-eframe%20%2B%20egui-4C8EDA?style=flat-square" alt="eframe + egui"/>
  <img src="https://img.shields.io/badge/Backend-Rust-orange?style=flat-square&logo=rust" alt="Rust"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="MIT"/>
</p>

本项目是一个面向 Windows 的本地 HTTPS 入口代理工具。

它做的事很直接：

- 接住被 `hosts` 指向本机的目标域名流量
- 把请求透明转发到你指定的上游
- 用桌面界面完成配置、证书、`hosts`、启动和日志查看

典型场景：

- Trae 这类固定访问 `api.openai.com` 的客户端
- 不方便单独配置 `base_url` 的 IDE / 插件
- 希望在本机入口层统一接管，而不是每个客户端都改一遍

---

## 截图

![桌面版主界面](./images/devproxy-main.png)

---

## 下载与运行

当前项目以 **单文件 `DevProxy.exe`** 为主。

仓库内已经整理好的纯净发布目录：

- `release/DevProxy.exe`

双击运行后，按界面流程完成：

```text
保存配置 → 生成证书 → 写入 hosts → 启动代理
```

随后正常使用 `api.openai.com`，流量会自动进入本地代理并转发到你的上游。

---

## 工作原理

```text
客户端 -> 目标域名（hosts 指向本机）-> DevProxy 本地 HTTPS -> 你的上游
```

示例：

```text
Trae -> api.openai.com -> 127.0.0.1:443 -> DevProxy -> https://你的上游/v1
```

监听的 `443` 是本机代理端口，不是 OpenAI 服务器端口。

---

## 主要功能

- 本地 HTTPS 透明入口代理
- 原生桌面 GUI，基于 `eframe + egui`
- Axum + Rustls 代理内核
- 自签证书生成与安装
- `hosts` 写入与恢复
- 上游地址、域名规则、超时等配置持久化
- 实时运行日志
- 单文件 `exe` 分发

---

## 运行期数据

程序运行后会在以下目录生成配置和证书：

```text
%APPDATA%\devproxy\runtime\proxy-core\
```

CA 证书路径：

```text
%APPDATA%\devproxy\runtime\proxy-core\certs\ca.pem
```

如果 UAC 被拒绝，或需要重新信任，可将 `ca.pem` 改名为 `.crt` 后双击安装到“受信任的根证书颁发机构”。

---

## 使用说明

### 关于证书

- “生成证书”会生成本地 CA 和服务端证书
- Windows 下程序会尝试自动安装 CA 到系统信任库
- 如果路由域名发生变化，需要重新生成证书
- “删除证书”只会删除证书，不会改动 `hosts`

### 关于 hosts

- “写入 hosts” 会把目标域名指向本机监听地址
- “去除 hosts” 用于手动恢复系统环境
- 关闭窗口后不会自动恢复 `hosts`

### 关于退出行为

- 关闭窗口后，代理进程会停止，监听端口会释放
- 已写入的 `hosts` 和已生成的证书会保留
- 这样下次打开程序后可以直接继续使用

---

## 常见问题

**Q: 这是单文件版 exe 吗？运行时需要 `deps`、`build` 这些目录吗？**  
A: 是。真正运行只需要 `DevProxy.exe`。`target_local/release` 下的其他目录主要是编译缓存和中间产物，不是运行依赖。

**Q: 需要安装 WebView2 Runtime 吗？**  
A: 不需要。当前版本基于 `eframe + egui`，不依赖 Tauri / WebView2。

**Q: 端口 443 被占用怎么办？**  
A: 关闭占用 443 的程序，或在高级配置里改用其他端口。

**Q: 客户端报 SSL 证书错误怎么办？**  
A: 先重新执行“生成证书”。如果 UAC 被拒绝，请手动安装：

```text
%APPDATA%\devproxy\runtime\proxy-core\certs\ca.pem
```

**Q: 关闭窗口后为什么客户端还是连不上？**  
A: 因为 `hosts` 仍然保留，目标域名依旧指向本机，但代理已经停止。此时重新启动 DevProxy，或手动点击“去除 hosts”恢复环境。

---

## 从源码构建

```powershell
cargo build --release --manifest-path desktop-native/Cargo.toml --target-dir desktop-native/target_local
```

构建后主程序位于：

- `desktop-native/target_local/release/DevProxy.exe`

说明：

- `desktop-native/target_local/release/DevProxy.exe` 是 Cargo 输出的主程序
- `release/DevProxy.exe` 是整理后的纯净发布副本
- `desktop-native/target_local/release` 下的 `deps`、`build`、`.fingerprint`、`incremental` 都不是运行必需品

---

## 目录结构

```text
DevProxy/
├── desktop-native/
│   ├── Cargo.toml
│   ├── build.rs
│   ├── src/
│   │   └── main.rs
│   └── target_local/
├── images/
├── release/
│   └── DevProxy.exe
└── README.md
```

---

## English

DevProxy is a local HTTPS entry proxy for Windows.

It intercepts traffic for domains redirected to localhost via `hosts`, then forwards it to your upstream through a native Rust desktop app.

Main points:

- Single-file `DevProxy.exe`
- Native GUI built with `eframe + egui`
- Axum + Rustls proxy engine
- Local certificate generation and trust install
- `hosts` write / remove support

Build command:

```powershell
cargo build --release --manifest-path desktop-native/Cargo.toml --target-dir desktop-native/target_local
```

Built executable:

- `desktop-native/target_local/release/DevProxy.exe`

Clean release copy:

- `release/DevProxy.exe`

---

## License

MIT
