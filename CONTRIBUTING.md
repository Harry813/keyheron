# KeyHeron（青鹭）贡献指南

这是一个开发者预览项目。PR 可以从一个小改动开始，例如添加一个可运行的 API 示例、改进一种审批交互、或修正一项授权回归。先说明使用场景、受影响的运行路径和可重复的验证步骤。涉及访问控制的问题请先阅读 [安全披露说明](SECURITY.md)。

## 从干净的检出目录运行

使用 Python 3.12、Rust 1.99.1、C 编译器和 OpenSSL，浏览器可使用本机现代 Chrome。Rust 依赖包括本地编译的 SQLite。CI 在 Ubuntu 24.04 x86_64 和 macOS 15 arm64 上使用同一 Rust 工具链。首次构建和安装需要联网。

```sh
rustup toolchain install 1.99.1 --profile minimal
cargo +1.99.1 build --release --locked --manifest-path rust-core/Cargo.toml
python3 tools.py --install
python3 verify_web.py
python3 verify_external.py
python3 scripts/test_release.py
```

从本地源码重新构建后，可用 `python3 web_demo.py --open --core rust-core/target/release/agent-access-core` 明确指定该构件。源码包中的 `bin/` 初始为空。KeyFence 由安装器从上游 v0.4.0 下载并检查对应平台的 SHA-256。基准或演示只需要合成凭据。自有私有服务验收所需凭据由操作者在本机提供。

## 修改和验证

- 授权、会话和控制 API 位于 `rust-core/src/`。修改时覆盖一次允许和一次拒绝，说明环境、操作和授权期限。对回执、撤销或重试的改动，检查上游实际收到的请求和审计结果。
- 前端位于 `web/`。使用启动器打开申请人和审批人页面，检查普通键盘操作、窄屏布局、状态变化和历史回读。前端和终端应通过相同的 Rust API 修改状态。
- 性能改动可运行 `python3 bench.py --samples 1200 --concurrency 1 8 --json`。记录构建摘要、硬件、样本量、错误、审计行数以及各链路的 p50/p95/p99。CI 用小样本确认三条链路可用；它无法替代稳定硬件上的性能对照。
- 示例配置只保存凭据引用。测试生成的数据库、角色链接、CA 私钥、第三方业务凭据和本机构建目录留在本机。对拒绝行为的报告可以使用固定的模拟账户与公开路径。
- 更新 Cargo 依赖后，在同一提交中运行 `python3 scripts/rust_notices.py` 并审核 `third_party/RUST-NOTICES.txt` 的差异。Linux CI 使用完整锁定依赖图检查声明，已执行 `cargo fetch --locked` 的离线机器可以增加 `--offline`。
- 在本项目的 `main` 分支或发布标签上，Linux CI 另用该作业的只读 GitHub 安装令牌，通过代理读取当前安装可见的仓库。令牌仅传给这一个受信步骤。PR、fork 和其他分支运行离线 HTTPS 夹具验收。

## 制作发布候选

维护者选择与 Cargo 版本对应的 Git 标签。公开发行物包括源码 ZIP、能单独检出的 Web ZIP、两个通过矩阵验收的 Rust 可执行程序、`RELEASE-METADATA.json` 和 `SHA256SUMS`。源包和 Web 包各自带有原创代码的许可与归属声明；第三方项目的条款另行保留。下载的 `keyheron-core-平台` 对应本地 `bin/agent-access-core-平台`（保留现有可执行程序名称）。重命名后运行 `chmod +x` 赋予执行权限。单独分发原生构件时，请一并保留发布附件中的 LICENSE、NOTICE 和 RUST-NOTICES.txt。KeyFence 继续由各系统按上游摘要获取。

本地查看当前工作树的候选包（选择新的或空的输出目录）：

```sh
python3 scripts/package_release.py --preview --out dist/local-preview
```

复验**已存在并已检出**的标签时，使用 `python3 scripts/package_release.py --tag "$TAG" --out dist/tag-check`。打包器直接读取该标签的 Git blob，并固定 ZIP 条目顺序、权限与时间。源码和 Web 包应能从同一标签重复生成同样的字节。各平台原生二进制的摘要以通过 CI 的实际构件为准。

向配置了 GitHub Actions 的正式仓库推送 `v*` 标签时，release 工作流会先验收两个平台，再创建草稿 Release；PR 与普通分支只运行检查。首次使用时确认仓库已允许 Actions 创建构建证明，已启用私下安全报告，并对主分支和发布标签设置相应的维护者权限。发布前由维护者核对变更记录、目标提交、原生平台、构件清单、SHA 和证明，再在 GitHub 中发布草稿。已公开的标签和附件应保持不可变；修复采用新版本。

下载发布附件后，在同一目录核验完整性：

```sh
shasum -a 256 -c SHA256SUMS
gh attestation verify SHA256SUMS --repo Harry813/keyheron
```

SHA 校验绑定具体文件，GitHub 构建证明用于核对来源工作流、仓库和输出摘要。也可对单个发行物运行同一条 `gh attestation verify`。维护者应核对证明来自预期的标签和工作流。[GitHub 构建证明](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
