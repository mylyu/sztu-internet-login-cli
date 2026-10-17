# SZTU Internet Login CLI

**English** | [简体中文](#sztu-校园网登录命令行工具)

A small, portable command-line client for the Srun campus network portal. It
is a single statically linked Linux x86_64 executable and needs no runtime
installation or configuration file on the target server.

## Features

- `login`, `status`, and manual `logout` commands.
- Prompts for the password without putting it in shell history, process
  arguments, or a file. The terminal displays one `*` per typed character.
- Logout uses the portal's signed device-management endpoint and verifies
  that the session has gone offline.
- Refuses to replace a different account that is already online.
- Built with Go's standard library only. Prebuilt binaries are published as
  assets on the [GitHub Releases](https://github.com/mylyu/sztu-internet-login-cli/releases) page,
  not stored in the source repository.

## Quick start

Download `campus-srun-linux-amd64.tar.gz` from the
[latest GitHub Release](https://github.com/mylyu/sztu-internet-login-cli/releases/latest)
and extract it on a Linux x86_64 server:

```sh
tar -xzf campus-srun-linux-amd64.tar.gz
chmod 755 campus-srun
./campus-srun status
./campus-srun login -username YOUR_USERNAME
./campus-srun logout
```

The release also includes a `.sha256` checksum file. Verify the downloaded
archive with:

```sh
sha256sum -c campus-srun-linux-amd64.tar.gz.sha256
```

Login prompts for the password interactively; type it and press Enter. The
password is not a command-line option. For a remote SSH session, allocate a
TTY so the prompt can read securely:

```sh
ssh -t root@server '/path/to/campus-srun login -username YOUR_USERNAME'
```

The default gateway is `http://172.19.0.5`, access point ID is `1`, and a
username without a domain gets the site's `@xyw` suffix. These defaults are
specific to the intended SZTU network environment. Other Srun deployments can
override the gateway and access point:

```sh
./campus-srun status -gateway http://gateway.example -ac-id 1
./campus-srun login -username USER -gateway http://gateway.example -ac-id 1
./campus-srun logout -gateway http://gateway.example -ac-id 1
```

`logout -username USER` is also supported as a safety check; if supplied, it
must match the currently online account. Logout does not require a password.

## Build and test

Requires Go on the build machine; target servers do not need Go.

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath -ldflags='-s -w' -o campus-srun main.go
GO111MODULE=off go test -race main.go main_test.go
GO111MODULE=off go vet main.go main_test.go
```

The binary uses only Go's standard library. Password handling is in memory;
as with other Go programs, clearing a byte buffer cannot guarantee forensic
erasure of all copies from process memory.

## Checksums

Verify repository files from the repository root with:

```sh
sha256sum -c SHA256SUMS
```

---

# SZTU 校园网登录命令行工具

[English](#sztu-internet-login-cli) | **简体中文**

一个用于深澜（Srun）校园网认证门户的轻量级命令行工具。它提供单个
静态链接的 Linux x86_64 可执行文件，目标服务器无需安装运行环境，也无需
密码配置文件。

## 功能

- 提供 `login`、`status` 和手动 `logout` 命令。
- 交互式输入密码，不会把密码放入命令行参数、Shell 历史或文件；输入时
  每个字符显示一个 `*`。
- 注销使用门户的签名设备管理接口，并检查会话是否已离线。
- 如果当前已有其他账号在线，不会直接替换该账号。
- 仅使用 Go 标准库构建。预编译二进制作为资产发布在
  [GitHub Releases 页面](https://github.com/mylyu/sztu-internet-login-cli/releases)，
  不存放在源码仓库中。

## 快速开始

从[最新 GitHub Release](https://github.com/mylyu/sztu-internet-login-cli/releases/latest)
下载 `campus-srun-linux-amd64.tar.gz`，在 Linux x86_64 服务器上解压并运行：

```sh
tar -xzf campus-srun-linux-amd64.tar.gz
chmod 755 campus-srun
./campus-srun status
./campus-srun login -username YOUR_USERNAME
./campus-srun logout
```

Release 还提供 `.sha256` 校验文件，可用以下命令验证下载的压缩包：

```sh
sha256sum -c campus-srun-linux-amd64.tar.gz.sha256
```

运行登录命令后，按提示输入密码并按回车。密码不是命令行选项。通过 SSH
远程登录时，请分配伪终端（TTY），以便安全读取密码：

```sh
ssh -t root@server '/path/to/campus-srun login -username YOUR_USERNAME'
```

默认网关为 `http://172.19.0.5`，接入点 ID 为 `1`；未带域名的用户名会自动
附加本站使用的 `@xyw` 后缀。这些默认值针对预期的 SZTU 网络环境。其他
Srun 部署可覆盖网关和接入点：

```sh
./campus-srun status -gateway http://gateway.example -ac-id 1
./campus-srun login -username USER -gateway http://gateway.example -ac-id 1
./campus-srun logout -gateway http://gateway.example -ac-id 1
```

也可以给 `logout` 指定 `-username USER` 作为安全检查；若指定，必须与当前
在线账号一致。注销无需密码。

## 构建与测试

构建机器需要安装 Go；目标服务器不需要 Go。

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath -ldflags='-s -w' -o campus-srun main.go
GO111MODULE=off go test -race main.go main_test.go
GO111MODULE=off go vet main.go main_test.go
```

程序只依赖 Go 标准库。密码仅在进程内存中处理；与其他 Go 程序一样，清零
字节缓冲区不能保证从进程内存中的所有副本进行取证级擦除。

## 校验和

在仓库根目录运行以下命令，校验仓库文件：

```sh
sha256sum -c SHA256SUMS
```
