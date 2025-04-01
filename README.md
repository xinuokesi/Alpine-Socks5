# Alpine Socks5代理一键安装脚本

这是一个用于在Alpine Linux上快速部署Socks5代理的脚本，支持随机/自定义端口和用户名密码，并内置保活和开机自启功能。

## 一键安装

### 交互式安装

```bash
wget -O - https://raw.githubusercontent.com/xinuokesi/Alpine-Socks5/main/setup_socks5.sh | sh
```

### 或者使用curl:

```bash
curl -fsSL https://raw.githubusercontent.com/xinuokesi/Alpine-Socks5/main/setup_socks5.sh | sh
```

### 自动安装（使用随机配置）

```bash
wget -O - https://raw.githubusercontent.com/xinuokesi/Alpine-Socks5/main/setup_socks5.sh | sh -s -- --auto
```
