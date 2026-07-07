# OCI IPv6 SOCKS5 Proxy Panel

一键部署 OCI IPv6 SOCKS5 代理池面板。支持：网页添加/删除代理、切换单个端口的 IPv6、强制 IPv6、网页配置 Oracle API、修改面板和代理账号密码、导出 `socks5://user:pass@host:port`。

## 安装

```bash
git clone <your-repo-url> oci-ipv6-proxy-panel
cd oci-ipv6-proxy-panel
sudo bash install.sh
```

安装后登录面板，在“Oracle API”页填写 OCI API config/private key、VNIC ID、Subnet ID，然后添加代理。

## 注意

- OCI API 只负责申请/释放 IPv6；本机服务负责 SOCKS5 代理。
- OCI 单 VNIC 普通 IPv6 通常最多 32 个对象；CIDR 需要账号限额支持。
- 强制 IPv6 开启时，IPv4-only 目标会失败，不会回退到服务器 IPv4。
