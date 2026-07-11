#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR=/opt/oci-ipv6-proxy-panel
if [ "$(id -u)" -ne 0 ]; then echo "请用 root 运行：sudo bash install.sh"; exit 1; fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y python3-venv python3-pip curl iproute2
mkdir -p "$INSTALL_DIR"/{secure,data,templates}
chmod 700 "$INSTALL_DIR/secure"
cp -r app/app.py app/socks_server.py app/ss_config.py "$INSTALL_DIR/"
cp app/templates/index.html "$INSTALL_DIR/templates/index.html"
chmod +x "$INSTALL_DIR/app.py" "$INSTALL_DIR/socks_server.py" "$INSTALL_DIR/ss_config.py"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install -q --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install -q flask oci gunicorn
PUBLIC_HOST=$(curl -4 -fsS --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')
read -rp "面板端口 [18080]: " PANEL_PORT; PANEL_PORT=${PANEL_PORT:-18080}
read -rp "面板用户名 [admin]: " PANEL_USER; PANEL_USER=${PANEL_USER:-admin}
read -rsp "面板密码 [随机生成]: " PANEL_PASS; echo; PANEL_PASS=${PANEL_PASS:-$(openssl rand -hex 8 2>/dev/null || date +%s)}
RAND_USER="u_$(openssl rand -hex 5 2>/dev/null || date +%s)"
RAND_PASS="p_$(openssl rand -hex 9 2>/dev/null || date +%s)"
read -rp "代理用户名 [随机生成]: " PROXY_USER; PROXY_USER=${PROXY_USER:-$RAND_USER}
read -rsp "代理密码 [随机生成]: " PROXY_PASS; echo; PROXY_PASS=${PROXY_PASS:-$RAND_PASS}
read -rp "代理端口起始 [30000]: " PORT_START; PORT_START=${PORT_START:-30000}
read -rp "最大代理数量 [32]: " MAX_PROXIES; MAX_PROXIES=${MAX_PROXIES:-32}
PORT_END=$((PORT_START + MAX_PROXIES - 1))
IFACE=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1); IFACE=${IFACE:-enp0s6}
cat > "$INSTALL_DIR/config.json" <<JSON
{
  "public_host": "$PUBLIC_HOST",
  "panel_port": $PANEL_PORT,
  "panel_user": "$PANEL_USER",
  "panel_pass": "$PANEL_PASS",
  "proxy_user": "$PROXY_USER",
  "proxy_pass": "$PROXY_PASS",
  "port_start": $PORT_START,
  "port_end": $PORT_END,
  "max_proxies": $MAX_PROXIES,
  "iface": "$IFACE",
  "vnic_id": "",
  "subnet_id": "",
  "instance_id": "",
  "compartment_id": "",
  "max_vnics": 4,
  "force_ipv6": true,
  "ss_port_start": 31000,
  "ss_method": "aes-256-gcm",
  "ss_password": "$(openssl rand -base64 24 2>/dev/null | tr -d '\n' || date +%s)"
}
JSON
[ -f "$INSTALL_DIR/data/proxies.json" ] || echo '[]' > "$INSTALL_DIR/data/proxies.json"
cat > /etc/systemd/system/oci-ipv6-proxy-panel.service <<EOF
[Unit]
Description=OCI IPv6 Proxy Pool Web Panel
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/gunicorn -w 2 -b 0.0.0.0:$PANEL_PORT app:app
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/oci-ipv6-socks.service <<EOF
[Unit]
Description=OCI IPv6 SOCKS5 Proxy Service
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/socks_server.py
Restart=always
RestartSec=3
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now oci-ipv6-socks.service oci-ipv6-proxy-panel.service
cat <<MSG
安装完成：
面板：http://$PUBLIC_HOST:$PANEL_PORT
用户名：$PANEL_USER
密码：$PANEL_PASS
代理账号：$PROXY_USER
代理密码：$PROXY_PASS
下一步：登录面板 -> Oracle API -> 填写 OCI API 与 VNIC/Subnet -> 添加代理。
MSG
