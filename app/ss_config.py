#!/usr/bin/env python3
"""Generate shadowsocks-rust multi-server config from proxy-pool state."""
import json
import os

BASE=os.environ.get('OCI_PROXY_BASE','/opt/oci-ipv6-proxy-panel')
CONFIG=f'{BASE}/config.json'
STATE=f'{BASE}/data/proxies.json'
OUTPUT=f'{BASE}/data/shadowsocks.json'

def load(path, default):
    try:
        with open(path) as f: return json.load(f)
    except Exception:
        return default

def main():
    cfg=load(CONFIG,{})
    method=cfg.get('ss_method','aes-256-gcm')
    password=cfg.get('ss_password','')
    start=int(cfg.get('ss_port_start',31000))
    servers=[]
    for item in load(STATE,[]):
        if not item.get('ip') or not item.get('port'): continue
        ss_port=int(item.get('ss_port') or start + (int(item['port'])-int(cfg.get('port_start',30000))))
        servers.append({
            'server':'0.0.0.0', 'server_port':ss_port,
            'password':password, 'method':method,
            'mode':'tcp_and_udp', 'outbound_bind_addr':item['ip'],
        })
    data={'servers':servers, 'timeout':300, 'mode':'tcp_and_udp'}
    os.makedirs(os.path.dirname(OUTPUT),exist_ok=True)
    tmp=OUTPUT+'.tmp'
    with open(tmp,'w') as f: json.dump(data,f,indent=2)
    os.replace(tmp,OUTPUT)
    print(f'generated {len(servers)} Shadowsocks servers')

if __name__=='__main__': main()
