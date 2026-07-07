#!/usr/bin/env python3
import os, json, time, subprocess
from functools import wraps
from flask import Flask, request, jsonify, Response, render_template_string
import oci
from oci.core.models import CreateIpv6Details
from oci.exceptions import ServiceError

BASE=os.environ.get('OCI_PROXY_BASE','/opt/oci-ipv6-proxy-panel')
CONFIG=f'{BASE}/config.json'
STATE=f'{BASE}/data/proxies.json'
OCI_CONFIG=f'{BASE}/secure/oci_config'
OCI_KEY=f'{BASE}/secure/oci_api_key.pem'
app=Flask(__name__)

def load_json(path, default):
    try:
        with open(path) as f: return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp=path+'.tmp'
    with open(tmp,'w') as f: json.dump(data,f,indent=2,ensure_ascii=False)
    os.replace(tmp,path)

def cfg(): return load_json(CONFIG,{})
def save_cfg(c): save_json(CONFIG,c)
def state(): return load_json(STATE,[])
def save_state(s): save_json(STATE,s)

def run(cmd, timeout=30):
    return subprocess.run(cmd, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout).stdout.strip()

def require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        c=cfg(); auth=request.authorization
        if not auth or auth.username!=c.get('panel_user') or auth.password!=c.get('panel_pass'):
            return Response('Auth required',401,{'WWW-Authenticate':'Basic realm="OCI IPv6 Proxy Panel"'})
        return fn(*a, **kw)
    return wrapper

def public_config(c=None):
    c = c or cfg()
    return {k:v for k,v in c.items() if 'pass' not in k.lower() and 'secret' not in k.lower()}

def net_client():
    conf=oci.config.from_file(OCI_CONFIG)
    return oci.core.VirtualNetworkClient(conf)

def wait_ipv6(net, oid):
    for _ in range(50):
        obj=net.get_ipv6(oid).data
        if obj.lifecycle_state=='AVAILABLE': return obj
        time.sleep(1.2)
    return net.get_ipv6(oid).data

def create_oci_ipv6(display='proxy-panel-ipv6'):
    c=cfg(); net=net_client()
    r=net.create_ipv6(CreateIpv6Details(vnic_id=c['vnic_id'], subnet_id=c['subnet_id'], display_name=display))
    return wait_ipv6(net,r.data.id)

def delete_oci_ipv6(oid):
    try:
        net_client().delete_ipv6(oid)
        return None
    except ServiceError as e:
        return f'{e.status} {e.code}: {e.message}'
    except Exception as e:
        return str(e)

def add_os_ip(ip):
    c=cfg(); iface=c.get('iface','enp0s6')
    return run(f'ip -6 addr add {ip}/128 dev {iface} nodad 2>/dev/null || true; ip -6 addr show dev {iface} | grep -q {ip} && echo OK || echo FAIL')

def del_os_ip(ip):
    c=cfg(); iface=c.get('iface','enp0s6')
    return run(f'ip -6 addr del {ip}/128 dev {iface} 2>/dev/null || true; echo OK')

def restart_proxy():
    return run('systemctl restart oci-ipv6-socks.service && sleep 1 && systemctl is-active oci-ipv6-socks.service', timeout=25)

def next_port(s):
    c=cfg(); start=int(c.get('port_start',30000)); end=int(c.get('port_end',30031)); used={int(x['port']) for x in s}
    for p in range(start,end+1):
        if p not in used: return p
    return None

def proxy_uri(item):
    c=cfg(); host=c.get('public_host','127.0.0.1')
    u=item.get('username') or c.get('proxy_user')
    p=item.get('password') or c.get('proxy_pass')
    if u and p: return f'socks5://{u}:{p}@{host}:{item["port"]}'
    return f'socks5://{host}:{item["port"]}'

def enrich(items):
    return [{**x,'uri':proxy_uri(x),'can_rotate':not x.get('protected',False)} for x in items]

@app.route('/')
@require_auth
def index():
    return render_template_string(open(f'{BASE}/templates/index.html').read(), cfg=cfg())

@app.route('/api/status')
@require_auth
def api_status():
    s=state(); c=cfg()
    return jsonify({
        'config': public_config(c), 'count': len(s), 'max': c.get('max_proxies',32), 'proxies': enrich(s),
        'proxy_service': run('systemctl is-active oci-ipv6-socks.service || true'),
        'panel_service': run('systemctl is-active oci-ipv6-proxy-panel.service || true'),
        'oci_config_present': os.path.exists(OCI_CONFIG), 'oci_key_present': os.path.exists(OCI_KEY)
    })

@app.route('/api/add', methods=['POST'])
@require_auth
def api_add():
    c=cfg(); s=state(); n=int((request.json or {}).get('count',1))
    maxn=int(c.get('max_proxies',32)); can=maxn-len(s)
    n=max(1,min(n,can))
    if n<=0: return jsonify({'ok':False,'error':'已达到最大数量'}),400
    made=[]; errors=[]
    for _ in range(n):
        port=next_port(s)
        if not port: break
        try:
            obj=create_oci_ipv6('proxy-panel-ipv6')
            ip=obj.ip_address; osres=add_os_ip(ip)
            item={'id':obj.id,'ip':ip,'port':port,'username':c.get('proxy_user','proxy'),'password':c.get('proxy_pass','proxy'),'created':time.strftime('%F %T'),'os_add':osres,'protected':False}
            s.append(item); save_state(s); made.append({**item,'uri':proxy_uri(item)})
        except ServiceError as e:
            errors.append(f'{e.status} {e.code}: {e.message}'); break
        except Exception as e:
            errors.append(str(e)); break
    return jsonify({'ok':True,'added':made,'errors':errors,'restart':restart_proxy()})

@app.route('/api/rotate', methods=['POST'])
@require_auth
def api_rotate():
    oid=(request.json or {}).get('id')
    s=state(); idx=next((i for i,x in enumerate(s) if x['id']==oid),None)
    if idx is None: return jsonify({'ok':False,'error':'not found'}),404
    item=s[idx]
    if item.get('protected'):
        return jsonify({'ok':False,'error':'这个是实例原有主 IPv6，不能自动释放切换；请切换其它端口。'}),400
    old=dict(item)
    # Free old cloud object first because OCI VNIC is normally at 32/32 limit.
    del_os_ip(old['ip'])
    derr=delete_oci_ipv6(old['id'])
    time.sleep(2)
    try:
        obj=create_oci_ipv6('proxy-panel-rotated-ipv6')
        item.update({'id':obj.id,'ip':obj.ip_address,'rotated':time.strftime('%F %T'),'os_add':add_os_ip(obj.ip_address),'protected':False})
        s[idx]=item; save_state(s)
        return jsonify({'ok':True,'old':old,'new':{**item,'uri':proxy_uri(item)},'delete_error':derr,'restart':restart_proxy()})
    except Exception as e:
        # Keep state honest: old IP was released, remove this proxy entry so it cannot serve stale/broken IP.
        s.pop(idx); save_state(s); restart_proxy()
        return jsonify({'ok':False,'error':f'旧 IPv6 已释放，但新 IPv6 创建失败：{e}','old':old,'delete_error':derr}),500

@app.route('/api/delete', methods=['POST'])
@require_auth
def api_delete():
    oid=(request.json or {}).get('id')
    s=state(); item=next((x for x in s if x['id']==oid),None)
    if not item: return jsonify({'ok':False,'error':'not found'}),404
    del_os_ip(item['ip'])
    err=None
    if not item.get('protected'):
        err=delete_oci_ipv6(item['id'])
    s=[x for x in s if x['id']!=oid]; save_state(s)
    return jsonify({'ok':True,'delete_error':err,'restart':restart_proxy()})

@app.route('/api/delete_all', methods=['POST'])
@require_auth
def api_delete_all():
    s=state(); errs=[]; kept=[]
    for item in s:
        if item.get('protected'):
            kept.append(item); continue
        del_os_ip(item['ip'])
        err=delete_oci_ipv6(item['id'])
        if err: errs.append(err)
    save_state(kept)
    return jsonify({'ok':True,'kept_protected':len(kept),'errors':errs,'restart':restart_proxy()})

@app.route('/api/config', methods=['POST'])
@require_auth
def api_config():
    data=request.json or {}; c=cfg(); restart=False
    for k in ['force_ipv6','public_host','proxy_user','proxy_pass','panel_user','panel_pass']:
        if k in data:
            c[k]=bool(data[k]) if k=='force_ipv6' else str(data[k])
            if k in ['force_ipv6','proxy_user','proxy_pass']: restart=True
    # Apply new proxy credentials to existing proxy rows if requested.
    if data.get('apply_proxy_credentials_to_existing'):
        s=state()
        for it in s:
            it['username']=c.get('proxy_user','')
            it['password']=c.get('proxy_pass','')
        save_state(s); restart=True
    save_cfg(c)
    return jsonify({'ok':True,'config':public_config(c),'restart':restart_proxy() if restart else 'not-needed'})

@app.route('/api/oci_config', methods=['POST'])
@require_auth
def api_oci_config():
    data=request.json or {}
    required=['user','fingerprint','tenancy','region','private_key']
    missing=[k for k in required if not data.get(k)]
    if missing: return jsonify({'ok':False,'error':'缺少字段: '+','.join(missing)}),400
    os.makedirs(f'{BASE}/secure', exist_ok=True)
    key=str(data['private_key']).strip()+"\n"
    with open(OCI_KEY,'w') as f: f.write(key)
    os.chmod(OCI_KEY,0o600)
    content='[DEFAULT]\nuser={user}\nfingerprint={fingerprint}\ntenancy={tenancy}\nregion={region}\nkey_file={key_file}\n'.format(key_file=OCI_KEY, **{k:str(data[k]).strip() for k in ['user','fingerprint','tenancy','region']})
    with open(OCI_CONFIG,'w') as f: f.write(content)
    os.chmod(OCI_CONFIG,0o600)
    c=cfg()
    for k in ['vnic_id','subnet_id']:
        if data.get(k): c[k]=str(data[k]).strip()
    save_cfg(c)
    # Validate by listing current VNIC IPv6s when possible.
    try:
        ips=[oci.util.to_dict(x) for x in net_client().list_ipv6s(vnic_id=c.get('vnic_id')).data] if c.get('vnic_id') else []
        return jsonify({'ok':True,'validated':True,'ipv6_count':len(ips),'config':public_config(c)})
    except Exception as e:
        return jsonify({'ok':True,'validated':False,'warning':str(e),'config':public_config(c)})

@app.route('/api/export')
@require_auth
def api_export():
    return Response('\n'.join(proxy_uri(x) for x in state())+'\n', mimetype='text/plain; charset=utf-8')

@app.route('/api/restart', methods=['POST'])
@require_auth
def api_restart(): return jsonify({'ok':True,'restart':restart_proxy()})

if __name__=='__main__':
    app.run(host='0.0.0.0', port=int(cfg().get('panel_port',18080)))
