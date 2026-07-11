#!/usr/bin/env python3
import os, json, time, subprocess, secrets, string, base64
from urllib.parse import quote
from functools import wraps
from flask import Flask, request, jsonify, Response, render_template_string
import oci
from oci.core.models import CreateIpv6Details, AttachVnicDetails, CreateVnicDetails
from oci.exceptions import ServiceError

BASE=os.environ.get('OCI_PROXY_BASE','/opt/oci-ipv6-proxy-panel')
CONFIG=f'{BASE}/config.json'; STATE=f'{BASE}/data/proxies.json'; VNICS=f'{BASE}/data/vnics.json'
SS_CONFIG=f'{BASE}/data/shadowsocks.json'; SS_GENERATOR=f'{BASE}/ss_config.py'
OCI_CONFIG=f'{BASE}/secure/oci_config'; OCI_KEY=f'{BASE}/secure/oci_api_key.pem'
# Runtime values are loaded from config.json / environment.
# Do not hardcode real OCIDs in source control.
def instance_id(): return os.environ.get('OCI_INSTANCE_ID') or cfg().get('instance_id','')
def compartment_id(): return os.environ.get('OCI_COMPARTMENT_ID') or cfg().get('compartment_id','')
def max_vnics(): return int(os.environ.get('OCI_MAX_VNICS') or cfg().get('max_vnics', 4))
app=Flask(__name__)

def load_json(path, default):
    try:
        with open(path) as f: return json.load(f)
    except Exception: return default

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp=path+'.tmp'
    with open(tmp,'w') as f: json.dump(data,f,indent=2,ensure_ascii=False)
    os.replace(tmp,path)

def cfg(): return load_json(CONFIG,{})
def save_cfg(c): save_json(CONFIG,c)
def state(): return load_json(STATE,[])
def save_state(s): save_json(STATE,s)
def vnics(): return load_json(VNICS,[])
def save_vnics(v): save_json(VNICS,v)
def run(cmd, timeout=30): return subprocess.run(cmd,shell=True,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout).stdout.strip()

def require_auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        c=cfg(); auth=request.authorization
        if not auth or auth.username!=c.get('panel_user') or auth.password!=c.get('panel_pass'):
            return Response('Auth required',401,{'WWW-Authenticate':'Basic realm="OCI IPv6 Proxy Panel"'})
        return fn(*a, **kw)
    return wrapper

def public_config(c=None):
    c=c or cfg()
    return {k:v for k,v in c.items() if 'pass' not in k.lower() and 'secret' not in k.lower() and k != 'subscription_token'}
def oci_conf(): return oci.config.from_file(OCI_CONFIG)
def net_client(): return oci.core.VirtualNetworkClient(oci_conf())
def compute_client(): return oci.core.ComputeClient(oci_conf())

def wait_ipv6(net, oid):
    for _ in range(50):
        obj=net.get_ipv6(oid).data
        if obj.lifecycle_state=='AVAILABLE': return obj
        time.sleep(1.2)
    return net.get_ipv6(oid).data

def wait_attach(compute, aid):
    for _ in range(80):
        a=compute.get_vnic_attachment(aid).data
        if a.lifecycle_state=='ATTACHED': return a
        time.sleep(2)
    return compute.get_vnic_attachment(aid).data

def create_oci_ipv6(vnic_id, subnet_id, display='proxy-panel-ipv6'):
    net=net_client(); r=net.create_ipv6(CreateIpv6Details(vnic_id=vnic_id, subnet_id=subnet_id, display_name=display)); return wait_ipv6(net,r.data.id)
def delete_oci_ipv6(oid):
    try: net_client().delete_ipv6(oid); return None
    except ServiceError as e: return f'{e.status} {e.code}: {e.message}'
    except Exception as e: return str(e)

def table_for(item):
    vid=item.get('vnic_id')
    return next((int(v.get('table',100)) for v in vnics() if v.get('vnic_id')==vid), 100)
def add_os_ip(ip, iface=None, table=None):
    iface=iface or cfg().get('iface','enp0s6'); table=table or 100
    run(f'ip link set {iface} up || true')
    run(f'ip -6 addr add {ip}/128 dev {iface} nodad 2>/dev/null || true')
    run(f'ip -6 route replace default via fe80::200:17ff:fe36:1c6b dev {iface} table {table} || true')
    run(f'ip -6 rule add from {ip}/128 table {table} priority {10000+table} 2>/dev/null || true')
    return run(f'ip -6 addr show dev {iface} | grep -q {ip} && echo OK || echo FAIL')
def del_os_ip(ip, iface=None, table=None):
    iface=iface or cfg().get('iface','enp0s6'); table=table or 100
    run(f'ip -6 addr del {ip}/128 dev {iface} 2>/dev/null || true')
    run(f'ip -6 rule del from {ip}/128 table {table} priority {10000+table} 2>/dev/null || true')
    return 'OK'
def restart_proxy(): return run('systemctl restart oci-ipv6-socks.service && sleep 1 && systemctl is-active oci-ipv6-socks.service', timeout=25)
def restart_ss():
    run(f'python3 {SS_GENERATOR}', timeout=25)
    return run('systemctl restart oci-ipv6-ss.service && sleep 1 && systemctl is-active oci-ipv6-ss.service', timeout=25)

def next_port(s):
    c=cfg(); start=int(c.get('port_start',30000)); end=int(c.get('port_end',30127)); used={int(x['port']) for x in s}
    for p in range(start,end+1):
        if p not in used: return p
    return None

def random_text(prefix='', n=16):
    alphabet='abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return prefix + ''.join(secrets.choice(alphabet) for _ in range(n))

def subscription_token():
    """Create one opaque, revocable token for public read-only subscriptions."""
    c=cfg(); token=c.get('subscription_token','')
    if not token:
        token=secrets.token_urlsafe(32)
        c['subscription_token']=token
        save_cfg(c)
    return token

def ensure_subscription_ids(items=None):
    """Keep selection IDs stable when an OCI IPv6 object is rotated."""
    items=state() if items is None else items
    changed=False
    for item in items:
        if not item.get('subscription_id'):
            item['subscription_id']=secrets.token_urlsafe(12)
            changed=True
    if changed: save_state(items)
    return items

def selected_subscription_items(keys=None):
    items=ensure_subscription_ids()
    if not keys: return items
    wanted=set(keys)
    return [item for item in items if item.get('subscription_id') in wanted]

def subscription_url(token, keys=None, fmt=None):
    base=request.host_url.rstrip('/') + '/subscribe/' + quote(token, safe='')
    params=[]
    if keys: params.append('ids=' + quote(','.join(keys), safe=','))
    if fmt == 'clash': params.append('format=clash')
    return base + ('?' + '&'.join(params) if params else '')

def yaml_value(value):
    """JSON strings are valid YAML strings and safely preserve special characters."""
    return json.dumps(str(value), ensure_ascii=False)

def clash_config(items, protocol='socks5'):
    proxies=[]; names=[]; c=cfg(); host=c.get('public_host','127.0.0.1')
    for item in items:
        port=ss_port(item) if protocol == 'ss' else int(item['port'])
        name=f'OCI {"SS" if protocol == "ss" else "SOCKS5"} {port}'
        names.append(name)
        proxies.extend([f'  - name: {yaml_value(name)}', f'    type: {"ss" if protocol == "ss" else "socks5"}',
                        f'    server: {yaml_value(host)}', f'    port: {port}'])
        if protocol == 'ss':
            proxies.extend([f'    cipher: {yaml_value(c.get("ss_method","aes-256-gcm"))}', f'    password: {yaml_value(c.get("ss_password",""))}', '    udp: true'])
        else:
            proxies.extend([f'    username: {yaml_value(item.get("username") or c.get("proxy_user", ""))}', f'    password: {yaml_value(item.get("password") or c.get("proxy_pass", ""))}', '    udp: true'])
    label='OCI Shadowsocks' if protocol == 'ss' else 'OCI IPv6 SOCKS5'
    group=[f'  - name: {yaml_value(label)}','    type: select','    proxies:'] + [f'      - {yaml_value(name)}' for name in names]
    return '\n'.join(['mixed-port: 7890','allow-lan: false','mode: rule','log-level: info','proxies:'] + proxies + ['proxy-groups:'] + group + ['rules:',f'  - MATCH,{label}',''])

def proxy_uri(item):
    c=cfg(); host=c.get('public_host','127.0.0.1'); u=item.get('username') or c.get('proxy_user'); p=item.get('password') or c.get('proxy_pass')
    return f'socks5://{u}:{p}@{host}:{item["port"]}' if u and p else f'socks5://{host}:{item["port"]}'
def ss_port(item):
    c=cfg(); return int(item.get('ss_port') or int(c.get('ss_port_start',31000)) + int(item['port'])-int(c.get('port_start',30000)))
def ss_uri(item):
    c=cfg(); method=c.get('ss_method','aes-256-gcm'); password=c.get('ss_password','')
    host=c.get('public_host','127.0.0.1'); credential=base64.urlsafe_b64encode(f'{method}:{password}'.encode()).decode().rstrip('=')
    return f'ss://{credential}@{host}:{ss_port(item)}#{quote("OCI-SS-"+str(item["port"]))}'
def enrich(items):
    ensure_subscription_ids(items)
    token=subscription_token()
    return [{**x,'uri':proxy_uri(x),'ss_uri':ss_uri(x),'ss_port':ss_port(x),'can_rotate':not x.get('protected',False),
             'subscription_url':subscription_url(token,[x['subscription_id']])} for x in items]

def vnic_counts():
    counts={v.get('vnic_id'):0 for v in vnics()}
    for it in state(): counts[it.get('vnic_id')]=counts.get(it.get('vnic_id'),0)+1
    return counts
def choose_vnic_for_add():
    counts=vnic_counts(); candidates=[v for v in vnics() if counts.get(v.get('vnic_id'),0)<32]
    if not candidates: return None
    candidates.sort(key=lambda v: counts.get(v.get('vnic_id'),0))
    return candidates[0]

@app.route('/')
@require_auth
def index(): return render_template_string(open(f'{BASE}/templates/index.html').read(), cfg=cfg())
@app.route('/api/status')
@require_auth
def api_status():
    items=ensure_subscription_ids(); c=cfg(); counts=vnic_counts(); vlist=[]
    for v in vnics(): vlist.append({**v,'count':counts.get(v.get('vnic_id'),0)})
    return jsonify({'config':public_config(c),'count':len(items),'max':c.get('max_proxies',len(vlist)*32),'proxies':enrich(items),'vnics':vlist,
                    'subscriptions':{'all_url':subscription_url(subscription_token())},
                    'proxy_service':run('systemctl is-active oci-ipv6-socks.service || true'),'panel_service':run('systemctl is-active oci-ipv6-proxy-panel.service || true')})
@app.route('/api/add',methods=['POST'])
@require_auth
def api_add():
    data=request.json or {}
    s=state(); n=int(data.get('count',1)); made=[]; errors=[]
    requested_vnic=data.get('vnic_id')
    for _ in range(max(1,n)):
        if requested_vnic:
            v=next((x for x in vnics() if x.get('vnic_id')==requested_vnic), None)
            if v and vnic_counts().get(requested_vnic,0) >= 32:
                v=None
        else:
            v=choose_vnic_for_add()
        port=next_port(s)
        if not v or not port: errors.append('指定/可用 VNIC 容量不足或端口已满'); break
        try:
            obj=create_oci_ipv6(v['vnic_id'],v['subnet_id'])
            item={'id':obj.id,'subscription_id':secrets.token_urlsafe(12),'ip':obj.ip_address,'port':port,'username':cfg().get('proxy_user','proxy'),'password':cfg().get('proxy_pass','proxy'),'created':time.strftime('%F %T'),'protected':False,'vnic_id':v['vnic_id'],'subnet_id':v['subnet_id'],'iface':v['iface'],'os_add':add_os_ip(obj.ip_address,v['iface'],int(v.get('table',100)))}
            s.append(item); save_state(s); made.append({**item,'uri':proxy_uri(item)})
        except Exception as e: errors.append(str(e)); break
    return jsonify({'ok':True,'added':made,'errors':errors,'restart':restart_proxy(),'ss_restart':restart_ss()})
@app.route('/api/rotate',methods=['POST'])
@require_auth
def api_rotate():
    oid=(request.json or {}).get('id'); s=state(); idx=next((i for i,x in enumerate(s) if x['id']==oid),None)
    if idx is None: return jsonify({'ok':False,'error':'not found'}),404
    item=s[idx]
    if item.get('protected'): return jsonify({'ok':False,'error':'默认主 IPv6 不能切换'}),400
    old=dict(item); table=table_for(item); del_os_ip(old['ip'],old.get('iface'),table); derr=delete_oci_ipv6(old['id']); time.sleep(2)
    try:
        obj=create_oci_ipv6(item['vnic_id'],item['subnet_id'],'proxy-panel-rotated-ipv6')
        item.update({'id':obj.id,'ip':obj.ip_address,'rotated':time.strftime('%F %T'),'os_add':add_os_ip(obj.ip_address,item.get('iface'),table)})
        s[idx]=item; save_state(s); return jsonify({'ok':True,'old':old,'new':{**item,'uri':proxy_uri(item)},'delete_error':derr,'restart':restart_proxy(),'ss_restart':restart_ss()})
    except Exception as e:
        s.pop(idx); save_state(s); restart_proxy(); return jsonify({'ok':False,'error':f'旧 IPv6 已释放，但新 IPv6 创建失败：{e}','old':old,'delete_error':derr}),500
@app.route('/api/delete',methods=['POST'])
@require_auth
def api_delete():
    oid=(request.json or {}).get('id'); s=state(); item=next((x for x in s if x['id']==oid),None)
    if not item: return jsonify({'ok':False,'error':'not found'}),404
    del_os_ip(item['ip'],item.get('iface'),table_for(item)); err=None
    if not item.get('protected'): err=delete_oci_ipv6(item['id'])
    save_state([x for x in s if x['id']!=oid]); return jsonify({'ok':True,'delete_error':err,'restart':restart_proxy(),'ss_restart':restart_ss()})
@app.route('/api/vnics/add',methods=['POST'])
@require_auth
def api_vnic_add():
    limit=max_vnics()
    if len(vnics())>=limit: return jsonify({'ok':False,'error':f'当前配置最多 {limit} 个 VNIC，已满'}),400
    iid=instance_id()
    if not iid: return jsonify({'ok':False,'error':'缺少 instance_id，请在 config.json 或环境变量 OCI_INSTANCE_ID 中配置'}),400
    c=cfg(); compute=compute_client(); net=net_client(); name=f'proxy-secondary-vnic-{len(vnics())}'
    r=compute.attach_vnic(AttachVnicDetails(instance_id=iid,display_name=name,create_vnic_details=CreateVnicDetails(subnet_id=c.get('subnet_id'),display_name=name,assign_public_ip=False,assign_ipv6_ip=True)))
    a=wait_attach(compute,r.data.id); vnic=net.get_vnic(a.vnic_id).data
    time.sleep(3)
    # map iface by MAC
    mac=vnic.mac_address.lower(); iface=None
    for _ in range(20):
        for n in os.listdir('/sys/class/net'):
            try:
                if open('/sys/class/net/'+n+'/address').read().strip().lower()==mac: iface=n
            except Exception: pass
        if iface: break
        time.sleep(1)
    if not iface: return jsonify({'ok':False,'error':'VNIC 已创建但系统未发现网卡，请稍后刷新/重启网络','vnic_id':vnic.id}),500
    vlist=vnics(); table=100+len(vlist); rec={'vnic_id':vnic.id,'attachment_id':a.id,'display_name':vnic.display_name,'is_primary':False,'protected':False,'subnet_id':vnic.subnet_id,'mac':mac,'iface':iface,'private_ip':vnic.private_ip,'table':table}
    vlist.append(rec); save_vnics(vlist); run(f'ip link set {iface} up'); run(f'ip -6 route replace default via fe80::200:17ff:fe36:1c6b dev {iface} table {table}')
    return jsonify({'ok':True,'vnic':rec})
@app.route('/api/vnics/delete',methods=['POST'])
@require_auth
def api_vnic_delete():
    vid=(request.json or {}).get('vnic_id'); v=next((x for x in vnics() if x.get('vnic_id')==vid),None)
    if not v: return jsonify({'ok':False,'error':'not found'}),404
    if v.get('protected') or v.get('is_primary'): return jsonify({'ok':False,'error':'默认主 VNIC 禁止删除'}),400
    if any(x.get('vnic_id')==vid for x in state()): return jsonify({'ok':False,'error':'这个 VNIC 下面还有代理，请先删除这些代理'}),400
    try: compute_client().detach_vnic(v['attachment_id'])
    except Exception as e: return jsonify({'ok':False,'error':str(e)}),500
    save_vnics([x for x in vnics() if x.get('vnic_id')!=vid]); return jsonify({'ok':True})
@app.route('/api/proxy_credentials/random',methods=['POST'])
@require_auth
def api_proxy_credentials_random():
    data=request.json or {}; c=cfg()
    c['proxy_user']=random_text('u_',10); c['proxy_pass']=random_text('p_',18)
    s=state()
    if data.get('apply_existing', True):
        for it in s: it['username']=c['proxy_user']; it['password']=c['proxy_pass']
        save_state(s)
    save_cfg(c)
    return jsonify({'ok':True,'proxy_user':c['proxy_user'],'proxy_pass':c['proxy_pass'],'updated_existing':bool(data.get('apply_existing', True)),'restart':restart_proxy()})

@app.route('/api/config',methods=['POST'])
@require_auth
def api_config():
    data=request.json or {}; c=cfg(); restart=False
    for k in ['force_ipv6','public_host','proxy_user','proxy_pass','panel_user','panel_pass']:
        if k in data and data[k] != '': c[k]=bool(data[k]) if k=='force_ipv6' else str(data[k]); restart = restart or k in ['force_ipv6','proxy_user','proxy_pass']
    if data.get('apply_proxy_credentials_to_existing'):
        s=state()
        for it in s: it['username']=c.get('proxy_user',''); it['password']=c.get('proxy_pass','')
        save_state(s); restart=True
    save_cfg(c); return jsonify({'ok':True,'config':public_config(c),'restart':restart_proxy() if restart else 'not-needed'})
@app.route('/api/export')
@require_auth
def api_export(): return Response('\n'.join(proxy_uri(x) for x in state())+'\n',mimetype='text/plain; charset=utf-8')

@app.route('/subscribe/<token>')
def subscription(token):
    """Public read-only endpoint protected by the high-entropy URL token."""
    if not secrets.compare_digest(token, subscription_token()):
        return Response('Not found\n', status=404, mimetype='text/plain')
    raw=request.args.get('ids','').strip()
    keys=[x for x in raw.split(',') if x] if raw else None
    items=selected_subscription_items(keys)
    is_clash=request.args.get('format','').lower() == 'clash'
    protocol='ss' if request.args.get('protocol','').lower() == 'ss' else 'socks5'
    body=clash_config(items, protocol) if is_clash else '\n'.join(ss_uri(item) if protocol == 'ss' else proxy_uri(item) for item in items)+'\n'
    mimetype='text/yaml; charset=utf-8' if is_clash else 'text/plain; charset=utf-8'
    filename=('oci-ss' if protocol == 'ss' else 'oci-socks5') + ('-clash.yaml' if is_clash else '-subscription.txt')
    response=Response(body, mimetype=mimetype)
    response.headers['Content-Disposition']=f'inline; filename="{filename}"'
    response.headers['Cache-Control']='no-store'
    return response

@app.route('/api/restart',methods=['POST'])
@require_auth
def api_restart(): return jsonify({'ok':True,'restart':restart_proxy()})
if __name__=='__main__': app.run(host='0.0.0.0',port=int(cfg().get('panel_port',18080)))
