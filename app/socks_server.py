#!/usr/bin/env python3
import asyncio, json, struct, socket, os
BASE=os.environ.get('OCI_PROXY_BASE','/opt/oci-ipv6-proxy-panel')
CONFIG=f'{BASE}/config.json'
STATE=f'{BASE}/data/proxies.json'

def load(path, default):
    try:
        with open(path) as f: return json.load(f)
    except Exception: return default

def cfg(): return load(CONFIG,{})
def state(): return load(STATE,[])
async def read_exact(r,n): return await r.readexactly(n)
async def pipe(a,b):
    try:
        while True:
            data=await a.read(65536)
            if not data: break
            b.write(data); await b.drain()
    except Exception: pass
    try: b.close()
    except Exception: pass

def resolve_first(host, port, family):
    infos=socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    if not infos: raise OSError('no address')
    return infos[0][4]
async def open_v6_connection(host, port, src):
    loop=asyncio.get_running_loop(); dest=await loop.run_in_executor(None, resolve_first, host, port, socket.AF_INET6)
    sock=socket.socket(socket.AF_INET6, socket.SOCK_STREAM); sock.setblocking(False); sock.bind((src,0,0,0))
    try:
        await asyncio.wait_for(loop.sock_connect(sock, dest), timeout=15)
        r,w=await asyncio.open_connection(sock=sock); return r,w,'ipv6-bound'
    except Exception:
        sock.close(); raise
async def open_v4_fallback(host, port):
    loop=asyncio.get_running_loop(); dest=await loop.run_in_executor(None, resolve_first, host, port, socket.AF_INET)
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.setblocking(False)
    try:
        await asyncio.wait_for(loop.sock_connect(sock, dest), timeout=15)
        r,w=await asyncio.open_connection(sock=sock); return r,w,'ipv4-fallback'
    except Exception:
        sock.close(); raise
async def handle_client(reader, writer, item):
    c=cfg(); user=(item.get('username') or c.get('proxy_user','')).encode(); pwd=(item.get('password') or c.get('proxy_pass','')).encode(); src=item['ip']
    try:
        head=await read_exact(reader,2)
        if head[0]!=5: writer.close(); return
        methods=await read_exact(reader,head[1])
        if user and pwd:
            if 2 not in methods: writer.write(b'\x05\xff'); await writer.drain(); writer.close(); return
            writer.write(b'\x05\x02'); await writer.drain(); await read_exact(reader,1)
            ulen=(await read_exact(reader,1))[0]; u=await read_exact(reader,ulen)
            plen=(await read_exact(reader,1))[0]; p=await read_exact(reader,plen)
            if u!=user or p!=pwd: writer.write(b'\x01\x01'); await writer.drain(); writer.close(); return
            writer.write(b'\x01\x00'); await writer.drain()
        else:
            writer.write(b'\x05\x00'); await writer.drain()
        ver,cmd,_,atyp=await read_exact(reader,4)
        if ver!=5 or cmd!=1: writer.write(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00'); await writer.drain(); writer.close(); return
        if atyp==1: host=socket.inet_ntop(socket.AF_INET, await read_exact(reader,4))
        elif atyp==3:
            ln=(await read_exact(reader,1))[0]; host=(await read_exact(reader,ln)).decode(errors='ignore')
        elif atyp==4: host=socket.inet_ntop(socket.AF_INET6, await read_exact(reader,16))
        else: writer.close(); return
        port=struct.unpack('!H', await read_exact(reader,2))[0]
        force_ipv6=bool(cfg().get('force_ipv6', False))
        try:
            rr,ww,mode=await open_v6_connection(host, port, src)
        except Exception as e6:
            if force_ipv6:
                print(f'connect failed {host}:{port} via {src}: v6={e6}; force_ipv6=on no fallback', flush=True)
                writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'); await writer.drain(); writer.close(); return
            try: rr,ww,mode=await open_v4_fallback(host, port)
            except Exception as e4:
                print(f'connect failed {host}:{port} via {src}: v6={e6} v4={e4}', flush=True)
                writer.write(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'); await writer.drain(); writer.close(); return
        if mode=='ipv6-bound': writer.write(b'\x05\x00\x00\x04'+socket.inet_pton(socket.AF_INET6,src)+b'\x00\x00')
        else: writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await writer.drain(); await asyncio.gather(pipe(reader,ww),pipe(rr,writer))
    except Exception as e:
        print(f'client error: {e}', flush=True)
        try: writer.close()
        except Exception: pass
async def main():
    servers=[]
    for item in state():
        if not item.get('port') or not item.get('ip'): continue
        srv=await asyncio.start_server(lambda r,w,it=item: handle_client(r,w,it), '0.0.0.0', int(item['port']), reuse_address=True)
        servers.append(srv); print(f"listening {item['port']} -> {item['ip']}", flush=True)
    if not servers:
        print('no proxies configured; idle', flush=True)
        while True: await asyncio.sleep(3600)
    await asyncio.gather(*(s.serve_forever() for s in servers))
if __name__=='__main__': asyncio.run(main())
