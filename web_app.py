from __future__ import annotations

import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from flask import Flask, Response, abort, jsonify, request, send_file, session

APP_NAME = "Elephant Scrape"
BASE_DIR = Path(os.environ.get("ELEPHANT_DATA_DIR", Path.cwd() / ".elephant_data"))
BASE_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD = int(os.environ.get("ELEPHANT_MAX_UPLOAD", str(512 * 1024 * 1024)))

app = Flask(__name__)
app.secret_key = os.environ.get("ELEPHANT_SESSION_SECRET", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD + 4 * 1024 * 1024

def user_id() -> str:
    uid = session.get("uid")
    if not uid:
        uid = secrets.token_urlsafe(24)
        session["uid"] = uid
    return uid

def user_dir() -> Path:
    path = BASE_DIR / user_id()
    path.mkdir(parents=True, exist_ok=True)
    return path

def safe_id(value: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,100}", value or ""):
        abort(400, "Invalid file id")
    return value

def manifest_path() -> Path:
    return user_dir() / "manifest.json"

def load_manifest() -> list[dict[str, Any]]:
    p = manifest_path()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []

def save_manifest(items: list[dict[str, Any]]) -> None:
    p = manifest_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, p)

def blob_path(file_id: str) -> Path:
    return user_dir() / (safe_id(file_id) + ".blob")

@app.after_request
def security_headers(response: Response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'"
    )
    return response

@app.get("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")

@app.route("/api/index", methods=["GET", "POST", "DELETE"])
def vercel_dispatch():
    """Dispatch Vercel rewrites back to the Flask routes."""
    path = request.args.get("path", "/")
    if path == "/":
        return index()
    if path == "/api/me" and request.method == "GET":
        return api_me()
    if path == "/api/files" and request.method == "GET":
        return api_files()
    if path == "/api/files" and request.method == "POST":
        return api_upload()
    match = re.fullmatch(r"/api/files/([A-Za-z0-9_-]{16,100})", path)
    if match:
        file_id = match.group(1)
        if request.method == "GET":
            return api_download(file_id)
        if request.method == "DELETE":
            return api_delete(file_id)
    abort(404)

@app.get("/api/me")
def api_me():
    items = load_manifest()
    return jsonify({
        "app": APP_NAME,
        "files": len(items),
        "bytes": sum(int(x.get("size", 0)) for x in items),
        "encrypted_by_client": True,
    })

@app.get("/api/files")
def api_files():
    # Names are encrypted; browser-side search happens after vault unlock.
    return jsonify(load_manifest())

@app.post("/api/files")
def api_upload():
    upload = request.files.get("blob")
    metadata_raw = request.form.get("metadata", "")
    if upload is None or not metadata_raw:
        abort(400, "Encrypted file and metadata are required")
    try:
        metadata = json.loads(metadata_raw)
    except ValueError:
        abort(400, "Invalid metadata")
    if not isinstance(metadata, dict) or not metadata.get("clientEncrypted"):
        abort(400, "Only client-encrypted objects are accepted")

    file_id = secrets.token_urlsafe(24)
    target = blob_path(file_id)
    size = 0
    with target.open("wb") as out:
        while True:
            chunk = upload.stream.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_UPLOAD:
                out.close()
                target.unlink(missing_ok=True)
                abort(413, "File is too large")
            out.write(chunk)

    record = {"id": file_id, "size": size, "created": int(time.time()), "metadata": metadata}
    items = load_manifest()
    items.append(record)
    save_manifest(items)
    return jsonify(record), 201

@app.get("/api/files/<file_id>")
def api_download(file_id: str):
    path = blob_path(file_id)
    if not path.exists():
        abort(404)
    return send_file(path, mimetype="application/octet-stream", as_attachment=False)

@app.delete("/api/files/<file_id>")
def api_delete(file_id: str):
    safe_id(file_id)
    items = load_manifest()
    remaining = [x for x in items if x.get("id") != file_id]
    if len(remaining) == len(items):
        abort(404)
    blob_path(file_id).unlink(missing_ok=True)
    save_manifest(remaining)
    return jsonify({"ok": True})

INDEX_HTML = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Elephant Scrape</title>
<style>
:root{--sand:#F5F2EB;--card:#EFEAE0;--ink:#3E2723;--muted:#6d5b52;--border:#C2A67D;--hover:#D2B48C;--danger:#9b2c2c}
*{box-sizing:border-box}body{margin:0;background:var(--sand);color:var(--ink);font-family:Inter,Segoe UI,Arial,sans-serif}.app{min-height:100vh;display:flex;flex-direction:column}
.top{display:flex;align-items:center;gap:16px;padding:22px 28px;border-bottom:1px solid var(--border)}.logo{font-size:28px;font-weight:800}.tag,.lock{color:var(--muted)}.lock{margin-left:auto;font-size:13px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;padding:14px 28px;background:var(--card);border-bottom:1px solid var(--border)}button{border:1px solid var(--border);background:#fffaf1;color:var(--ink);padding:9px 14px;border-radius:9px;cursor:pointer}button:hover{background:var(--hover)}button.primary{font-weight:700}button.danger{color:var(--danger)}
.main{display:grid;grid-template-columns:230px 1fr;gap:16px;flex:1;padding:18px 28px}.side,.panel{background:var(--card);border:1px solid var(--border);border-radius:14px}.side{padding:16px}.side h3{margin:0 0 14px}.provider{padding:10px;border-radius:8px;background:#fffaf1}.provider small{display:block;color:var(--muted);margin-top:4px}.panel{padding:16px;min-width:0}
.search{display:flex;gap:8px;margin-bottom:14px}.search input{flex:1;border:1px solid var(--border);border-radius:9px;padding:10px 12px;background:#fffdf8;color:var(--ink)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid #d8cbb9}th{font-size:13px;color:var(--muted)}td.name{font-weight:650}tr.selected{background:#eadfce}.empty{text-align:center;padding:60px 20px;color:var(--muted)}
.status{padding:12px 28px;border-top:1px solid var(--border);color:var(--muted);font-size:13px}.modal{position:fixed;inset:0;background:rgba(62,39,35,.35);display:none;align-items:center;justify-content:center;padding:20px}.modal.open{display:flex}.box{max-width:480px;width:100%;background:var(--sand);border:1px solid var(--border);border-radius:16px;padding:22px}.box h2{margin-top:0}.box input{width:100%;padding:11px;border:1px solid var(--border);border-radius:9px;margin:8px 0 14px;background:white}.warning{background:#fff4df;border-left:4px solid #b07b22;padding:12px;border-radius:7px;margin:10px 0}.actions{display:flex;justify-content:flex-end;gap:8px}.hidden{display:none!important}
@media(max-width:800px){.main{grid-template-columns:1fr;padding:12px}.side{display:none}.top,.toolbar,.status{padding-left:14px;padding-right:14px}.tag{display:none}table th:nth-child(3),table td:nth-child(3){display:none}}
</style></head>
<body>
<div class="app">
<header class="top"><div class="logo">Elephant Scrape</div><div class="tag">privacy-first unified storage</div><div class="lock">🔒 encryption happens in your browser</div></header>
<nav class="toolbar"><button class="primary" id="uploadBtn">Upload</button><button id="refreshBtn">Refresh</button><button id="downloadBtn">Download</button><button class="danger" id="deleteBtn">Delete</button><button id="vaultBtn">Vault</button></nav>
<main class="main"><aside class="side"><h3>Storage</h3><div class="provider"><strong>Web storage</strong><small>Encrypted objects on this Elephant Scrape server</small></div><p style="color:var(--muted);font-size:13px;line-height:1.5">Cloud providers can be added behind the same storage adapter without exposing your decrypted files to the server.</p></aside>
<section class="panel"><div class="search"><input id="search" placeholder="Search your decrypted file names…"><button id="searchBtn">Search</button></div><table><thead><tr><th>Name</th><th>Size</th><th>Added</th><th></th></tr></thead><tbody id="files"></tbody></table><div id="empty" class="empty">No files yet. Upload something to start your vault.</div></section></main>
<footer class="status" id="status">Ready.</footer></div>
<input id="fileInput" type="file" multiple class="hidden">
<div class="modal" id="vaultModal"><div class="box"><h2>Vault passphrase</h2><p>Your passphrase stays in this browser tab. It is never sent to Elephant Scrape.</p><input id="passphrase" type="password" autocomplete="new-password" placeholder="Choose or enter your vault passphrase"><div class="warning">If you forget this passphrase, encrypted files cannot be recovered by the server.</div><div class="actions"><button id="vaultCancel">Cancel</button><button class="primary" id="vaultSave">Unlock vault</button></div></div></div>
<script>
const state={key:null,salt:null,files:[]},$=id=>document.getElementById(id),enc=new TextEncoder(),dec=new TextDecoder();
function b64(buf){return btoa(String.fromCharCode(...new Uint8Array(buf)))}function ub64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
async function derive(pass,salt){const base=await crypto.subtle.importKey('raw',enc.encode(pass),'PBKDF2',false,['deriveKey']);return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:310000,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
$('vaultSave').onclick=async()=>{const p=$('passphrase').value;if(p.length<10){alert('Use a passphrase of at least 10 characters.');return}const saved=sessionStorage.getItem('vaultSalt');state.salt=saved?ub64(saved):crypto.getRandomValues(new Uint8Array(16));state.key=await derive(p,state.salt);sessionStorage.setItem('vaultSalt',b64(state.salt));$('passphrase').value='';$('vaultModal').classList.remove('open');setStatus('Vault unlocked.');render()};
$('vaultCancel').onclick=()=> $('vaultModal').classList.remove('open');
async function encryptFile(file){const data=await file.arrayBuffer(),iv=crypto.getRandomValues(new Uint8Array(12)),metadataIv=crypto.getRandomValues(new Uint8Array(12));const meta=enc.encode(JSON.stringify({name:file.name,type:file.type,size:file.size,lastModified:file.lastModified}));const metadataCipher=await crypto.subtle.encrypt({name:'AES-GCM',iv:metadataIv},state.key,meta),cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},state.key,data);return{blob:new Blob([cipher],{type:'application/octet-stream'}),metadata:{iv:b64(iv),metadataIv:b64(metadataIv),metadataCipher:b64(metadataCipher),salt:b64(state.salt),clientEncrypted:true,version:2}}}
async function decryptMetadata(record){const iv=ub64(record.metadata.metadataIv),plain=await crypto.subtle.decrypt({name:'AES-GCM',iv},state.key,ub64(record.metadata.metadataCipher));return JSON.parse(dec.decode(plain))}
async function decryptFile(record){const r=await fetch('/api/files/'+encodeURIComponent(record.id));if(!r.ok)throw Error('Download failed');const data=await crypto.subtle.decrypt({name:'AES-GCM',iv:ub64(record.metadata.iv),},await r.arrayBuffer());return{data,meta:await decryptMetadata(record)}}
function kind(name){const e=name.toLowerCase().split('.').pop();if(['exe','msi','com','scr','bat','cmd','ps1','vbs','js','jar','dll','sys'].includes(e))return'executable';if(['py','rs','c','h','cpp','cs','java','ts','tsx','jsx','go','rb','php','html','css','sh'].includes(e))return'code';if(['png','jpg','jpeg','gif','webp','bmp','tiff'].includes(e))return'image';if(['txt','md','csv','json','xml','yaml','yml','log'].includes(e))return'text';return'unknown'}
function inspect(file){const k=kind(file.name),target={text:5,image:5,code:10,executable:20,unknown:40}[k],reasons=file.size?[]:['The file is empty.'];return{kind:k,target,reasons,safe:!reasons.length}}
async function upload(){if(!state.key){$('vaultModal').classList.add('open');return}const input=$('fileInput');input.value='';input.click();input.onchange=async()=>{try{for(const file of input.files){const check=inspect(file);if(!check.safe&&!confirm('Security warning: '+check.reasons.join(' ')+'\n\nUpload anyway?'))continue;setStatus('Encrypting '+file.name+'…');const result=await encryptFile(file),fd=new FormData();fd.append('blob',result.blob,file.name+'.es');fd.append('metadata',JSON.stringify(result.metadata));const res=await fetch('/api/files',{method:'POST',body:fd});if(!res.ok)throw Error(await res.text())}await load();setStatus('Upload complete.')}catch(e){setStatus('Upload failed: '+e.message);alert(e.message)}}}
async function load(){const res=await fetch('/api/files');if(!res.ok)throw Error('Could not load files');state.files=await res.json();render()}
async function render(){const q=$('search').value.trim().toLowerCase(),body=$('files');body.innerHTML='';let shown=0;for(const f of state.files){let name='Encrypted file';if(state.key){try{name=(await decryptMetadata(f)).name}catch(e){name='Locked file'}}if(q&&!name.toLowerCase().includes(q))continue;shown++;const tr=document.createElement('tr');tr.innerHTML='<td class="name"></td><td>'+format(f.size)+'</td><td>'+new Date(f.created*1000).toLocaleString()+'</td><td><button data-id="'+f.id+'">Download</button></td>';tr.querySelector('.name').textContent=name;tr.querySelector('button').onclick=()=>download(f);body.appendChild(tr)}$('empty').classList.toggle('hidden',shown>0)}
async function download(record){if(!state.key){$('vaultModal').classList.add('open');return}try{setStatus('Decrypting…');const d=await decryptFile(record),blob=new Blob([d.data],{type:d.meta.type||'application/octet-stream'}),a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=d.meta.name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);setStatus('Downloaded '+d.meta.name)}catch(e){alert('Download failed: '+e.message)}}
async function del(){const tr=document.querySelector('#files tr.selected');if(!tr){alert('Select a file first.');return}const id=tr.querySelector('button').dataset.id;if(!confirm('Delete this encrypted object permanently?'))return;const r=await fetch('/api/files/'+id,{method:'DELETE'});if(!r.ok)alert('Delete failed');await load()}
$('files').onclick=e=>{const tr=e.target.closest('tr');if(!tr||e.target.tagName==='BUTTON')return;document.querySelectorAll('#files tr').forEach(x=>x.classList.remove('selected'));tr.classList.add('selected')};
function format(n){let u=['B','KB','MB','GB','TB'],i=0,x=n;while(x>=1024&&i<4){x/=1024;i++}return x.toFixed(i?1:0)+' '+u[i]}function setStatus(x){$('status').textContent=x}
$('uploadBtn').onclick=upload;$('refreshBtn').onclick=load;$('downloadBtn').onclick=()=>{const tr=document.querySelector('#files tr.selected');if(tr)tr.querySelector('button').click();else alert('Select a file first.')};$('deleteBtn').onclick=del;$('vaultBtn').onclick=()=>{$('vaultModal').classList.add('open')};$('searchBtn').onclick=render;$('search').oninput=render;
load().catch(e=>setStatus('Could not load files: '+e.message));
</script></body></html>'''

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=True)
