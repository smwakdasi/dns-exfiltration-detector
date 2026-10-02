"""Step 7: zero-dependency dashboard.  python3 dashboard.py  ->  http://localhost:8080"""
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from storage import Storage

st = Storage()
PAGE = """<!doctype html><meta charset=utf-8><title>DNS-Guard</title>
<style>body{font-family:sans-serif;margin:2rem}table{border-collapse:collapse;width:100%;margin-bottom:2rem}
td,th{border:1px solid #ccc;padding:4px 8px;font-size:13px}th{background:#eee}h2{margin-bottom:4px}</style>
<h1>DNS-Guard Dashboard</h1><div id=stats></div><h2>Recent alerts</h2><table id=al></table>
<h2>Blocks</h2><table id=bl></table><h2>Latest queries</h2><table id=q></table>
<script>
const t=(id,rows)=>{if(!rows.length){document.getElementById(id).innerHTML='<tr><td>none</td></tr>';return}
const k=Object.keys(rows[0]);document.getElementById(id).innerHTML='<tr>'+k.map(x=>'<th>'+x+'</th>').join('')+'</tr>'+
rows.map(r=>'<tr>'+k.map(x=>'<td>'+String(r[x]).replace(/</g,'&lt;')+'</td>').join('')+'</tr>').join('')};
async function go(){const d=await (await fetch('/api')).json();
document.getElementById('stats').innerText=`Queries: ${d.total} | Suspicious: ${d.susp} | Alerts: ${d.alerts}`;
t('al',d.alerts_rows);t('bl',d.blocks);t('q',d.queries)}go();setInterval(go,3000)
</script>"""


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api":
            one = lambda s: st.rows(s)[0]["n"]
            body = json.dumps({
                "total": one("SELECT COUNT(*) n FROM queries"),
                "susp": one("SELECT COUNT(*) n FROM queries WHERE suspicious=1"),
                "alerts": one("SELECT COUNT(*) n FROM alerts"),
                "alerts_rows": st.rows("SELECT datetime(ts,'unixepoch') time,src_ip,domain,score,action,reasons FROM alerts ORDER BY id DESC LIMIT 15"),
                "blocks": st.rows("SELECT datetime(ts,'unixepoch') time,kind,target,dry_run,active FROM blocks ORDER BY id DESC LIMIT 15"),
                "queries": st.rows("SELECT datetime(ts,'unixepoch') time,src_ip,fqdn,qtype,entropy,score FROM queries ORDER BY id DESC LIMIT 20"),
            }).encode()
            ctype = "application/json"
        else:
            body, ctype = PAGE.encode(), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", 8080), H).serve_forever()
