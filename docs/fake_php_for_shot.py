"""截图用的本地假 PHP 服务：返回 PHP/8.4.26 banner，让 --demo 能扫出真实结果。

只用于生成 README 截图，跑完即杀。
"""
import http.server
import socketserver
import sys


class H(http.server.BaseHTTPRequestHandler):
    # 让 Server 头看起来就是 Apache（基类会用 server_version + sys_version 拼）
    server_version = "Apache/2.4.69 (Debian)"
    sys_version = ""

    def do_GET(self):
        body = b"ok\n"
        self.send_response(200)
        self.send_header("X-Powered-By", "PHP/8.4.26")
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


socketserver.TCPServer.allow_reuse_address = True
port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
with socketserver.TCPServer(("127.0.0.1", port), H) as srv:
    print(f"fake php on 127.0.0.1:{port}", flush=True)
    srv.serve_forever()
