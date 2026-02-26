from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import gzip
import zlib

class MyRequestHandler(BaseHTTPRequestHandler):
    def _handle_request(self, method):
        """处理请求的通用方法"""
        # 打印请求信息
        print(f"Request Method: {method}")
        print(f"Request Path: {self.path}")
        print(f"Request Headers:\n{self.headers}")
        
        all_headers = dict(self.headers)
        found_testmykv = False
        
        for header_key, header_value in all_headers.items():
            # 检查key或value中是否包含testmykv（不区分大小写）
            if 'testmykv' in header_key.lower() or 'testmykv' in header_value.lower():
               found_testmykv=True
        
       
        # 准备响应内容
        response_content = b"Hello from Python server!"
        
        if not found_testmykv:
            self.send_response(203)
        else:
            self.send_response(200)

        self.send_header("Content-type", "text/plain; charset=utf-8")
        
        self.send_header("Content-Length", str(len(response_content)))
        self.end_headers()
        
        # 发送响应体
        self.wfile.write(response_content)

    def do_GET(self):
        self._handle_request("GET")


def run(server_class=HTTPServer, handler_class=MyRequestHandler, port=80):
    server_address = ("", port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting Python server on port {port}...")
    print("服务器功能:")
    print("- 支持GET")
    print("- 检查包含'testmykv'的测试头部")
    print("- 显示所有接收到的头部信息")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
