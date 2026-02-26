# -*- coding: utf-8 -*-
import socket
import ssl
import struct
from collections import OrderedDict
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
def create_keepalive_connection(test_ip, port, use_ssl=False, server_hostname=None, timeout=10):
    """创建支持长连接的socket，SSL握手在此完成"""
    sock = None
    try:
        # 创建socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # 连接服务器
        sock.connect((test_ip, port))
        
        # 如果需要SSL，在这里完成握手
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=server_hostname or test_ip)
        
        logger.info("长连接已建立，SSL握手完成: {}".format("https" if use_ssl else "http"))
        return True, sock
        
    except Exception as e:
        logger.info("建立长连接失败: {}".format(str(e)))
        if sock:
            try:
                sock.close()
            except:
                pass
        return False, None


def close_keepalive_connection(sock):
    """优雅关闭长连接"""
    if sock:
        try:
            sock.close()
            logger.info("长连接已关闭")
        except Exception as e:
            logger.info("关闭连接异常: {}".format(str(e)))


def send_raw_http_request(test_ip, port, method, path, headers, use_ssl=False, timeout=10, body=None,raw_request=""):
    """使用原始socket发送HTTP请求（短连接实现）
    
    Args:
        headers: 可以是dict或list。如果是list，格式为[(key, value), (key, value), ...]，支持重复的key
    """
    sock = None
    try:
        # 创建socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 0, 0))  # 禁用SO_LINGER
        sock.settimeout(timeout)
        
        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=test_ip)
        
        # 连接服务器
        sock.connect((test_ip, port))
        
        if raw_request=="":
            # 处理请求体
            if body is not None:
                body_bytes = body.encode('utf-8') if isinstance(body, str) else body
                # 如果headers是list，添加Content-Length
                if isinstance(headers, list):
                    headers = list(headers)
                    headers.append(('Content-Length', str(len(body_bytes))))
                else:
                    headers = headers.copy()
                    headers['Content-Length'] = str(len(body_bytes))
            elif method in ['PUT', 'POST']:
                # 检查是否已有Content-Length
                has_content_length = False
                if isinstance(headers, list):
                    has_content_length = any(k.lower() == 'content-length' for k, v in headers)
                else:
                    has_content_length = 'Content-Length' in headers
                
                if not has_content_length:
                    # PUT/POST请求默认添加body
                    if method == "POST" or method == "PUT":
                        body = "aaaa" * 10
                        body_bytes = body.encode('utf-8')
                    if isinstance(headers, list):
                        headers = list(headers)
                        headers.append(('Content-Length', str(len(body_bytes))))
                    else:
                        headers = headers.copy()
                        headers['Content-Length'] = str(len(body_bytes))
                else:
                    body_bytes = None
            else:
                body_bytes = None
            
            # 构造HTTP请求
            request_lines = ["{} {} HTTP/1.1".format(method, path)]
            
            # 强制短连接：添加Connection: close头
            if isinstance(headers, list):
                headers = list(headers)
                headers.append(('Connection', 'close'))
                # 遍历list格式的headers
                for key, value in headers:
                    request_lines.append("{}: {}".format(key, value))
            else:
                headers = headers.copy()
                headers['Connection'] = 'close'
                # 遍历dict格式的headers
                for key, value in headers.items():
                    request_lines.append("{}: {}".format(key, value))
            
            request_lines.append("")  # 空行表示headers结束
            request_header = "\r\n".join(request_lines).encode('utf-8') + b"\r\n"
            
            # 构造完整请求
            if body_bytes is not None:
                request = request_header + body_bytes
            else:
                request = request_header
        
        else:
            request=raw_request
        logger.info("发送{}短连接请求:\n{}".format("https" if use_ssl else "http", repr(request)))
        
        # 发送请求
        sock.send(request)
        
        # 接收响应 - 对于 HEAD 请求只读取 header 部分
        response = b""
        if method.upper() == 'HEAD':
            # HEAD 请求只读取 header 部分，直到遇到 \r\n\r\n
            header_buf = b""
            while True:
                try:
                    chunk = sock.recv(1)
                    if not chunk:
                        break
                    header_buf += chunk
                    if header_buf.endswith(b'\r\n\r\n'):
                        break
                except socket.timeout:
                    break
            response = header_buf
        else:
            # 其他方法读取完整响应
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
        
        # 客户端主动关闭连接（标准四次挥手）
        try:
            # 1. 客户端发送FIN
            sock.shutdown(socket.SHUT_WR)
            # 2. 等待服务器ACK（此时服务器可能还有数据）
            # 3. 等待服务器FIN
            # 4. 客户端发送ACK
            sock.settimeout(2)  # 给服务器响应时间
            try:
                # 继续读取直到服务器关闭
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
            except socket.timeout:
                logger.info("服务器响应超时，强制关闭连接")
                
        except Exception as e:
            logger.info("关闭连接时异常: {}".format(str(e)))
        
        # 解析响应
        response_str = response.decode('utf-8', errors='ignore')
        
        # 分离响应头和响应体
        if '\r\n\r\n' in response_str:
            header_part, body_part = response_str.split('\r\n\r\n', 1)
        else:
            header_part = response_str
            body_part = ""
        
        lines = header_part.split('\r\n')
        
        # 获取状态码
        status_line = lines[0] if lines else ""
        status_code = 0
        if status_line.startswith("HTTP/"):
            parts = status_line.split()
            if len(parts) >= 2:
                try:
                    status_code = int(parts[1])
                except ValueError:
                    status_code = 0
            else:
                logger.info("无法解析状态行格式: {}".format(repr(status_line)))
                status_code = 0
        else:
            logger.info("响应不以HTTP开头: {}".format(repr(status_line[:100])))
            status_code = 0
        
        # 获取 Content-Length
        content_length = 0
        for line in lines:
            if line.lower().startswith('content-length:'):
                try:
                    content_length = int(line.split(':', 1)[1].strip())
                    break
                except (ValueError, IndexError):
                    pass
        
        logger.info("短连接收到响应状态码: {}".format(status_code))
        logger.info("响应头部:\n{}".format(header_part))
        logger.info("Content-Length: {}, 实际响应体长度: {}".format(content_length, len(body_part)))
        # if body_part:
        #     logger.info("响应体内容:\n{}".format(repr(body_part)))
        # else:
        #     logger.info("响应体为空")
        
        return True, {"status": status_code, "response": response_str, "headers": header_part, "body": body_part}
        
    except Exception as e:
        logger.info("短连接请求失败: {}".format(str(e)))
        return False, {"status": 0, "error": str(e)}
    finally:
        if sock:
            try:
                sock.close()  # 确保连接完全关闭
            except:
                pass


def send_raw_http_request_long(sock, method, path, headers, body=None, terminator=b"\r\n\r\n"):
    """
    在已有 keep-alive 的 sock 上发一次 HTTP/1.1 请求并读完本次响应，
    不关闭连接，不处理 SSL 握手，方便调用者复用。
    返回 (success, {"status": int, "response": str, "body_start": int})
    
    Args:
        headers: 可以是dict或list。如果是list，格式为[(key, value), (key, value), ...]，支持重复的key
    """
    try: 
        # 注意：SSL握手应该在外部完成，这里不再处理
        # sock应该是已经SSL化的socket（如果是HTTPS）
        # ---- 1. 构造请求 ----
        if body is not None:
            body_bytes = body.encode('utf-8') if isinstance(body, str) else body
            if isinstance(headers, list):
                headers = list(headers)
                headers.append(('Content-Length', str(len(body_bytes))))
            else:
                headers = headers.copy()
                headers['Content-Length'] = str(len(body_bytes))
        else:
            body_bytes = None
        # 构建请求行
        lines = ["{} {} HTTP/1.1".format(method, path)]
        
        # 处理headers
        if isinstance(headers, list):
            # list格式：直接遍历，支持重复key
            # 先找Host头
            host_value = None
            for k, v in headers:
                if k.lower() == 'host':
                    host_value = v
                    break
            if host_value:
                lines.append("Host: {}".format(host_value))
            # 添加其他头（跳过Host头，因为已经添加过了）
            for k, v in headers:
                if k.lower() != 'host':
                    lines.append("{}: {}".format(k, v))
        else:
            # dict格式：原有逻辑
            # 确保Host头放在第一位
            host_value = headers.get('Host', '')
            if host_value:
                lines.append("Host: {}".format(host_value))
            
            # 添加其他头（跳过Host头，因为已经添加过了）
            for k, v in headers.items():
                if k.lower() != 'host':  # 跳过Host头，避免重复
                    lines.append("{}: {}".format(k, v))
        
        header_bytes = "\r\n".join(lines).encode('utf-8') + terminator
        if body_bytes:
            request = header_bytes + body_bytes
        else:
            request = header_bytes

        logger.info("发送 keep-alive 请求:\n{}".format(repr(request[:200])))

        # ---- 2. 发送 ----
        sock.sendall(request)

        # ---- 3. 按 HTTP/1.1 规范读取响应 ----
        # 先读头部
        header_buf = b''
        timeout_count = 0
        max_timeout_retries = 3
        
        while True:
            try:
                chunk = sock.recv(1)
                if not chunk:
                    # 连接被服务器关闭
                    if len(header_buf) == 0:
                        # 如果一点数据都没收到，说明服务器立即关闭了连接
                        raise Exception("服务器立即关闭了连接，可能是请求格式错误")
                    else:
                        # 收到了部分数据后连接关闭
                        break
                header_buf += chunk
                if header_buf.endswith(b'\r\n\r\n'):
                    break
                timeout_count = 0  # 重置超时计数
            except socket.timeout:
                timeout_count += 1
                if timeout_count >= max_timeout_retries:
                    raise Exception("读取响应头部超时")
                # 短暂等待后重试
                continue
            except socket.error as e:
                # 连接被重置或其他socket错误
                if e.errno == 104:  # ECONNRESET
                    raise Exception("连接被服务器重置，可能是请求格式错误")
                else:
                    raise Exception("Socket错误: {}".format(str(e)))

        # 如果头部为空，说明服务器没有响应
        if len(header_buf) == 0:
            raise Exception("没有收到服务器响应")

        header_str = header_buf.decode('utf-8', errors='ignore')
        lines = header_str.split('\r\n')
        
        # 检查是否能解析状态行
        if len(lines) == 0 or not lines[0].startswith('HTTP/'):
            raise Exception("无效的HTTP响应: {}".format(header_str[:100]))
            
        status_line = lines[0]
        try:
            status_code = int(status_line.split()[1])
        except (IndexError, ValueError):
            raise Exception("无法解析状态码: {}".format(status_line))

        # 解析 Content-Length
        content_length = 0
        for line in lines:
            if line.lower().startswith('content-length:'):
                try:
                    content_length = int(line.split(':', 1)[1].strip())
                    break
                except (ValueError, IndexError):
                    content_length = 0
                    break

        # 读 body（如果有）
        body_bytes_left = content_length
        body_buf = b''
        # HEAD 请求不返回 body，直接跳过
        if method.upper() == 'HEAD':
            body_bytes_left = 0
            
        while body_bytes_left > 0:
            try:
                chunk = sock.recv(body_bytes_left)
                if not chunk:
                    break
                body_buf += chunk
                body_bytes_left -= len(chunk)
            except socket.timeout:
                # body读取超时，但这不是致命错误
                logger.info("读取响应body超时，已读取 {} 字节".format(len(body_buf)))
                break

        full_response = header_str.encode('utf-8') + body_buf
        logger.info("收到响应，状态码: {}".format(status_code))
        return True, {"status": status_code,
                      "response": full_response.decode('utf-8', errors='ignore')}
    except Exception as e:
        logger.info("keep-alive 请求失败: {}".format(str(e)))
        # 透传异常，调用者决定是否关闭socket
        return False, {"status": 0, "error": str(e)}

def get_connection_key(response_text):
    connection_header = None
    for line in response_text.splitlines():
        if line.lower().startswith("connection:"):
            connection_header = line.split(":", 1)[1].strip().lower()
            break
    return connection_header

def test_special_chars_with_raw_socket_single(headers ,expect_stauts,expect_body,test_path,test_ip):
    """使用原始socket测试特殊字符"""
    logger.info("===============使用原始socket测试特殊字符===============")
    # 测试特殊字符

    success, response = send_raw_http_request(
        test_ip, 80, "GET", test_path, headers, use_ssl=False
    )
    if not success:
            raise Exception,"请求失败"
    if response.get("status", 0) != expect_stauts:
            raise Exception,"status_code expect:{}  real:{}".format(expect_stauts,response.get("status", 0))
    if expect_body!="" and expect_body not in response.get("body", ""):
            raise Exception,"body expect contain:{}  real(first 100 char):{}".format(expect_body,response.get("body", "")[:100])
