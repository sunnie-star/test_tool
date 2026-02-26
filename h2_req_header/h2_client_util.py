# -*- coding: utf-8 -*-
"""
通用HTTP客户端模块
支持HTTP/1.1、HTTP/2、HTTPS、长连接和短连接
供其他测试脚本调用
"""
import sys
import socket
import ssl
import threading
import time
# from autotest_src.CaseConf import *
# from autotest_lib.keywords.keyword_impl import *
import logging

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
Log = logging.getLogger(__name__)


import h2.connection
import h2.config
import h2.events
import h2.utilities
from h2.connection import ConnectionState


H2_AVAILABLE = True

    
# try:
#     import h2.connection
#     import h2.config
#     import h2.events
#     import h2.utilities
#     try:
#         from h2.connection import ConnectionState
#     except ImportError:
#         ConnectionState = None
#     H2_AVAILABLE = True
# except ImportError:
#     H2_AVAILABLE = False
#     ConnectionState = None

# 全局客户端实例管理器，用于长连接复用
_global_clients = {}
_client_lock = threading.Lock()

class HTTPClient(object):
    """通用HTTP客户端类，支持HTTP/1.1和HTTP/2，支持长连接和短连接"""
    
    def __init__(self, host, port=80, use_ssl=False, http2=False, keep_alive=False, timeout=10, ip=None):
        """
        初始化HTTP客户端
        
        Args:
            host: 目标主机地址（用于Host头部）
            port: 端口，默认80
            use_ssl: 是否使用SSL/TLS
            http2: 是否使用HTTP/2协议
            keep_alive: 是否使用长连接
            timeout: 超时时间（秒）
            ip: 可选，指定连接的IP地址（如果为None则使用host）
        """
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.http2 = http2 and H2_AVAILABLE
        self.keep_alive = keep_alive
        self.timeout = timeout
        self.ip = ip  # 新增：指定连接的IP地址
        self._socket = None
        self._h2_connection = None
        self._is_connected = False
        
    def _get_client_key(self):
        """获取客户端的唯一标识"""
        actual_ip = self.ip if self.ip else self.host
        return "{}:{}:{}:{}:{}".format(actual_ip, self.host, self.port, self.use_ssl, self.http2)
    
    def _is_socket_alive(self, sock):
        """检查socket连接是否仍然有效"""
        if not sock:
            return False
        try:
            # 简单的连接检查
            sock.settimeout(0.1)
            if isinstance(sock, ssl.SSLSocket):
                # SSL socket检查
                try:
                    sock.getpeercert()
                    return True
                except:
                    return False
            else:
                # 普通socket检查
                try:
                    sock.recv(1, socket.MSG_PEEK)
                    return True
                except socket.timeout:
                    return True  # 超时表示连接正常
                except:
                    return False
        except:
            return False
        finally:
            try:
                sock.settimeout(self.timeout)
            except:
                pass
    
    def _create_socket(self):
        """创建socket连接"""
        # 使用指定的IP地址连接，如果没有指定则使用host
        connect_host = self.ip if self.ip else self.host
        
        Log.info("创建连接: {}:{} (实际连接IP: {})".format(self.host, self.port, connect_host))
        
        sock = socket.create_connection((connect_host, self.port), timeout=self.timeout)
        
        if self.use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            if self.http2:
                # HTTP/2需要ALPN
                try:
                    context.set_alpn_protocols(['h2', 'http/1.1'])
                    Log.info("设置ALPN协议: h2, http/1.1")
                except AttributeError:
                    try:
                        context.set_npn_protocols(['h2', 'http/1.1'])
                        Log.info("设置NPN协议: h2, http/1.1")
                    except AttributeError:
                        raise Exception("当前Python版本不支持ALPN/NPN协议协商")
            
            sock = context.wrap_socket(sock, server_hostname=self.host)
            
            if self.http2:
                # 检查协议协商结果
                negotiated = getattr(sock, 'selected_alpn_protocol', lambda: None)() or \
                           getattr(sock, 'selected_npn_protocol', lambda: None)()
                Log.info("协议协商结果: {}".format(negotiated))
                if negotiated != 'h2':
                    raise Exception("HTTP/2协议协商失败，实际协议: {}".format(negotiated))
        
        return sock
    
    def _ensure_connection(self):
            """确保连接可用（简化HTTP/2状态检查）"""
            # 1. socket 层存活检查
            if self._is_connected and self._socket and self._is_socket_alive(self._socket):
                # 2. HTTP/2 简单检查 - 只要连接存在就复用
                if self.http2 and self._h2_connection:
                    Log.info("复用现有HTTP/2连接")
                    return
                else:
                    Log.info("复用现有连接")
                    return

            # 3. 需要新建连接
            if self._socket:
                try:
                    self._socket.close()
                except:
                    pass
                self._socket = None
                self._h2_connection = None
                self._is_connected = False

            self._socket = self._create_socket()
            self._is_connected = True

            if self.http2:
                self._init_http2_connection()
    
    def _init_http2_connection(self):
        """初始化HTTP/2连接"""
        if not H2_AVAILABLE:
            raise Exception("HTTP/2库未安装")
        
        Log.info("初始化HTTP/2连接")
        config = h2.config.H2Configuration(client_side=True)
        
        # 禁用头部验证和规范化，绕过_build_headers_frames中的校验
        config.validate_outbound_headers = False
        config.normalize_outbound_headers = False
        Log.info("已禁用HTTP/2头部验证和规范化")
        
        self._h2_connection = h2.connection.H2Connection(config=config)
        self._h2_connection.initiate_connection()
        
        # 发送初始化数据
        init_data = self._h2_connection.data_to_send()
        if init_data:
            self._socket.sendall(init_data)
            Log.info("发送HTTP/2初始化数据: {} bytes".format(len(init_data)))
        
        Log.info("HTTP/2连接初始化完成")
    
    def _build_http1_request(self, method, path, headers=None, body=None):
        """构建HTTP/1.1请求"""
        if headers is None:
            headers = {}
        
        # 设置默认头部
        default_headers = {
            'Host': self.host,
            'User-Agent': 'HTTPClient/1.0',
            'Connection': 'keep-alive' if self.keep_alive else 'close'
        }
        
        # 合并头部
        for key, value in default_headers.items():
            if key not in headers:
                headers[key] = value
        
        # 构建请求行
        request_line = "{} {} HTTP/1.1".format(method, path)
        
        # 构建头部
        header_lines = ""
        for key, value in headers.items():
            header_lines += "{}: {}\r\n".format(key, value)
        
        # 处理请求体
        if body:
            if isinstance(body, str):
                body = body.encode('utf-8')
            elif not isinstance(body, bytes):
                body = str(body).encode('utf-8')
            
            header_lines += "Content-Length: {}\r\n".format(len(body))
        
        # 构建完整请求
        request = request_line + "\r\n" + header_lines + "\r\n"
        
        if body:
            request = request.encode('utf-8') + body
        else:
            request = request.encode('utf-8')
        
        # 打印完整请求
        Log.info("发送HTTP/1.1请求:\n{}".format(
            request.decode('utf-8', errors='ignore').replace('\r\n', '\\r\\n')
        ))
        
        return request
    
    def _parse_http1_response(self, data):
        """解析HTTP/1.1响应"""
        try:
            if not data:
                Log.warning("未收到响应数据")
                return None, None, None
                
            # 分离头部和主体
            header_end = data.find(b'\r\n\r\n')
            if header_end == -1:
                Log.warning("响应头部不完整")
                return None, None, None
            
            header_part = data[:header_end]
            body_part = data[header_end + 4:]
            
            # 打印原始响应数据
            Log.info("收到原始响应数据:\n{}".format(
                data.decode('utf-8', errors='ignore').replace('\r\n', '\\r\\n')
            ))
            
            # 解析状态行
            try:
                lines = header_part.decode('utf-8', errors='ignore').split('\r\n')
                if not lines or not lines[0]:
                    Log.warning("状态行解析失败")
                    return None, None, None
                
                status_line = lines[0]
                parts = status_line.split(' ', 2)
                
                if len(parts) < 2:
                    Log.warning("状态行格式错误: {}".format(status_line))
                    return None, None, None
                
                status_code = int(parts[1])
                Log.info("响应状态码: {}".format(status_code))
            except (ValueError, IndexError) as e:
                Log.error("解析状态码失败: {}".format(e))
                return None, None, None
            
            # 解析头部
            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            Log.info("响应头部: {}".format(headers))
            
            return status_code, headers, body_part
            
        except Exception as e:
            Log.error("解析HTTP响应失败: {}".format(e))
            return None, None, None
    
    def _decode_chunked(self, data):
        """解码chunked传输编码"""
        result = b''
        offset = 0
        
        Log.info("开始解码chunked数据")
        
        while offset < len(data):
            # 查找chunk大小行
            line_end = data.find(b'\r\n', offset)
            if line_end == -1:
                Log.warning("chunk大小行不完整")
                break
            
            size_line = data[offset:line_end]
            try:
                chunk_size = int(size_line.decode('utf-8').strip(), 16)
                Log.info("chunk大小: {} (0x{:x})".format(chunk_size, chunk_size))
            except (ValueError, IndexError):
                Log.error("无法解析chunk大小: {}".format(size_line))
                break
            
            if chunk_size == 0:
                Log.info("收到最后一个chunk")
                break
            
            # 计算chunk数据的起始和结束位置
            chunk_start = line_end + 2
            chunk_end = chunk_start + chunk_size
            
            # 检查边界
            if chunk_end + 2 > len(data):
                Log.warning("chunk数据不完整")
                break
            
            # 提取chunk数据
            chunk_data = data[chunk_start:chunk_end]
            Log.info("chunk数据长度: {}".format(len(chunk_data)))
            result += chunk_data
            offset = chunk_end + 2  # 跳过chunk数据和\r\n
        
        Log.info("chunked解码完成，总长度: {}".format(len(result)))
        return result
    
    def send_http1_request(self, method, path, headers=None, body=None):
        """发送HTTP/1.1请求
        
        Returns:
            tuple: (success, response_dict) - 统一返回格式
        """
        try:
            Log.info("开始发送HTTP/1.1 {}请求: {} {}".format(method, self.host, path))
            
            # 确保连接可用
            self._ensure_connection()
            
            # 构建请求
            request_data = self._build_http1_request(method, path, headers, body)
            
            # 发送请求
            Log.info("发送请求数据长度: {} bytes".format(len(request_data)))
            self._socket.sendall(request_data)
            
            # 接收响应
            response_data = b''
            self._socket.settimeout(5.0)  # 设置超时
            
            Log.info("开始接收响应...")
            
            # 首先读取头部
            while True:
                try:
                    chunk = self._socket.recv(4096)
                    if not chunk:
                        Log.warning("连接关闭，未收到完整响应")
                        break
                    response_data += chunk
                    
                    # 查找头部结束标记
                    header_end = response_data.find(b'\r\n\r\n')
                    if header_end != -1:
                        Log.info("收到响应头部，长度: {} bytes".format(header_end + 4))
                        break
                        
                except socket.timeout:
                    Log.error("接收响应超时")
                    break
            
            if not response_data:
                raise Exception("未收到任何响应数据")
            
            Log.info("总响应数据长度: {} bytes".format(len(response_data)))
            
            # 解析响应头部
            status_code, resp_headers, body_part = self._parse_http1_response(response_data)
            
            if status_code is None:
                raise Exception("无法解析HTTP响应")
            
            # 根据Content-Length读取剩余数据
            content_length = resp_headers.get('Content-Length')
            if content_length:
                try:
                    expected_length = int(content_length)
                    current_body_length = len(body_part)
                    
                    Log.info("期望内容长度: {}, 当前已接收: {}".format(expected_length, current_body_length))
                    
                    # 计算还需要读取的字节数
                    remaining = expected_length - current_body_length
                    if remaining > 0:
                        Log.info("需要继续读取 {} bytes".format(remaining))
                        while remaining > 0:
                            chunk = self._socket.recv(min(remaining, 4096))
                            if not chunk:
                                Log.warning("连接关闭，未收到完整内容")
                                break
                            body_part += chunk
                            remaining -= len(chunk)
                            
                        Log.info("内容读取完成，总长度: {} bytes".format(len(body_part)))
                            
                except (ValueError, socket.timeout) as e:
                    Log.error("处理Content-Length失败: {}".format(e))
            
            # 如果是chunked编码，继续读取直到结束
            elif resp_headers.get('Transfer-Encoding', '').lower() == 'chunked':
                Log.info("检测到chunked传输编码")
                while True:
                    try:
                        chunk = self._socket.recv(4096)
                        if not chunk:
                            Log.warning("连接关闭，未收到完整chunked数据")
                            break
                        body_part += chunk
                        
                        # 检查chunked结束标记
                        if body_part.endswith(b'0\r\n\r\n'):
                            Log.info("收到chunked结束标记")
                            break
                    except socket.timeout:
                        Log.warning("接收chunked数据超时")
                        break
            
            # 最终解码chunked数据
            if resp_headers.get('Transfer-Encoding', '').lower() == 'chunked':
                Log.info("开始解码chunked响应")
                body_part = self._decode_chunked(body_part)
            
            response_body = body_part.decode('utf-8', errors='ignore') if body_part else ""
            Log.info("响应体长度: {} bytes".format(len(response_body)))
            
            return True, {
                "status": status_code,
                "headers": resp_headers,
                "body": response_body
            }
            
        except socket.timeout as e:
            Log.error("请求超时: {}".format(e))
            return False, {"status": 0, "error": "请求超时"}
        except Exception as e:
            Log.error("请求失败: {}".format(e))
            return False, {"status": 0, "error": str(e)}
        
        finally:
            if not self.keep_alive:
                self.close()
    
    def send_http2_request(self, method, path, headers=None, body=None):
        """发送HTTP/2请求"""
        if not H2_AVAILABLE:
            Log.error("HTTP/2库未安装")
            return False, {"status": 0, "error": "HTTP/2库未安装"}

        try:
            Log.info("开始发送HTTP/2 {}请求: {} {}".format(method, self.host, path))
            self._ensure_connection()

            # 构建HTTP/2头部
            http2_headers = [
                (':method', method),
                (':path', path),
                (':scheme', 'https' if self.use_ssl else 'http'),
                (':authority', self.host),
            ]

            if headers:
                for k, v in headers.items():
                    http2_headers.append((k, str(v)))
                    Log.info("header key: {} value: {}".format(k,v))

            # 获取stream ID
            stream_id = self._h2_connection.get_next_available_stream_id()
            Log.info("使用 stream_id: {}".format(stream_id))

            # 发送请求
            if body is not None:
                if isinstance(body, str):
                    body_bytes = body.encode('utf-8')
                else:
                    body_bytes = str(body).encode('utf-8')
                self._h2_connection.send_headers(stream_id, http2_headers, end_stream=False)
                hdr_data = self._h2_connection.data_to_send()
                if hdr_data:
                    self._socket.sendall(hdr_data)
                self._h2_connection.send_data(stream_id, body_bytes, end_stream=True)
                data_frame = self._h2_connection.data_to_send()
                if data_frame:
                    self._socket.sendall(data_frame)
            else:
                self._h2_connection.send_headers(stream_id, http2_headers, end_stream=True)
                hdr_data = self._h2_connection.data_to_send()
                if hdr_data:
                    self._socket.sendall(hdr_data)

            # 接收响应
            response_data = ''
            response_headers = {}
            status_code = 0
            stream_ended = False
            
            Log.info("开始接收HTTP/2响应...")
            self._socket.settimeout(self.timeout)
            
            start_time = time.time()
            while not stream_ended and (time.time() - start_time) < self.timeout:
                try:
                    data = self._socket.recv(65535)
                    if not data:
                        Log.warning("未收到完整HTTP/2响应")
                        break
                        
                    Log.info("收到HTTP/2数据: {} bytes".format(len(data)))
                    
                    events = self._h2_connection.receive_data(data)
                    if not events:
                        continue
                        
                    for event in events:
                        if isinstance(event, h2.events.ResponseReceived):
                            Log.info("收到HTTP/2响应头部")
                            for header, value in event.headers:
                                # h2库可能返回bytes类型的header，需要解码为str
                                header_str = header.decode('utf-8') if isinstance(header, bytes) else header
                                value_str = value.decode('utf-8') if isinstance(value, bytes) else value
                                if header_str == ':status':
                                    status_code = int(value_str)
                                    Log.info("HTTP/2响应状态码: {}".format(status_code))
                                response_headers[header_str] = value_str
                                Log.info("HTTP/2响应头部: {}: {}".format(header_str, value_str))
                                
                        elif isinstance(event, h2.events.DataReceived):
                            chunk_data = event.data.decode('utf-8', errors='ignore')
                            response_data += chunk_data
                            Log.info("收到HTTP/2数据帧，长度: {} bytes".format(len(event.data)))
                            self._h2_connection.acknowledge_received_data(len(event.data), event.stream_id)
                            
                        elif isinstance(event, h2.events.StreamEnded):
                            Log.info("HTTP/2流结束")
                            stream_ended = True
                            break
                            
                        elif isinstance(event, h2.events.StreamReset):
                            error_code = getattr(event, 'error_code', None)
                            remote_reset = getattr(event, 'remote_reset', None)
                            Log.warning("HTTP/2流被重置(RST_STREAM), error_code={} (0x{:02X}), remote_reset={}".format(
                                error_code, error_code if error_code is not None else 0, remote_reset))
                            stream_ended = True
                            break
                            
                        elif isinstance(event, h2.events.ConnectionTerminated):
                            error_code = getattr(event, 'error_code', None)
                            last_stream_id = getattr(event, 'last_stream_id', None)
                            additional_data = getattr(event, 'additional_data', None)
                            Log.warning("HTTP/2连接终止(GOAWAY), error_code={} (0x{:02X}), last_stream_id={}, additional_data={}".format(
                                error_code, error_code if error_code is not None else 0, last_stream_id, additional_data))
                            stream_ended = True
                            break
                    
                    # 发送控制数据
                    pending_data = self._h2_connection.data_to_send()
                    if pending_data:
                        self._socket.sendall(pending_data)
                        Log.info("发送HTTP/2控制数据: {} bytes".format(len(pending_data)))
                        
                except socket.timeout:
                    Log.warning("HTTP/2接收数据超时")
                    break
            
            Log.info("HTTP/2响应完成，总数据长度: {} bytes".format(len(response_data)))
            if response_data:
                Log.info("HTTP/2响应体内容: {}".format(response_data))
            
            if status_code == 0:
                Log.warning("HTTP/2响应状态码为0，视为请求失败")
                return False, {
                    "status": 0,
                    "error": "未收到有效HTTP/2响应",
                    "headers": response_headers,
                    "data": response_data
                }
            
            Log.info("HTTP/2请求成功完成，状态码: {}".format(status_code))
            return True, {
                "status": status_code,
                "headers": response_headers,
                "data": response_data
            }
            
        except Exception as e:
            Log.error("HTTP/2请求失败: {}".format(e))
            return False, {"status": 0, "error": str(e)}
        
        finally:
            if not self.keep_alive:
                self.close()
    
    def request(self, method, path, headers=None, body=None):
        """
        发送HTTP请求（自动选择HTTP/1.1或HTTP/2）
        
        Args:
            method: HTTP方法
            path: 请求路径
            headers: 请求头部字典
            body: 请求
            
        Returns:
            (success, response_dict)
            success: 是否成功
            response_dict: 响应信息，包含status、headers、data等
        """
        Log.info("=" * 60)
        Log.info("开始HTTP请求: {} {}://{}:{}{}".format(
            method, 
            'https' if self.use_ssl else 'http',
            self.host,
            self.port,
            path
        ))
        Log.info("协议: {}, 连接类型: {}".format(
            "HTTP/2" if self.http2 else "HTTP/1.1",
            "长连接" if self.keep_alive else "短连接"
        ))
        
        if self.ip:
            Log.info("指定连接IP: {}".format(self.ip))
        
        if self.http2:
            success, response = self.send_http2_request(method, path, headers, body)
        else:
            success, response = self.send_http1_request(method, path, headers, body)
        
        # 失败时关闭连接
        if not success:
            try:
                self.close()
                Log.warning("请求失败或状态码为0，关闭连接: {} {} {}".format(method, self.host, path))
            except:
                pass
        
        if success:
            Log.info("请求成功，状态码: {}".format(response.get('status', 0)))
        else:
            Log.error("请求失败: {}".format(response.get('error', '未知错误')))
        
        Log.info("=" * 60)
        
        return success, response
    
    def close(self):
        """关闭客户端，释放连接"""
        if self._h2_connection:
            try:
                # 发送GOAWAY帧优雅关闭HTTP/2连接
                self._h2_connection.close_connection()
                Log.info("关闭HTTP/2连接")
            except Exception as e:
                Log.warning("关闭HTTP/2连接异常: {}".format(e))
            finally:
                self._h2_connection = None
        
        if self._socket:
            try:
                self._socket.close()
                Log.info("关闭socket连接")
            except Exception as e:
                Log.warning("关闭socket连接异常: {}".format(e))
            finally:
                self._socket = None
        
        self._is_connected = False
        
        # 从全局客户端管理器移除
        try:
            key = self._get_client_key()
            with _client_lock:
                if key in _global_clients:
                    del _global_clients[key]
                    Log.info("从全局客户端移除: {}".format(key))
        except Exception as e:
            Log.warning("移除全局客户端异常: {}".format(e))


# 便捷函数，类似requests库的使用方式
def get(host, path, headers=None, timeout=10, http2=False, keep_alive=False, ip=None, use_ssl=False, port=None):
    """发送GET请求
    
    Args:
        host: 目标主机地址
        path: 请求路径，如 /api/test
        headers: 请求头部字典
        timeout: 超时时间
        http2: 是否使用HTTP/2
        keep_alive: 是否使用长连接
        ip: 可选，指定连接的IP地址
        use_ssl: 是否使用SSL/TLS
        port: 端口，默认80或443
    """
    return request("GET", host, path, headers=headers, timeout=timeout, http2=http2, 
                   keep_alive=keep_alive, ip=ip, use_ssl=use_ssl, port=port)

def post(host, path, headers=None, body=None, timeout=10, http2=False, keep_alive=False, ip=None, use_ssl=False, port=None):
    """发送POST请求"""
    return request("POST", host, path, headers=headers, body=body, timeout=timeout, 
                   http2=http2, keep_alive=keep_alive, ip=ip, use_ssl=use_ssl, port=port)

def put(host, path, headers=None, body=None, timeout=10, http2=False, keep_alive=False, ip=None, use_ssl=False, port=None):
    """发送PUT请求"""
    return request("PUT", host, path, headers=headers, body=body, timeout=timeout, 
                   http2=http2, keep_alive=keep_alive, ip=ip, use_ssl=use_ssl, port=port)

def delete(host, path, headers=None, timeout=10, http2=False, keep_alive=False, ip=None, use_ssl=False, port=None):
    """发送DELETE请求"""
    return request("DELETE", host, path, headers=headers, timeout=timeout, 
                   http2=http2, keep_alive=keep_alive, ip=ip, use_ssl=use_ssl, port=port)

def head(host, path, headers=None, timeout=10, http2=False, keep_alive=False, ip=None, use_ssl=False, port=None):
    """发送HEAD请求"""
    return request("HEAD", host, path, headers=headers, timeout=timeout, 
                   http2=http2, keep_alive=keep_alive, ip=ip, use_ssl=use_ssl, port=port)

def options(host, path, headers=None, body=None, timeout=10, http2=False, keep_alive=False, ip=None, use_ssl=False, port=None):
    """发送OPTIONS请求"""
    return request("OPTIONS", host, path, headers=headers, body=body, timeout=timeout, 
                   http2=http2, keep_alive=keep_alive, ip=ip, use_ssl=use_ssl, port=port)

def get_global_client(host, port=None, use_ssl=False, http2=False, timeout=10, ip=None):
    """获取全局客户端实例，用于长连接复用"""
    if port is None:
        port = 443 if use_ssl else 80
    
    # 生成客户端key
    actual_ip = ip if ip else host
    client_key = "{}:{}:{}:{}:{}".format(actual_ip, host, port, use_ssl, http2)
    
    with _client_lock:
        if client_key not in _global_clients:
            # 创建新的客户端实例，强制使用长连接
            _global_clients[client_key] = HTTPClient(
                host, port, use_ssl, http2, keep_alive=True, timeout=timeout, ip=ip
            )
            Log.info("创建全局客户端实例: {}".format(client_key))
        
        return _global_clients[client_key]

def request(method, host, path, headers=None, body=None, timeout=10, http2=False, keep_alive=False, ip=None, use_ssl=False, port=None):
    """
    发送HTTP请求
    
    Args:
        method: HTTP方法
        host: 目标主机地址
        path: 请求路径，如 /api/test
        headers: 请求头部字典
        body: 请求体
        timeout: 超时时间
        http2: 是否使用HTTP/2
        keep_alive: 是否使用长连接
        ip: 可选，指定连接的IP地址
        use_ssl: 是否使用SSL/TLS
        port: 端口，默认80或443
        
    Returns:
        tuple: (success, response_dict) - 统一返回格式
            success: bool - 请求是否成功
            response_dict: dict - 响应信息，包含status、headers、data/body、error等
    """
    # 处理端口
    if port is None:
        port = 443 if use_ssl else 80
    
    if keep_alive:
        # 长连接：使用全局客户端实例
        client = get_global_client(host, port, use_ssl, http2, timeout, ip)
        success, response = client.request(method, path, headers, body)
        return success, response
    
    else:
        # 短连接：创建临时客户端实例
        client = HTTPClient(host, port, use_ssl, http2, keep_alive=False, timeout=timeout, ip=ip)
        try:
            success, response = client.request(method, path, headers, body)
            return success, response
        finally:
            client.close()

# 清理所有全局客户端
def close_all_connections():
    """关闭所有全局客户端连接"""
    global _global_clients
    with _client_lock:
        Log.info("关闭所有全局客户端连接")
        for key, client in _global_clients.items():
            try:
                client.close()
                Log.info("关闭客户端: {}".format(key))
            except:
                pass
        _global_clients = {}