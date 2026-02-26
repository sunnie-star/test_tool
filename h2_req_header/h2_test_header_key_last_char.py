# -*- coding: utf-8 -*-
import sys
import string
import os
import time
# 设置标准输出编码为UTF-8，解决Python 3中文输出问题
if sys.version_info[0] >= 3:
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# 创建Log对象用于兼容原有代码
class Log:
    @staticmethod
    def info(msg):
        # 确保消息是字符串类型
        if not isinstance(msg, str):
            msg = str(msg)
        print(msg)

from h2_client_util import request,Log

# 客户端-nginx（127 443 http2 https）-测试环境python源站 （回源http1）
  #  location / {
   #     root /usr/share/nginx/html;  # 网站根目录
    #    index index.html index.htm;  # 默认首页
 #proxy_pass http://ip:80;
  #  }
# TEST_IP="127.0.0.1"


# 客户端-cf（443 http2 https）-测试环境python源站 （回源http1）
# cdn ip，可curl 域名查看节点ip
TEST_IP="ip"
# 域名
DOMAIN = "host"

#修改来统计nginx  cf
other_status_codes_char = []
fail_char=[]
# 日志文件名
LOG_FILE = "h2_req_header/cloudflare/header_test_errors_key_end.log"

# Header name的分隔符集合
NAME_DELIMITERS = set('"(),/:;<=>?@[\\]{}')
def log_error_response(key, value, char_code, status_code,msg=""):
    """记录错误响应到日志文件"""
    try:
        with open(LOG_FILE, 'a') as f:
            f.write("Key: {}, Value: {}, Char Code: {}, Status Code: {} {}\n".format(
                repr(key), repr(value), char_code, status_code,msg))
    except Exception as e:
        Log.error("写入日志文件失败: {}".format(str(e)))
        raise Exception("写入日志文件失败: {}".format(str(e)))

status_code_stats = {
    200: 0,
    400: 0,
    203: 0,
    502: 0,
    0: 0
}
def update_status_stats(status_code):
    """更新状态码统计"""
    if status_code in status_code_stats:
        status_code_stats[status_code] += 1
    else:
        # 如果状态码不在预期范围内，抛出异常
        raise Exception("意外的状态码: {}，不在预期的200、400、203范围内".format(status_code))


TEST_PATHS = {
    "default": "/"
}

PORT_HTTP2 = 443  # HTTP/2通常使用443端口
PORT_HTTP2_CLEAR = 80  # HTTP/2 over TCP (明文)
# 需要测试的协议
SCHEMAS = ["https"]
# 需要测试的HTTP方法
METHODS = ["GET"]

def send_http2_request_with_custom_header(test_ip, port, method, path, headers, use_ssl=False, timeout=10, body=None):
    """使用h2_client_util发送HTTP/2短连接请求"""
    try:
        # 使用h2_client_util的request函数发送HTTP/2短连接请求
        success, response = request(
            method=method,
            host=DOMAIN,
            path=path,
            headers=headers,
            body=body,
            timeout=timeout,
            http2=True,
            keep_alive=False,  # 短连接
            ip=test_ip,
            use_ssl=use_ssl,
            port=port  # 使用传入的端口参数
        )
        
        return success, response
        
    except Exception as e:
        Log.info("HTTP/2请求失败: {}".format(str(e)))
        return False, {"status": 0, "error": str(e)}

# 重测
# [0x00, 0x05, 0x0A, 0x0D,0x1E, 0x27, 0x2F,0x60, 0x74]

#  ['0x00', '0x0A', '0x0D', '0x68']
#  ['0x00', '0x0A', '0x0D', '0x27', '0x66']
# 如果卡住了重启一下源站python_server.py
def test_header_kv_chars_with_http2():
    """使用HTTP/2测试头部键名结尾字符"""
    Log.info("===============使用HTTP/2测试头部键名结尾字符===============")
    for schema in SCHEMAS:

        for method in METHODS:
            for mode, test_path in TEST_PATHS.items():
                for char_code in  range(0x00, 0x80):
                    char = chr(char_code)
                    
                    # 构造测试头部：字符 + "aa" 作为头部名称
                    test_key = "aa{}".format(char)
                    test_value="testmykv"

                    # test_key = "testmykv"
                    # test_value="aa{}aa".format(char)
                    # testmykv是用来测试cdn是否把这个头删掉了 自定义的源站python_server.py会进行校验 删掉返回203
                    headers = {test_key: test_value}
                    # 根据协议选择正确的端口
                    current_port = PORT_HTTP2 if schema == "https" else PORT_HTTP2_CLEAR
                    msg = "字符: 0x{:02X}({}), 协议: {} 方法: {}, 模式: {}, 端口: {}".format(
                        char_code, repr(char), schema.upper(), method, mode, current_port
                    )
                    
                    
                    try:
                        success, response = send_http2_request_with_custom_header(
                            TEST_IP, current_port, method, test_path, headers, use_ssl=(schema == "https")
                        )
                        
                        if success:
                            status_code = response.get("status", 0)
                            # 更新状态码统计
                            
                            update_status_stats(status_code)
                              # 如果状态码是400或203，记录到日志文件
                            if status_code in [400, 203]:
                                if  char in NAME_DELIMITERS:
                                     log_error_response(test_key, test_value, char_code, status_code,"delimeters")
                                elif char >= 'A' and char <='Z':
                                    log_error_response(test_key, test_value, char_code, status_code,"upletter")
                                else:
                                    log_error_response(test_key, test_value, char_code, status_code)
                                
                            elif status_code in [0,502]:
                                other_status_codes_char.append(char_code)
                           
                        else:
                            error_msg = response.get('error', '未知错误')
                            fail_char.append(char_code)
                            log_error_response(test_key, test_value, char_code, -1,"fail")
                            Log.info("✗ 请求失败: {} - 错误: {}".format(msg, error_msg))
                            # raise Exception(msg)
         
                    
                                
                    except Exception as e:
                        error_msg = str(e)
                        Log.info("✗ 测试异常: {} - 异常: {}".format(msg, error_msg))
                        raise Exception(msg)
                    time.sleep(0.01)

def show_status_stats():
    """显示状态码统计结果"""
    Log.info("===============状态码统计结果===============")
    for code, count in status_code_stats.items():
        Log.info("状态码 {}: {} 次".format(code, count))
    Log.info("============================================")


"""主测试函数"""
try:
    Log.info("=====================测试key结尾字符，正常200，非法响应400/goaway====================")
    
    test_header_kv_chars_with_http2()
    # test_http2_uri()
    # test_http2_multi_host()
     # # 打印状态码统计结果
    show_status_stats()
    # 将字符码转换为16进制格式显示
    hex_codes = ["0x{:02X}".format(code) for code in other_status_codes_char]
    Log.info("其他状态码对应的字符码(16进制): {}".format(hex_codes))
    Log.info("其他状态码对应的字符码(10进制): {}".format(other_status_codes_char))


    hex_fail_ch = ["0x{:02X}".format(code) for code in fail_char]
    Log.info("error char(16进制): {}".format(hex_fail_ch))
    Log.info("error char(10进制): {}".format(fail_char))
    Log.info("HTTP/2头部键名结尾字符测试完成")

    
except Exception as e:
    Log.info("HTTP/2头部键名结尾字符测试异常: {}".format(str(e)))

