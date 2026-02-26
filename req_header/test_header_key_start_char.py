# -*- coding: utf-8 -*-
import sys
import socket
import ssl
import string
import struct
import datetime
from http_socket_utils import send_raw_http_request,logger

TEST_IP="ip"
DOMAIN="host"

PORT_HTTP = 3081

TEST_PATHS = {
    "default":"/"
}

PORT_HTTPS = 443

# 需要测试的HTTP方法
# METHODS = ["GET", "PUT", "OPTIONS", "HEAD", "POST"]
METHODS = ["GET"]

# 需要测试的协议
SCHEMAS = ["http"]  # 只测试HTTP协议

# 状态码统计
status_code_stats = {
    200: 0,
    400: 0,
    203: 0,
    502: 0, #有的时候不知道网不好还是啥 cf会出现502 这种case统计下来重测
    0: 0
}

other_status_codes_char = []

# 日志文件名
LOG_FILE = "header_test_errors.log"

# Header name的分隔符集合
NAME_DELIMITERS = set('"(),/:;<=>?@[\\]{}')

def log_error_response(key, value, char_code, status_code,msg=""):
    """记录错误响应到日志文件"""
    try:
        with open(LOG_FILE, 'a') as f:
            f.write("Key: {}, Value: {}, Char Code: {}, Status Code: {} {}\n".format(
                repr(key), repr(value), char_code, status_code,msg))
    except Exception as e:
        logger.error("写入日志文件失败: {}".format(str(e)))

def update_status_stats(status_code):
    """更新状态码统计"""
    if status_code in status_code_stats:
        status_code_stats[status_code] += 1
    else:
        # 如果状态码不在预期范围内，抛出异常
        raise Exception("意外的状态码: {}，不在预期的200、400、203范围内".format(status_code))

def show_status_stats():
    """显示状态码统计结果"""
    logger.info("===============状态码统计结果===============")
    for code, count in status_code_stats.items():
        logger.info("状态码 {}: {} 次".format(code, count))
    logger.info("============================================")

def test_http1_multi_host():
# 测试cf 
# 多个host 200 
# 第一个host为准
    fake_host="fake_host"
    port=80
    method="GET"
    test_path="/"
    headers = [("Host", DOMAIN),("Host", fake_host)]
    headers.append(("testmykv", "aa"))
    use_ssl = False
    success, response = send_raw_http_request(
    TEST_IP, port, method, test_path, headers, use_ssl)

def test_http1_uri():
# 测试nginx
    port=8080
    method="GET"
    test_path=""
    headers = [("Host", "testhost1")]
    use_ssl = False
    success, response = send_raw_http_request(
    TEST_IP, port, method, test_path, headers, use_ssl)

def test_special_chars_with_raw_socket():
    """使用原始socket测试特殊字符"""
    logger.info("===============使用原始socket测试特殊字符===============")
    # 测试特殊字符
    for schema in SCHEMAS:
        port = PORT_HTTPS if schema == "https" else PORT_HTTP
        use_ssl = schema == "https"
        
        for method in METHODS:
            for char_code in  range(0x00,0x80):
                for level,test_path in TEST_PATHS.items():
                    char = chr(char_code)
                    test_keys = [
                        #  char + "aa",
                        # "aa"+char+"bb",
                        # "aa"+char,
                        "testmykv",
                        # "testmykv",
                        # "testmykv"
                    ]
                    test_values = [
                        # "testmykv",
                        # "testmykv",
                        # "testmykv",
                        # char + "aa",
                        # "aa"+char+"bb",
                        "aa"+char
                    ]

                    for index in range(len(test_keys)):
                        headers = {"Host": DOMAIN,
                                    test_keys[index]: test_values[index]
                                    }
                        msg = "测试字符: 0x{:02X}({}), 值: {}, 方法: {}, 协议: {}".format(
                            char_code, repr(char), repr(test_values[index]), method, schema
                        )
                        logger.info(msg)

                        success, response = send_raw_http_request(
                            TEST_IP, port, method, test_path, headers, use_ssl
                        )

                        if success:
                            status_code = response.get("status", 0)
                            
                            # 更新状态码统计
                            update_status_stats(status_code)
                            
                            # 如果状态码是400或203，记录到日志文件
                            if status_code in [400, 203]:
                                if  char not in NAME_DELIMITERS:
                                    log_error_response(test_keys[index], test_values[index], char_code, status_code)
                                else:
                                    log_error_response(test_keys[index], test_values[index], char_code, status_code,"delimeters")
                            elif status_code in [0,502]:
                                other_status_codes_char.append(char_code)
                        else:
                            logger.error("✗ 请求失败: {}".format(response.get('error', '未知错误')))
                            raise Exception(msg)
 


def main():
    logger.info("=====================测试key开头字符，正常200，非法响应400====================")
    
    # 初始化日志文件
    with open(LOG_FILE, "w") as f:
        f.write("Header Test Error Log - Started at {}\n".format(
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ))
        f.write("=" * 50 + "\n")
    
    test_special_chars_with_raw_socket()
    
    # 打印状态码统计结果
    show_status_stats()
    # 将字符码转换为16进制格式显示
    hex_codes = ["0x{:02X}".format(code) for code in other_status_codes_char]
    logger.info("其他状态码对应的字符码(16进制): {}".format(hex_codes))
    logger.info("其他状态码对应的字符码(10进制): {}".format(other_status_codes_char))
    # test_http1_uri()
    # test_http1_multi_host()


    logger.info("测试完成")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error("测试失败: {}".format(str(e)))
