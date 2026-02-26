# 功能
禁止通用客户端的规范化、批量测试字符

# 使用方法
1、替换占位符，e.g.,TEST_IP（cdn节点ip）、DOMAIN（接入域名）、fake_host（特殊功能测试的时候填写即可，非必要）
2、在源站ip2上部署python_server.py，nginx配置proxy_pass到ip2，测试链路为客户端-nginx-源站；cf配置dns解析到ip2，测试链路为客户端-cf-源站
3、执行客户端测试脚本，http2 为h2_req_header/h2_test_header_key_last_char.py；http1为req_header/test_header_key_start_char.py