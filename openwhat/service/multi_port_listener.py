import socket
import threading
import time
import os

def create_dummy_server(port, response_message):
    def handle_connection(conn, addr):
        print(f"端口 {port} 收到连接：{addr}")
        try:
            time.sleep(2)
            conn.send(response_message.encode('utf-8'))
        except Exception as e:
            print(f"端口 {port} 连接错误: {e}")
        finally:
            conn.close()

    def server_thread():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(5)
            print(f"端口 {port} 监听中...")
            while True:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=handle_connection, args=(conn, addr)).start()
                except Exception as e:
                    print(f"端口 {port} 接受连接时发生错误: {e}")

    threading.Thread(target=server_thread, daemon=True).start()

# 从环境变量中获取 INSERT_FLAG 的值
insert_flag = os.getenv("INSERT_FLAG")
if not insert_flag:
    print("环境变量 INSERT_FLAG 未设置，使用默认值 DEFAULT_FLAG")
    insert_flag = "flag{de62b596-fbd4-48d8-b1f0-36b30511f895}"

# 定义每个端口的自定义响应消息
port_responses = {
    23: "Port 23 is open:",
    81: "Port 81 is open:",
    3309: "Port 3309 is open:",
    6380: "Port 6380 is open:",
    8082: "Port 8082 is open:",
    9001: "Port 9001 is open:"
}

# 将 INSERT_FLAG 均匀分配到每个端口的响应消息中
flag_parts = list(insert_flag)  # 将字符串拆分为字符列表
num_ports = len(port_responses)
flag_part_length = len(flag_parts) // num_ports  # 每个端口分配的字符长度
remaining_chars = len(flag_parts) % num_ports  # 剩余的字符数量

current_index = 0
for i, (port, response) in enumerate(port_responses.items()):
    # 每个端口分配的字符数量
    part_length = flag_part_length + (1 if i < remaining_chars else 0)
    # 提取对应的字符片段
    part = ''.join(flag_parts[current_index:current_index + part_length])
    # 将字符片段插入到响应消息中
    port_responses[port] = response + " " + part
    # 更新索引
    current_index += part_length

# 创建多个端口监听
for port, response in port_responses.items():
    create_dummy_server(port, response)

# 保持主线程运行
while True:
    time.sleep(1)