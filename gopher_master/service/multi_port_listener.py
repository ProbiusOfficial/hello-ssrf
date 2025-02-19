import socket
import threading
import os

def create_http_server(port, response_message):
    def handle_connection(conn, addr):
        print(f"端口 {port} 收到连接：{addr}")
        try:
            request = conn.recv(1024).decode('utf-8')  # 接收请求
            print(f"端口 {port} 收到请求：\n{request}")
            
            # 解析请求
            if "GET" in request and "key=helloctf" in request and port == 81:
                response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(response_message[0])}\r\n\r\n{response_message[0]}"
            elif "POST" in request and "key=helloctf" in request and port == 8181:
                response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(response_message[1])}\r\n\r\n{response_message[1]}"
            else:
                response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
            
            conn.send(response.encode('utf-8'))  # 发送响应
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

# 将 INSERT_FLAG 分成两部分
flag_part1 = insert_flag[:len(insert_flag) // 2]
flag_part2 = insert_flag[len(insert_flag) // 2:]

# 创建HTTP服务
create_http_server(81, (flag_part1, flag_part2))  # 81端口返回第一部分
create_http_server(8181, (flag_part1, flag_part2))  # 8181端口返回第二部分

# 保持主线程运行
while True:
    pass