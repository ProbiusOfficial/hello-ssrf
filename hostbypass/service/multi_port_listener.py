import socket
import threading
import os

def create_http_server(port):
    def handle_connection(conn, addr):
        print(f"端口 {port} 收到连接：{addr}")
        try:
            request = conn.recv(1024).decode('utf-8')  # 接收请求
            print(f"端口 {port} 收到请求：\n{request}")
            
            # 检查是否为GET请求且包含key=helloctf
            if "GET" in request and "key=helloctf" in request:
                response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(flag)}\r\n\r\n{flag}"
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
flag = os.getenv("INSERT_FLAG")
if not flag:
    print("环境变量 INSERT_FLAG 未设置，使用默认值 DEFAULT_FLAG")
    flag = "flag{de62b596-fbd4-48d8-b1f0-36b30511f895}"

# 创建HTTP服务，监听8181端口
create_http_server(8181)

# 保持主线程运行
while True:
    pass