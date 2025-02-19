import socket
import threading
import time

def create_echo_server(port):
    def handle_connection(conn, addr):
        print(f"端口 {port} 收到连接：{addr}")
        try:
            while True:
                data = conn.recv(1024)  # 接收客户端发送的数据
                if not data:
                    break
                print(f"端口 {port} 收到消息：{data.decode('utf-8')}")
                conn.send(data)  # 回显收到的消息
                break
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

# 监听81端口
create_echo_server(81)

# 保持主线程运行
while True:
    time.sleep(1)