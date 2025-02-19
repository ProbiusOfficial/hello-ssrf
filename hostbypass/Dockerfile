FROM php:7.3-fpm-alpine

# 制作者信息
LABEL auther_template="CTF-Archives"

# 安装必要的软件包和网络工具
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories  &&\
    apk add --update --no-cache \
    nginx \
    bash \
    python3 \
    py3-pip \
    netcat-openbsd \
    curl \
    socat

# 安装Python简单HTTP服务器依赖
RUN pip3 install flask -i https://pypi.tuna.tsinghua.edu.cn/simple/

# 拷贝容器入口点脚本
COPY ./service/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# 复制nginx配置文件
COPY ./config/nginx.conf /etc/nginx/nginx.conf

# 复制web项目源码
COPY src /var/www/html

# 创建多端口监听脚本
COPY ./service/multi_port_listener.py /multi_port_listener.py
RUN chmod +x /multi_port_listener.py

# 重新设置源码路径的用户所有权
RUN chown -R www-data:www-data /var/www/html

# 设置shell的工作目录
WORKDIR /var/www/html

#暴露多个端口
EXPOSE 80

# 设置nginx日志保存目录
VOLUME ["/var/log/nginx"]

# 设置容器入口点
ENTRYPOINT [ "/docker-entrypoint.sh" ]