# 使用官方的 php:fpm 镜像作为基础镜像
FROM php:8.2-fpm

# 制作者信息
LABEL auther_template="Hello-CTF"

# 拷贝容器入口点脚本
COPY ./service/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# 复制web项目源码
COPY src /var/www/html

# 重新设置源码路径的用户所有权
RUN chown -R www-data:www-data /var/www/html

# 设置shell的工作目录
WORKDIR /var/www/html

# 暴露 80 端口
EXPOSE 80

# 设置容器入口点
ENTRYPOINT [ "/docker-entrypoint.sh" ]