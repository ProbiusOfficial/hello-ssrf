FROM mysql:5.6

# 设置必要的环境变量
ENV MYSQL_ALLOW_EMPTY_PASSWORD="yes"

# 安装 Freexian 的 APT 源密钥
COPY ./config/freexian-archive-extended-lts.gpg /etc/apt/trusted.gpg.d/freexian-archive-extended-lts.gpg

# 重新配置Debian 9 Stretch 的可用源并配置本地实验环境
RUN echo "deb http://mirrors.cernet.edu.cn/debian-elts/ stretch main contrib non-free" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y curl tcpdump python python-pip openssh-server sudo net-tools \
    && pip install paramiko tornado -i https://pypi.tuna.tsinghua.edu.cn/simple


# Create a low-privilege user with a weak password
RUN useradd -ms /bin/bash helloctf && \
    echo "helloctf:123456" | chpasswd && \
    usermod -aG sudo helloctf

# Set up SSH
RUN mkdir /var/run/sshd

# MySQL配置文件
COPY ./config/mysqld.cnf /etc/mysql/mysql.conf.d/

# 初始化SQL文件（容器启动时自动执行）
COPY ./data/db.sql /docker-entrypoint-initdb.d/

# 复制Python脚本
COPY ./src/ /usr/local/bin/app
RUN chmod +x /usr/local/bin/app/*.py

# Entrypoint
COPY ./service/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 5050
