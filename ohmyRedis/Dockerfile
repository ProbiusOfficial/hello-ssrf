FROM centos:7
COPY rpm /rpm
RUN cd /rpm && rpm -ivh *.rpm
COPY redis-* /usr/local/bin/
COPY redis.conf /etc/
COPY start.sh /start.sh
COPY src/* /var/www/html
RUN chmod -v +x /start.sh \
    && chmod +x /usr/local/bin/redis-server

EXPOSE 80
CMD ["/start.sh"]
