# hello-ssrf
【Hello-CTF labs】靶场系列

算是 [ssrf-labs](https://github.com/ProbiusOfficial/ssrf-labs)  的前置靶场，介绍基本的协议，绕过方式以及攻击场景。

... 暂时先更新这么多，看我后续课程安排更新（

hello-world - 第一关 无过滤，主要了解file协议  
openwhat - 端口探测  
gopher_mirror - gopher协议特性  
gopher_master - gopher协议完成HTTP相关请求  
hostbypass - 简单绕过host限制  
whynotdomain - 域名绕过限制  
    
ohmyredis - 打redis
ohmysql - 打mysql未授权

## Usage

```bash
git clone https://github.com/ProbiusOfficial/hello-ssrf.git
cd hello-ssrf
docker-compose build
```
然后启动你想打的关卡（比如hostbypass）
```bash
docker run --rm -d -p 80:80/tcp hellossrf:hostbypass
```

## Writeup
后面再说（
