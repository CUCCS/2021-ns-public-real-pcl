## HTTP代理服务器实验

### 实验目的：

问题：使用http代理服务器访问HTTPS站点时，通信传输内容是否会被代理服务器“看到”？

结论：代理服务器不知道客户端和服务器的HTTPS通信内容，但代理服务器知道客户端访问了哪个HTTPS站点，这是由http代理的协议机制决定的：代理客户端会发送Connect请求到http代理服务器。

**验证实验：在Kali Linux中安装tinyproxy，然后用主机设置浏览器代理指向tinyproxy建立的HTTP正向代理，在Kali中用wireshark抓包，分析抓包过程，理解HTTP正向代理HTTPS流量的特点。**

```
提醒：HTTP代理服务器在转发客户端请求时，可能会添加Via字段，从而向目标站点暴露客户端正在使用代理访问。类似的，匿名通信应用tor的部分出口节点也会在http请求中自动加入via字段，向被访问站点宣告：当前请求正在使用匿名通信网络tor提供的匿名通信服务。
```

### 实验要求：

------

- [x] 课内tinyproxy实验跟做
- [x] 在Kali Linux中安装tinyproxy，然后用主机设置浏览器代理指向tinyproxy建立的HTTP正向代理
- [x] 在Kali中用wireshark抓包，分析抓包过程，理解HTTP正向代理HTTPS流量的特点

------

### 课内实验：

1.创建虚拟机 kali-Linux

<img src="img\kali-linux.jpg" alt="kali-linux" style="zoom:50%;" />

2.在Kali Linux中安装tinyproxy

<img src="img\update.jpg" alt="uodate" style="zoom:50%;" />

<img src="img\tinyproxy.jpg" alt="tinyproxy" style="zoom:50%;" />

systemctl status tinproxy查看状态，默认情况下没有启动

<img src="img\状态.jpg" alt="状态" style="zoom:50%;" />

启动一下

<img src="img\launch.jpg" alt="launch" style="zoom:50%;" />

3.访问前述 proxy.php

curl -x http://127.0.0.1:8888 http://127.0.0.1:8080/proxy.php

<img src="img\curl.jpg" alt="curl" style="zoom:50%;" />

4.修改配置文件

 在客户端请求头中加入客户端真实 IP 

```
sed -i.bak "s/#XTinyproxy Yes/XTinyproxy Yes/" /etc/tinyproxy/tinyproxy.conf
```


<img src="img\修改配置.jpg" alt="修改配置.jpg" style="zoom:67%;" />
5.重启 tinyproxy 服务 

systemctl restart tinyproxy

<img src="img\重启tinyproxy.jpg" alt="重启tinyproxy" style="zoom:67%;" />

6.在独立 shell 窗口开启 tinyproxy 日志监控小程序

sudo su- 进入root权限

<img src="img\进入root权限.jpg" alt="进入root权限" style="zoom: 67%;" />

tail -F /var/log/tinyproxy/tinyproxy.log

<img src="img\tail0.jpg" alt="tail0" style="zoom: 50%;" />

7.开启另一个终端，访问 HTTPS 站点

curl -x http://127.0.0.1:8888 https://auth.alipay.com/login/index.htm

观察日志输出结果

<img src="img\curl.jpg" alt="curl" style="zoom:50%;" />

8.查看响应头

curl -I -x http://127.0.0.1:8888 https://auth.alipay.com/login/index.htm

<img src="img\tail1.jpg" alt="tail1" style="zoom: 33%;" />

<img src="img\tail2.jpg" alt="tail2" style="zoom:33%;" />

### 课外实验：

### 实验环境：

#### 正向代理模你机制：

- 网关：代理服务器
- 受害者主机

1.根据拓扑关系继续使用实验一的虚拟机

<img src="img\虚拟机.jpg" alt="虚拟机" style="zoom:50%;" />



| 虚拟机名称     | 虚拟机IP       | 网卡                                             |
| -------------- | -------------- | ------------------------------------------------ |
| Gateway-Debian | 192.168.56.113 | NAT网络、host-only网络、内部网络intnet1、intnet2 |
| Victim=kali-1  | 172.16.111.121 | 内部网络intnet1                                  |
| Attack-kali    | 10.0.2.4       | NAT网络                                          |



<img src="img\debian-ip.jpg" alt="debian-ip" style="zoom:50%;" />

<img src="img\kali-ip.jpg" alt="kali-ip" style="zoom:67%;" />

2.测试连通性

- Attack-kali 可以ping Gateway-Debian 并可以上网

  <img src="img\ping1.jpg" alt="ping1" style="zoom: 67%;" />

- Attack-kali ping 不通 Victim=kali-1

  <img src="img\ping2.jpg" alt="ping2" style="zoom:67%;" />

- Gateway-Debian 可以 ping Attack-kali 和 Victim=kali-1

  <img src="img\ping3.jpg" alt="ping3" style="zoom:67%;" />

- Victim=kali-1可以 ping  Attack-kali、Gateway-Debian并且可以上网

  <img src="img\ping4.jpg" alt="ping4" style="zoom:50%;" />

### 实验过程：

1.网管上安装tinyproxy

<img src="img\debian-tinyproxy.jpg" alt="debian-tinyproxy" style="zoom:50%;" />

2.配置文件修改

```bash
编辑tinyproxy，取消Allow 10.0.0.0/8行首注释
vim /etc/tinyproxy/tinyproxy.conf
开启tinyproxy服务
/etc/init.d/tinyproxy start
```

<img src="img\port.jpg" alt="port" style="zoom: 50%;" />

<img src="img\ip.jpg" alt="ip" style="zoom:50%;" />

<img src="img\开启.jpg" alt="开启" style="zoom:67%;" />

3.对于Attack-kali

- 在浏览器preference中输入connection搜索connection settings

  <img src="img\8.jpg" alt="8" style="zoom: 50%;" />

- 选择**Manual proxy configuration**，并在 HTTP Proxy一栏输入网关的NAT网络地址，端口和 **tinyproxy.conf**文件中的一致

  <img src="img\9.jpg" alt="9" style="zoom:50%;" />

4.对于Victim-kali-1

```
# 开启服务
sudo service apache2 start
```

5.对于Attack-kali抓包

<img src="img\10.jpg" alt="10" style="zoom:80%;" />

- 访问Victim-kali-1


<img src="img\访问受害者.jpg" alt="访问受害者" style="zoom:50%;" />

<img src="img\访问受害者heacker.jpg" alt="访问受害者heacker" style="zoom:50%;" />

- 抓包结束，分析抓包结果


<img src="img\抓包结束.jpg" alt="抓包结束" style="zoom:67%;" />

<img src="img\抓包结果.jpg" alt="抓包结果" style="zoom: 50%;" />

<img src="img\分析抓包结果.jpg" alt="分析抓包结果" style="zoom:50%;" />

- 能看到代理`1.1 tinyproxy (tinyproxy/1.10.0)`，但是看不到具体的信息（例如ip地址）


6.对于网关，抓包并分析：

```
sudo tcpdump -i enp0s3 -n -w 20210919.2.pcap

# 复制文件到本机桌面上
scp cuc@192.168.56.113:/home/cuc/workspace/20210919.2.pcap ./
```

<img src="img\在网管上抓包并拷贝到主机桌面.jpg" alt="在网管上抓包并拷贝到主机桌面" style="zoom: 50%;" />

<img src="img\网关抓包分析.jpg" alt="网关抓包分析" style="zoom: 33%;" />

- 网关（代理服务器）行为分析

```
1.网关保留HTTP GET请求内容，若攻击者主机（客户端）的浏览器不清除历史记录，则下次访问同样的HTTP服务时用时非常短

2、若在网关设置防火墙规则过滤攻击者主机（客户端）发出的的请求，则攻击者主机（客户端）依然无法访问靶机端（服务器）的HTTP服务
3.代理层可以理解HTTP报文
```

7.对于Victim-kali-1

- 抓包分析：


<img src="img\受害者抓包分析.jpg" alt="受害者抓包分析" style="zoom:50%;" />

- Victim-kali-1服务器行为分析：


```
1.HTTP协议中出现Via字段，说明网关（代理服务器）正在提供代理服务

2.攻击者主机IP地址、以太网接口均未暴露
```

8.对于Attack-kali

- 访问www.cuc.edu.cn,抓包分析，通过代理访问HTTPS站点


<img src="img\访问http抓包.jpg" alt="访问http抓包" style="zoom:50%;" />

- HTTPS服务建立连接后，用户与网站进行加密通信


<img src="img\加密通信.jpg" alt="加密通信" style="zoom: 50%;" />

### 问题解决

1.修改配置文件时：wq！强制保存也出现错误

E212: Can‘t open file for writing Press ENTER or type command to continue

**解决方法：**

在命令前加sudo

2.在Attack-kali中访问Victim=kali-1失败，没有权限

**出现问题原因：tinyproxy 的配置实际没有生效**

**解决方法：**

```
#先关闭掉 tinyproxy 服务

service tinyproxy stop

#确认服务停掉了

ps aux | grep tinyproxy

#再重新开启服务

service tinyproxy restart

#查看tinyproxy状态

 service tinyproxy status
```

<img src="img\问题解决2.jpg" alt="问题解决2" style="zoom: 50%;" />



### 参考文献

[解决强制写入报错](https://blog.csdn.net/pearl8899/article/details/108632851)

[tinyproxy的一些命令](https://www.yuncongz.com/archives/1.html)

