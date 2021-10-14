# 基于 Scapy 编写端口扫描器

##  实验目的

- 掌握网络扫描之端口状态探测的基本原理

## 实验环境

- python + scapy

- 各主机ip地址 

  | 名称                | ip地址         |
  | ------------------- | -------------- |
  | 网关Gateway-Dbian   | 172.16.111.1   |
  | 扫描端Attack-kali-2 | 172.16.111.148 |
  | 受害者Victim-kali-1 | 172.16.111.121 |

  

## 实验要求

- [x] 禁止探测互联网上的 IP ，严格遵守网络安全相关法律法规
- [x] 完成以下扫描技术的编程实现
  - [x] TCP connect scan / TCP stealth scan
  - [x] TCP Xmas scan / TCP fin scan / TCP null scan
  - [x] UDP scan
- [x] 上述每种扫描技术的实现测试均需要测试端口状态为：`开放`、`关闭` 和 `过滤` 状态时的程序执行结果
- [x] 提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因；
- [x] 在实验报告中详细说明实验网络环境拓扑、被测试 IP 的端口状态是如何模拟的
- [x] （可选）复刻 nmap 的上述扫描技术实现的命令行参数开关

## 实验原理

`TCP connect scan`

> 这种扫描方式可以使用 Connect()调用，使用最基本的 TCP 三次握手链接建立机制，建立一个链接到目标主机的特定端口上。首先发送一个 SYN 数据包到目标主机的特定端口上，接着我们可以通过接收包的情况对端口的状态进行判断：

1. 如果接收到的是一个 SYN/ACK 数据包，则说明端口是开放状态的；
2. 如果接收到的是一个 RST/ACK 数据包，通常意味着端口是关闭的并且链接将会被重置；
3. 如果目标主机没有任何响应则意味着目标主机的端口处于过滤状态。

> 若接收到 SYN/ACK 数据包（即检测到端口是开启的），便发送一个 ACK 确认包到目标主机，这样便完成了三次握手连接机制。成功后再终止连接。

> 优点：稳定可靠，不需要特殊的权限。但扫描方式不隐蔽，服务器日志会纪录下大量密集的连接和错误记录，并容易被防火墙发现和屏蔽。



`TCP SYN scan`

> 与 TCP Connect 扫描不同，TCP SYN 扫描并不需要打开一个完整的链接。发送一个 SYN 包启动三方握手链接机制，并等待响应。

1. 如果我们接收到一个 SYN/ACK 包表示目标端口是开放的；
2. 如果接收到一个 RST/ACK 包表明目标端口是关闭的；
3. 如果端口是被过滤的状态则没有响应。

> 当得到的是一个 SYN/ACK 包时通过发送一个 RST 包立即拆除连接。

> 优点是隐蔽性较全连接扫描好，因为很多系统对这种半扫描很少记录。缺点是构建 SYN 报文需要超级用户权限，且网络防护设备会有记录。



`TCP Xmas scan`

> Xmas 发送一个 TCP 包，并对 TCP 报文头 FIN、URG 和 PUSH 标记进行设置。

1. 若是关闭的端口则响应 RST 报文；
2. 开放或过滤状态下的端口则无任何响应。

> 优点是隐蔽性好，缺点是需要自己构造数据包，要求拥有超级用户或者授权用户权限。



`TCP fin scan`

> 仅发送 FIN 包，它可以直接通过防火墙，如果端口是关闭的就会回复一个 RST 包，如果端口是开放或过滤状态则对 FIN 包没有任何响应。

> 其优点是 FIN 数据包能够通过只监测 SYN 包的包过滤器，且隐蔽性高于 SYN 扫描。缺点和 SYN 扫描类似，需要自己构造数据包，要求由超级用户或者授权用户访问专门的系统调用。

`TCP Null scan`

> 发送一个 TCP 数据包，关闭所有 TCP 报文头标记。只有关闭的端口会发送 RST 响应。

> 其优点和 Xmas 一样是隐蔽性好，缺点也是需要自己构造数据包，要求拥有超级用户或者授权用户权限。

UDP scan

> UDP 是一个无链接的协议，当我们向目标主机的 UDP 端口发送数据,我们并不能收到一个开放端口的确认信息,或是关闭端口的错误信息。

1. 如果收到一个 ICMP 不可到达的回应，那么则认为这个端口是关闭的
2. 对于没有回应的端口则认为是开放的
3. 当向一个未开放的 UDP 端口发送数据时,其主机就会返回一个 ICMP 不可到达(ICMP_PORT_UNREACHABLE)的错误,大多数 UDP 端口扫描的方法就是向各个被扫描的 UDP 端口发送零字节的 UDP 数据包实验步骤。

> 其缺点是，UDP 是不可靠的，UDP 数据包和 ICMP 错误报文都不保证到达；且 ICMP 错误消息发送效率是有限的，故而扫描缓慢；还有就是非超级用户无法直接读取端口访问错误。





## 环境准备，端口状态模拟：

Attacker作为扫描端，Victim作为被扫描的靶机

在 靶机 `Victim-kali-1` 上安装  `ufw` , 用于控制端口打开、关闭以及过滤

在靶机  `Victim-kali-1` 上安装 `dnsmasq`,用于搭建dns服务：`sudo apt install dnsmasq`

> ufw命令：`sudo ufw enable\disable` `sudo ufw allow port-num`
> 检测某一端口状态：`sudo netstat -lnp | grep port-num`
> 设置端口过滤状态：`sudo ufw deny port-num`
> nmap扫描TCP：`sudo nmap [-sT/sX/sS] ip-address` 扫描UDP：`sudo namp -sU ip-address

```
sudo apt-get update 
sudo apt install ufw
sudo apt-get install dnsmasq
```

<img src="img\victim和attackupdate.jpg" alt="victim和attackupdate" style="zoom: 50%;" />

<img src="img\attack install dnsmasq.jpg" alt="attack install dnsmasq" style="zoom: 67%;" />

<img src="img\victim install ufw.jpg" alt="victim install ufw" style="zoom: 67%;" />

`dnsmasq` 状态操作

```shell
systemctl start dnsmasq # 启动（靶机）
systemctl status dnsmasq # 查看状态
systemctl stop dnsmasq # 关闭
```

<img src="img\dnsmasq 状态操作.jpg" alt="dnsmasq 状态操作" style="zoom:80%;" />

- **关闭状态**：对应端口没有开启监听，防火墙没有开启

  ```shell
  ufw disable（靶机）
  systemctl stop apache2 # 关闭端口80（靶机）
  systemctl stop dnsmasq # 关闭端口53
  ```

  <img src="img\ufw disable.jpg" alt="ufw disable" style="zoom:80%;" />

  <img src="img\attack-stop.jpg" alt="attack-stop" style="zoom:80%;" />

- **开启状态**：对应端口开启监听，防火墙处于关闭状态

  ```shell
  systemctl start apache2 # 开启80端口 apache2基于TCP, 在80端口提供服务（靶机）
  systemctl start dnsmasq # 开启53端口 DNS服务基于UDP,在53端口提供服务
  ```

  <img src="img\attack-start.jpg" alt="attack-start" style="zoom:80%;" />

- **过滤状态**：对应端口开启监听, 防火墙开启

  ```shell
  ufw enable && ufw deny 80/tcp（靶机）
  ufw enable && ufw deny 53/udp
  ```

  <img src="img\ufw 过滤状态.jpg" alt="ufw 过滤状态" style="zoom:80%;" />

- **初始状态**

  ```
  nmap 172.16.111.121(扫描端)
  ```

  <img src="img\初始状态.jpg" alt="初始状态" style="zoom:80%;" />

## 实验步骤：

#### TCP connect scan

  [connect.py](code\connect.py) 

```python
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

dst_ip = "172.16.111.121" # 靶机IP地址
src_port = RandShort()
dst_port = 80

tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
print(type(tcp_connect_scan_resp))

if str(type(tcp_connect_scan_resp)) == "<class 'NoneType'>":
        print("no response, filtered.")

# 获取 tcp 应答
elif tcp_connect_scan_resp.haslayer(TCP):
    # Flags:0x012 SYN,ACK
    if tcp_connect_scan_resp.getlayer(TCP).flags == 0x12:
        # Flags: 0x014 ACK,RST
        send_ack = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
        print("is open")
    elif tcp_connect_scan_resp.getlayer(TCP).flags == 0x14:
        print("is closed, connection will be reset.")
    print('finished tcp connect scan.\n')
elif(tcp_connect_scan_resp.haslayer(ICMP)):
    if(int(tcp_connect_scan_resp.getlayer(ICMP).type)==3 and int(tcp_connect_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print("filtered")
print('finished tcp syn scan.\n')    
    
```

**端口开放**

```
systemctl start apache2 （靶机）
systemctl status apache2 （靶机）
```

<img src="img\端口开放connect.jpg" alt="端口开放connect" style="zoom:67%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.1.pcap
  ```

  <img src="img\端口开放靶机抓包connect.jpg" alt="端口开放靶机抓包connect" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 connect.py
  ```

  <img src="img\端口开放python3 connect.jpg" alt="端口开放python3 connect" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口开放connect抓包结果.jpg" alt="端口开放connect抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sT -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口开放nmap connect.jpg" alt="端口开放nmap connect" style="zoom:67%;" />

**端口关闭**

```
systemctl stop apache2（靶机）
systemctl status apache2
ufw disable
```

<img src="img\端口关闭connect.jpg" alt="端口关闭connect" style="zoom:80%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.2.pcap
  ```

  <img src="img\端口关闭靶机抓包connect.jpg" alt="端口关闭靶机抓包connect" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 connect.py
  ```

  <img src="img\端口关闭python3 connect.jpg" alt="端口关闭python3 connect" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口关闭connect抓包结果.jpg" alt="端口关闭connect抓包结果" style="zoom: 67%;" />

- nmap 复刻

  ```
  nmap -sT -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口关闭nmap connect.jpg" alt="端口关闭nmap connect" style="zoom: 80%;" />

**端口过滤**

```
ufw enable && ufw deny 80/tcp（靶机）
```

<img src="img\端口过滤connect.jpg" alt="端口过滤connect" style="zoom:80%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.3.pcap
  ```

  <img src="img\端口过滤靶机抓包connect.jpg" alt="端口过滤靶机抓包connect" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 connect.py
  ```

  <img src="img\端口过滤python3 connect.jpg" alt="端口过滤python3 connect" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口过滤connect抓包结果.jpg" alt="端口过滤connect抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sT -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口过滤nmap connect.jpg" alt="端口过滤nmap connect" style="zoom:80%;" />

#### TCP stealth scan

 [stealth.py](code\stealth.py) 

```python
from scapy.all import *

def tcp_syn_scan(dst_ip, dst_port, timeout=10):

    # send SYN+port(80)
    tcp_sun_scan_p = sr1(IP(dst=dst_ip) / TCP(dport=dst_port,flags="S"),timeout=10)
    print(type(tcp_sun_scan_p))

    if str(type(tcp_sun_scan_p)) == "<class 'NoneType'>":
        print('no response, filtered')
    elif tcp_sun_scan_p.haslayer(TCP):
        # Flags:0x012 SYN,ACK
        if tcp_sun_scan_p.getlayer(TCP).flags == 0x12:
            # Flags: 0x014 ACK+RST
            send_ack = sr(IP(dst=dst_ip) / TCP(dport=dst_port, flags="AR"), timeout=10)
            print("is open")
        elif tcp_sun_scan_p.getlayer(TCP).flags == 0x14:
            print("is closed")
    elif tcp_sun_scan_p.haslayer(ICMP):
        if int(tcp_sun_scan_p.getlayer(ICMP).type)==3 and int(tcp_sun_scan_p.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            print("filtered")
    print('finished tcp syn scan.\n')
    
tcp_syn_scan('172.16.111.121', 80)

```



**端口开放**

```
systemctl start apache2 （靶机）
systemctl status apache2 （靶机）
ufw disable (关闭防火墙)
```

<img src="img\端口开放stealth.jpg" alt="端口开放stealth" style="zoom:67%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.4.pcap
  ```

  <img src="img\端口开放靶机抓包stealth.jpg" alt="端口开放靶机抓包stealth" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 stealth.py
  ```

  <img src="img\端口开放python3 stealth.jpg" alt="端口开放python3 stealth" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口开放stealth抓包结果.jpg" alt="端口开放stealth抓包结果" style="zoom: 67%;" />

- nmap 复刻

  ```
  nmap -sS -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口开放nmap stealth.jpg" alt="端口开放nmap stealth" style="zoom:80%;" />

**端口关闭**

```
systemctl stop apache2
systemctl status apache2
```

![端口关闭stealth](img\端口关闭stealth.jpg)

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.5.pcap
  ```

  <img src="img\端口关闭靶机抓包stealth.jpg" alt="端口关闭靶机抓包stealth" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 stealth.py
  ```

  <img src="img\端口关闭python3 stealth.jpg" alt="端口关闭python3 stealth" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口关闭stealth抓包结果.jpg" alt="端口关闭stealth抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sS -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口关闭nmap stealth.jpg" alt="端口关闭nmap stealth" style="zoom:80%;" />

**端口过滤**

```
ufw enable && ufw deny 80/tcp（靶机）
```

<img src="img\端口过滤stealth.jpg" alt="端口过滤stealth" style="zoom:80%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.6.pcap
  ```

  <img src="img\端口过滤靶机抓包stealth.jpg" alt="端口过滤靶机抓包stealth" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 stealth.py
  ```

  <img src="img\端口过滤python3 stealth.jpg" alt="端口过滤python3 stealth" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口过滤stealth抓包结果.jpg" alt="端口过滤stealth抓包结果" style="zoom: 67%;" />

- nmap 复刻

  ```
  nmap -sS -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口过滤nmap stealth.jpg" alt="端口过滤nmap stealth" style="zoom:80%;" />



#### TCP Xmas scan

 [Xmas.py](code\Xmas.py) 

```python
from scapy.all import *

def tcp_xmas_scan(dst_ip, dst_port, timeout=10):

   
    xmas_scan_resp = sr1(IP(dst=dst_ip) / TCP(dport=dst_port, flags="FPU"), timeout=10)
    print(type(xmas_scan_resp))

    if (str(type(xmas_scan_resp)) == "<class 'NoneType'>"):
        print("Open|Filtered")

    elif (xmas_scan_resp.haslayer(TCP)):
        if (xmas_scan_resp.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif (xmas_scan_resp.haslayer(ICMP)):
        if (int(xmas_scan_resp.getlayer(ICMP).type) == 3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,13]):
            print("Filtered")
    print('finished tcp xmas scan.\n')

tcp_xmas_scan('172.16.111.121', 80)
```



**端口开放**

```
systemctl start apache2 （靶机）
systemctl status apache2 （靶机）
ufw disable (关闭防火墙)
```

<img src="img\端口开放Xmas.jpg" alt="端口开放Xmas" style="zoom:67%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.7.pcap
  ```

  <img src="img\端口开放靶机抓包Xmas.jpg" alt="端口开放靶机抓包Xmas" style="zoom: 80%;" />

- 扫描端执行代码

  ```
  sudo python3 Xmas.py
  ```

  <img src="img\端口开放python3 Xmas.jpg" alt="端口开放python3 Xmas" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口开放Xmas抓包结果.jpg" alt="端口开放Xmas抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sX -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口开放nmap Xmas.jpg" alt="端口开放nmap Xmas" style="zoom: 80%;" />

**端口关闭**

```
systemctl stop apache2
systemctl status apache2
```

<img src="img\端口关闭Xmas.jpg" alt="端口关闭Xmas" style="zoom:67%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.8.pcap
  ```

  <img src="img\端口关闭靶机抓包Xmas.jpg" alt="端口关闭靶机抓包Xmas" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 Xmas.py
  ```

  <img src="img\端口关闭python3 Xmas.jpg" alt="端口关闭python3 Xmas" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口关闭Xmas抓包结果.jpg" alt="端口关闭Xmas抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sX -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口关闭nmap Xmas.jpg" alt="端口关闭nmap Xmas" style="zoom:80%;" />

**端口过滤**

```
ufw enable && ufw deny 80/tcp（靶机）
```

<img src="img\端口过滤Xmas.jpg" alt="端口过滤Xmas" style="zoom:80%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.9.pcap
  ```

  <img src="img\端口过滤靶机抓包Xmas.jpg" alt="端口过滤靶机抓包Xmas" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 Xmas.py
  ```

  <img src="img\端口过滤python3 Xmas.jpg" alt="端口过滤python3 Xmas" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口过滤Xmas抓包结果.jpg" alt="端口过滤Xmas抓包结果" style="zoom: 67%;" />

- nmap 复刻

  ```
  nmap -sX-p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口过滤nmap Xmas.jpg" alt="端口过滤nmap Xmas" style="zoom:80%;" />

  

> Xmas --在扫描端执行Xmas.py，端口开启和过滤同时出现



#### TCP fin scan

 [fin.py](code\fin.py) 

```python
from scapy.all import *

def tcp_fin_scan(dst_ip, dst_port, dst_timeout=10):

    fin_scan_resp = sr1(IP(dst=dst_ip) / TCP(dport=dst_port, flags="F"), timeout=10)
    print(type(fin_scan_resp))

    if (str(type(fin_scan_resp)) == "<class 'NoneType'>"):
        print("Open|Filtered")
    elif (fin_scan_resp.haslayer(TCP)):
        if (fin_scan_resp.getlayer(TCP).flags == 0x14):
            print("Closed")

    elif (fin_scan_resp.haslayer(ICMP)):
        if (int(fin_scan_resp.getlayer(ICMP).type) == 3 and int(fin_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,13]):
            print("Filtered")
    print('finished tcp fin scan.\n')

tcp_fin_scan('172.16.111.121', 80)
```



**端口开放**

```
systemctl start apache2 （靶机）
systemctl status apache2 （靶机）
ufw disable (关闭防火墙)
```

<img src="img\端口开放fin.jpg" alt="端口开放fin" style="zoom: 67%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.10.pcap
  ```

  ![端口开放靶机抓包fin](img\端口开放靶机抓包fin.jpg)

- 扫描端执行代码

  ```
  sudo python3 fin.py
  ```

  ![端口开放python3 fin](img\端口开放python3 fin.jpg)

- 抓包结果

  <img src="img\端口开放fin抓包结果.jpg" alt="端口开放fin抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sF -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口开放nmap fin.jpg" alt="端口开放nmap fin" style="zoom:80%;" />

**端口关闭**

```
systemctl stop apache2
systemctl status apache2
```

<img src="img\端口关闭fin.jpg" alt="端口关闭fin" style="zoom:67%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.11.pcap
  ```

  <img src="img\端口关闭靶机抓包fin.jpg" alt="端口关闭靶机抓包fin" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 fin.py
  ```

  <img src="img\端口关闭python3 fin.jpg" alt="端口关闭python3 fin" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口关闭fin抓包结果.jpg" alt="端口关闭fin抓包结果" style="zoom: 67%;" />

- nmap 复刻

  ```
  nmap -sF -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口关闭nmap fin.jpg" alt="端口关闭nmap fin" style="zoom:80%;" />

**端口过滤**

```
ufw enable && ufw deny 80/tcp（靶机）
```

<img src="img\端口过滤fin.jpg" alt="端口过滤fin" style="zoom:80%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211012.3.pcap
  ```

  <img src="img\端口过滤靶机抓包fin.jpg" alt="端口过滤靶机抓包fin" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 fin.py
  ```

  <img src="img\端口过滤python3 fin.jpg" alt="端口过滤python3 fin" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口过滤fin抓包结果.jpg" alt="端口过滤fin抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sF -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口过滤nmap fin.jpg" alt="端口过滤nmap fin" style="zoom:80%;" />

> fin----在扫描端执行fin.py，端口开启和过滤同时出现

#### TCP null scan

 [null.py](code\null.py) 

```python
from scapy.all import *

def tcp_null_scan(dst_ip, dst_port, dst_timeout=10):

    null_scan_resp = sr1(IP(dst=dst_ip) / TCP(dport=dst_port, flags=""), timeout=10)
    print(type(null_scan_resp))

    if (str(type(null_scan_resp)) == "<class 'NoneType'>"):
        print("Open|Filtered")

    elif (null_scan_resp.haslayer(TCP)):
        if (null_scan_resp.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif (null_scan_resp.haslayer(ICMP)):
        if (int(null_scan_resp.getlayer(ICMP).type) == 3 and int(null_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,13]):
            print("Filtered")

    print('finished tcp null scan.\n')

tcp_null_scan('172.16.111.121', 80)
```



**端口开放**

```
systemctl start apache2 （靶机）
systemctl status apache2 （靶机）
ufw disable (关闭防火墙)
```

<img src="img\端口开放null.jpg" alt="端口开放null" style="zoom:67%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.13.pcap
  ```

  <img src="img\端口开放靶机抓包null.jpg" alt="端口开放靶机抓包null" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 null.py
  ```

  <img src="img\端口开放python3 null.jpg" alt="端口开放python3 null" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口开放null抓包结果.jpg" alt="端口开放null抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sN -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口开放nmap null.jpg" alt="端口开放nmap null" style="zoom:80%;" />

**端口关闭**

```
systemctl stop apache2
systemctl status apache2
```

<img src="img\端口关闭null.jpg" alt="端口关闭null" style="zoom:80%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.14.pcap
  ```

  <img src="img\端口关闭靶机抓包null.jpg" alt="端口关闭靶机抓包null" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 null.py
  ```

  <img src="img\端口关闭python3 null.jpg" alt="端口关闭python3 null" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口关闭null抓包结果.jpg" alt="端口关闭null抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sN -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口关闭nmap null.jpg" alt="端口关闭nmap null" style="zoom:80%;" />

**端口过滤**

```
ufw enable && ufw deny 80/tcp（靶机）
```

<img src="img\端口过滤null.jpg" alt="端口过滤null" style="zoom:80%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.15.pcap
  ```

  <img src="img\端口过滤靶机抓包null.jpg" alt="端口过滤靶机抓包null" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 null.py
  ```

  <img src="img\端口过滤python3 null.jpg" alt="端口过滤python3 null" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口过滤null抓包结果.jpg" alt="端口过滤null抓包结果" style="zoom: 67%;" />

- nmap 复刻

  ```
  nmap -sN -p 80 172.16.111.121（扫描端）
  ```

  <img src="img\端口过滤nmap null.jpg" alt="端口过滤nmap null" style="zoom:80%;" />

> null---在扫描端执行null.py，端口开启和过滤同时出现

#### UDP scan

 [UDP.py](code\UDP.py) 

```python
from scapy.all import *


def udp_scan(dst_ip, dst_port, dst_timeout=10):
    udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port), timeout=dst_timeout)
    print(type(udp_scan_resp))
    if (str(type(udp_scan_resp)) == "<class 'NoneType'>"):
        print("Open|Filtered")
    elif (udp_scan_resp.haslayer(UDP)):
        print("Open")
    elif(udp_scan_resp.haslayer(ICMP)):
        if(int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) == 3):
            print("Closed")
        elif(int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
            print("Filtered")
        elif(udp_scan_resp.haslayer(IP) and udp_scan_resp.getlayer(IP).proto == IP_PROTOS.udp):
            print("Open")


udp_scan('172.16.111.121', 53)
```



**端口开放**

```
systemctl start dnsmasq （靶机）
systemctl status dnsmasq （靶机）
ufw disable (关闭防火墙)
```

<img src="img\端口开放udp.jpg" alt="端口开放udp" style="zoom: 67%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.16.pcap
  ```

  <img src="img\端口开放靶机抓包udp.jpg" alt="端口开放靶机抓包udp" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 UDP.py
  ```

  <img src="img\端口开放python3 udp.jpg" alt="端口开放python3 udp" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口开放udp抓包结果.jpg" alt="端口开放udp抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sU -p 53 172.16.111.121（扫描端）
  ```

  <img src="img\端口开放nmap udp.jpg" alt="端口开放nmap udp" style="zoom:80%;" />

**端口关闭**

```
systemctl stop dnsmasq
systemctl status dnsmasq
```

<img src="img\端口关闭udp.jpg" alt="端口关闭udp" style="zoom:67%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.17.pcap
  ```

  <img src="img\端口关闭靶机抓包udp.jpg" alt="端口关闭靶机抓包udp" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 UDP.py
  ```

  <img src="img\端口关闭python3 udp.jpg" alt="端口关闭python3 udp" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口关闭udp抓包结果.jpg" alt="端口关闭udp抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sU -p 53 172.16.111.121（扫描端）
  ```

  <img src="img\端口关闭nmap udp.jpg" alt="端口关闭nmap udp" style="zoom:80%;" />

**端口过滤**

```
ufw enable && ufw deny 53/udp（靶机）
```

<img src="img\端口过滤udp.jpg" alt="端口过滤udp" style="zoom:80%;" />

- 靶机抓包

  ```
  sudo tcpdump -i eth0 -enp -w 20211010.18.pcap
  ```

  <img src="img\端口过滤靶机抓包udp.jpg" alt="端口过滤靶机抓包udp" style="zoom:80%;" />

- 扫描端执行代码

  ```
  sudo python3 UDP.py
  ```

  <img src="img\端口过滤python3 udp.jpg" alt="端口过滤python3 udp" style="zoom:80%;" />

- 抓包结果

  <img src="img\端口过滤udp抓包结果.jpg" alt="端口过滤udp抓包结果" style="zoom:67%;" />

- nmap 复刻

  ```
  nmap -sU -p 53 172.16.111.121（扫描端）
  ```

  <img src="img\端口过滤python3 udp.jpg" alt="端口过滤python3 udp" style="zoom:80%;" />

## 问题

1.namp无法监听\ufw disable 无法关闭防火墙

解决方法：sudo su 进入root权限

2.实现本机Windows与虚拟机kali拖放

<img src="img\宿主机与虚拟机之间的拖放功能实现.jpg" alt="宿主机与虚拟机之间的拖放功能实现" style="zoom: 67%;" />

## 参考资料

[2020-ns-public-LyuLumos](https://github.com/CUCCS/2020-ns-public-LyuLumos/tree/ch0x05/ch0x05)

[2020-ns-public-Loonyluna12345](https://github.com/CUCCS/2020-ns-public-Loonyluna12345/blob/chapter5/chapter5/chapter5-report.md)

[虚拟机与Windows主机共享文件](https://www.cnblogs.com/Sylon/p/11747455.html)

[2020-ns-public-chococolate](https://github.com/CUCCS/2020-ns-public-chococolate/blob/chap0x05/chap0x05/chap0x05.md)

[课本第五章](https://c4pr1c3.gitee.io/cuc-ns/chap0x05/main.html)

