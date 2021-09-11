# 实验一：基于 VirtualBox 的网络攻防基础环境搭建

## 实验目的

- 掌握 VirtualBox 虚拟机的安装与使用；
- 掌握 VirtualBox 的虚拟网络类型和按需配置；
- 掌握 VirtualBox 的虚拟硬盘多重加载；

##  实验环境

以下是本次实验需要使用的网络节点说明和主要软件举例：

- VirtualBox 虚拟机
- 攻击者主机（Attacker）：Kali Rolling 2109.2
- 网关（Gateway, GW）：Debian Buster
- 靶机（Victim）：From Sqli to shell / xp-sp3 / Kali

## 实验完成度

- [x] 靶机可以直接访问攻击者主机
- [x] 攻击者主机无法直接访问靶机
- [x] 网关可以直接访问攻击者主机和靶机
- [x] 靶机的所有对外上下行流量必须经过网关
- [x] 所有节点均可以访问互联网

## 虚拟机IP地址

| 虚拟机名称     | 虚拟机地址                                | 网段    |
| -------------- | ----------------------------------------- | ------- |
| Gateway-Debian | 192.168.56.113(172.16.111.1/172.16.222.1) |         |
| Victim-Xp-1    | 172.16.111.149                            | intnet1 |
| Victim-kali    | 172.16.111.121                            | intnet1 |
| Victim-Xp-2    | 172.16.222.118                            | intnet2 |
| Victim-Debian  | 172.16.222.101                            | intnet2 |
| Attack-kali    | 10.0.2.15                                 |         |



##  实验过程

#### 1.配置虚拟机和多重加载（各虚拟机的安装，文件皆为老师课件下载）

- ##### kali导入虚拟电脑，配置多重加载

  <img src="img\释放.jpg" alt="释放" style="zoom:50%;" />

- ##### 新建虚拟机Attack-Kali、Victim-kali利用多重加载配置

  <img src="img\Attack-Kali.jpg" alt="Attack-Kali" style="zoom:50%;" />

  <img src="img\Victim-kali.jpg" alt="Victim-kali" style="zoom:50%;" />

- ##### 新建虚拟机Gatew-Debian、Victim-Debian和配置多重加载

  <img src="img\Debian.jpg" alt="Debian" style="zoom:50%;" />

- ##### 新建虚拟机Victim-Xp-1、Victim-Xp-2和配置多重加载

  <img src="img\xp.jpg" alt="xp" style="zoom:50%;" />

#### 2.配置Gateway-Debian网关

- ##### 配置网络

  **网卡1至网卡4：内部地址转换（NAT）、仅主机（Host-only）网络、内部网络intnet1、内部网络intnet2**

  <img src="img\Gateway-Debian网络配置.jpg" alt="Gateway-Debian网络配置" style="zoom:50%;" />

  **详细界面：**

  <img src="img\网卡1.jpg" alt="网卡1" style="zoom: 50%;" />

  <img src="img\网卡2.jpg" alt="网卡2" style="zoom:50%;" />

  <img src="img\网卡3.jpg" alt="网卡3" style="zoom:50%;" />

  <img src="img\主机网络管理1.jpg" alt="主机网络管理1" style="zoom:50%;" />

  <img src="img\主机网络管理2.jpg" alt="主机网络管理2" style="zoom:50%;" />

#### 3.配置Victim-Xp-1，Victim-Xp-2，Victim-kali，Victim-Debian

- **配置网络之后启动虚拟机Gateway-Debian，root权限登录，修改密码（root/toor）查询IP地址**

  <img src="img\debian-ip.jpg" alt="debian-ip" style="zoom:50%;" />

- **设置Victim-Xp-1的网络配置，内部网络intnet1**

  <img src="img\Victim-Xp-1-intnet1.jpg" alt="Victim-Xp-1-intnet1" style="zoom:50%;" />

  <img src="img\Victim-Xp-1-ip.jpg" alt="Victim-Xp-1-ip" style="zoom:50%;" />

  <img src="img\Victim-Xp-1-ip2.jpg" alt="Victim-Xp-1-ip2" style="zoom:50%;" />

  

- **设置Victim-kali的网络配置，内部网络intnet1**

  <img src="img\Victim-kali-intnet1.jpg" alt="Victim-kali-intnet1" style="zoom:50%;" />

- **查看Victim-kali的IP地址**

  <img src="img\Victim-kali-ip.jpg" alt="Victim-kali-ip" style="zoom:50%;" />

  

- **设置Victim-Xp-2和Victim-Debian的网络配置，内部网络intnet2**

  <img src="img\Victim-Xp-2-intnet2.jpg" alt="Victim-Xp-2-intnet2" style="zoom:50%;" />

  <img src="img\Victim-Debian.jpg" alt="Victim-Debian" style="zoom:50%;" />

- **Victim-Xp-2和Victim-Debian的IP地址**

  <img src="img\Victim-Xp-2-ip.jpg" alt="Victim-Xp-2-ip" style="zoom:50%;" />

  <img src="img\Victim-Debian-ip.jpg" alt="Victim-Debian-ip" style="zoom:50%;" />

  

- **-------为了可以联通攻击者，修改Gateway-Debian的网络配置，将网卡1的网络地址转换(NAT)改为NAT网络**

  <img src="img\设置NATnetwork.jpg" alt="设置NATnetwork" style="zoom:50%;" />

  <img src="img\Gateway-Debian-网卡1更改.jpg" alt="Gateway-Debian-网卡1更改" style="zoom:50%;" />

  <img src="img\Gateway-Debian-网卡1更改2.jpg" alt="Gateway-Debian-网卡1更改2" style="zoom:50%;" />

- **设置Attack-kali网络配置**

  <img src="img\Attack-kali-Nat.jpg" alt="Attack-kali-Nat" style="zoom:50%;" />

  <img src="img\Attack-kali-Nat2.jpg" alt="Attack-kali-Nat2" style="zoom:50%;" />

- **查看Attack-kali的IP地址**

  <img src="img\Attack-kali-ip.jpg" alt="Attack-kali-ip" style="zoom:50%;" />

- **再次查看Gateway-Debian的IP地址,没有改变**

  <img src="img\Gateway-Debian-ip2.jpg" alt="Gateway-Debian-ip2" style="zoom:50%;" />

- **证明Gateway-Debian网络方式改变，Victim-Xp-2 ping Attack-kali（可以联通，则一定是NAT网络）**

  <img src="img\Victim-Xp-2-ping-Attack-kali.jpg" alt="Victim-Xp-2-ping-Attack-kali" style="zoom:50%;" />

### 4.进行任务测试

- [x] 靶机可以直接访问攻击者主机

  **靶机Victim-Xp-1访问Attack-kali---成功**

  <img src="img\靶机Victim-Xp-1访问Attack-kali.jpg" alt="靶机Victim-Xp-1访问Attack-kali" style="zoom:50%;" />

  **靶机Victim-kali 访问Attack-kali---成功**

  <img src="img\靶机Victim-kali 访问Attack-kali.jpg" alt="靶机Victim-kali 访问Attack-kali" style="zoom:50%;" />

  **靶机Victim-Xp-2访问Attack-kali---成功**

  <img src="img\靶机Victim-Xp-2访问Attack-kali.jpg" alt="靶机Victim-Xp-2访问Attack-kali" style="zoom:50%;" />

  **靶机Victim-Debian  访问Attack-kali---成功**

  <img src="img\靶机Victim-Debian  访问Attack-kali.jpg" alt="靶机Victim-Debian  访问Attack-kali" style="zoom:50%;" />

- [x] 攻击者主机无法直接访问靶机

  **Attack-kali访问靶机Victim-Xp-1**

  <img src="img\Attack-kali访问靶机Victim-Xp-1.jpg" alt="Attack-kali访问靶机Victim-Xp-1" style="zoom:50%;" />

  **Attack-kali访问靶机Victim-kali**

  <img src="img\Attack-kali访问靶机Victim-kali.jpg" alt="Attack-kali访问靶机Victim-kali" style="zoom:50%;" />

  **Attack-kali访问靶机Victim-Xp-2**

  <img src="img\Attack-kali访问靶机Victim-Xp-2.jpg" alt="Attack-kali访问靶机Victim-Xp-2" style="zoom:50%;" />

  **Attack-kali访问靶机Victim-Debian**

  <img src="img\Attack-kali访问靶机Victim-Debian.jpg" alt="Attack-kali访问靶机Victim-Debian" style="zoom:50%;" />

 - [x] 网关可以直接访问攻击者主机和靶机

  **Gateway-Debian访问Victim-Xp-1（关闭防火墙)**

  <img src="img\Gateway-Debian访问Victim-Xp-1.jpg" alt="Gateway-Debian访问Victim-Xp-1" style="zoom:50%;" />

  **Gateway-Debian访问Victim-kali**

  <img src="img\Gateway-Debian访问Victim-kali.jpg" alt="Gateway-Debian访问Victim-kali" style="zoom:50%;" />

  **Gateway-Debian访问Victim-Xp-2（关闭防火墙)**

  <img src="img\Gateway-Debian访问Victim-Xp-2.jpg" alt="Gateway-Debian访问Victim-Xp-2" style="zoom:50%;" />

  **Gateway-Debian访问Victim-Debian**

  <img src="img\Gateway-Debian访问Victim-Debian.jpg" alt="Gateway-Debian访问Victim-Debian" style="zoom:50%;" />

  **Gateway-Debian访问Attack-kali**

  <img src="img\Gateway-Debian访问Attack-kali.jpg" alt="Gateway-Debian访问Attack-kali" style="zoom:50%;" />

- [x] 靶机的所有对外上下行流量必须经过网关(以Victim-Xp-2浏览器登录校园网(cuc.edu.cn)为例)

- **在Gateway-Debian中安装tmux，方便装包程序放在后台运行**

   
  ```
  tcpdump -i enp0s10 -n -w 20210909.1.pcap
  ```

  <img src="img\在Gateway-Debian上抓包.jpg" alt="在Gateway-Debian上抓包" style="zoom:50%;" />

- **用Victim-Xp-1 ping www.taobao.com**

  <img src="img\Victim-Xp-1-taobao.jpg" alt="Victim-Xp-1-taobao" style="zoom:50%;" />

- **用Victim-Xp-2浏览器登录校园网(cuc.edu.cn)**

  <img src="img\Victim-Xp-2-cuc.jpg" alt="Victim-Xp-2-cuc" style="zoom:50%;" />

- **Ctrl C结束抓包，查看抓包结果**

  <img src="img\Debian抓包结果.jpg" alt="Debian抓包结果" style="zoom:50%;" />

- **将所抓的包拷贝到普通目录中，并下载到桌面上**

  <img src="img\拷贝.jpg" alt="拷贝" style="zoom:50%;" />

  <img src="img\桌面.jpg" alt="桌面" style="zoom:50%;" />

- **对抓到的包20210908.1.pcap进行分析**

  ## <img src="img\抓包分析.jpg" alt="抓包分析" style="zoom:50%;" />

- [x] 所有节点均可以访问互联网

  **Gateway-Debian访问www.cuc.edu.cn**

  <img src="img\Gateway-Debian访问www.cuc.edu.cn.jpg" alt="Gateway-Debian访问www.cuc.edu.cn" style="zoom:50%;" />
  
  **Victim-Xp-1访问www.cuc.edu.cn**
  
  <img src="img\Victim-Xp-1访问www.cuc.edu.cn.jpg" alt="Victim-Xp-1访问www.cuc.edu.cn" style="zoom:50%;" />
  
  **Victim-kali访问www.cuc.edu.cn**
  
  <img src="img\Victim-kali访问www.cuc.edu.cn.jpg" alt="Victim-kali访问www.cuc.edu.cn" style="zoom:50%;" />
  
  **Victim-Xp-2访问www.cuc.edu.cn**
  
  <img src="img\Victim-Xp-2访问www.cuc.edu.cn.jpg" alt="Victim-Xp-2访问www.cuc.edu.cn" style="zoom:50%;" />
  
  **Victim-Debian访问www.cuc.edu.cn**
  
  <img src="img\Victim-Debian访问www.cuc.edu.cn.jpg" alt="Victim-Debian访问www.cuc.edu.cn" style="zoom:50%;" />

  **Attack-kali访问www.cuc.edu.cn**
  
  <img src="img\Attack-kali访问www.cuc.edu.cn.jpg" alt="Attack-kali访问www.cuc.edu.cn" style="zoom:50%;" />
  
    
  
  ## 遇到的问题
  
  **问题1：在Gateway-Debian的cuc@debian上无法下载tcpdump**
  
  **解决方法：进入到root用户，下载tcpdump之后进行抓包**
  
  <img src="img\问题1.jpg" alt="问题1" style="zoom:50%;" />
  
  ## 参考文献
  
  [linux虚拟机中怎么更改用户名和密码](https://blog.csdn.net/youmatterhsp/article/details/80472103)
  
  [linux系统ssh免密钥登录配置](https://blog.csdn.net/xiaoyi23000/article/details/80597516)
  
  [VirtualBox 之虚拟硬盘多重加载](https://expoli.tech/articles/2021/06/07/1623066136894.html)
  
  
