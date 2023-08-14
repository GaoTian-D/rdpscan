# 使用说明
```
$ rdpscan_linux_amd64_v1/rdpscan -i 8.135.43.106:3389
[INF] 8.135.43.106:3389
TargetName: iZntwcqcvh9v6nZ
Product_Version: 6.1.7601
OS: Windows 7 Service Pack 1/Windows Server 2008 R2 Service Pack 1
NetBIOS_Domain_Name: iZntwcqcvh9v6nZ
NetBIOS_Computer_Name: iZntwcqcvh9v6nZ
DNS_Computer_Name: iZntwcqcvh9v6nZ
DNS_Domain_Name: iZntwcqcvh9v6nZ
System_Time: 2023-08-14 19:18:38

[INF] 读取待扫描源完成, 总 IP 数 1
```
# 识别原理

## 连接初始化
1. 客户端通过向服务器发送 `x.224 Connection Request PDU`  启动连接请求
2. 服务器使用 `X.224 Connection Confirm PDU` 进行响应

## X.224 Connection Request PDU 说明
> [微软官方文档](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10)

示例的 X.224 Connection Request PDU
```
 00000000 03 00 00 2c 27 e0 00 00 00 00 00 43 6f 6f 6b 69     ...,'......Cooki
 00000010 65 3a 20 6d 73 74 73 68 61 73 68 3d 65 6c 74 6f     e: mstshash=elto
 00000020 6e 73 0d 0a 01 00 08 00 00 00 00 00                 ns..........
```

### tpktHeader(4 字节)
```
 03 -> TPKT Header: version = 3
 00 -> TPKT Header: Reserved = 0
 00 -> TPKT Header: Packet length - high part
 2c -> TPKT Header: Packet length - low part (total = 44 bytes)
```

### x224Crq(7 字节)

```
 27 -> X.224: Length indicator (39 bytes)
 e0 -> X.224: Type (high nibble) = 0xe = CR TPDU; credit (low nibble) = 0
 00 00 -> X.224: Destination reference = 0 目的端口, 根据文档全 0
 00 00 -> X.224: Source reference = 0  源端口, 根据文档全 0
 00 -> X.224: Class and options = 0 , 根据文档全 0
```
- Length indicator 表示 `TPDU` 头部的长度, 最大值 254，此处等于 44 - 5 = 39
- Type 1111，高半字节是 **e**，表示是 CR 连接请求，Credit 信号量，也就是 CDT，用于流量控制
- Destination reference 目的端口
- Source reference 源端口
- Class and options 类别选项

### routingToken (variable)
```
 43 6f 6f 6b 69 65 3a 20 6d 73 74 73 68 61 73 68 
 3d 65 6c 74 6f 6e 73 -> "Cookie: mstshash=eltons"
```
Cookie 终结符 `0x0D0A`
```
 0d0a -> Cookie terminator sequence
```
routingToken 包含一个 cookie 变量，格式 `Cookie: mstshash=某个标识串`


### rdpNegReq(8 字节, 可选)

基本固定

```
 01 -> RDP_NEG_REQ::type (TYPE_RDP_NEG_REQ)
 00 -> RDP_NEG_REQ::flags (0)
 08 00 -> RDP_NEG_REQ::length (8 bytes)
 00 00 00 00 -> RDP_NEG_REQ::requestedProtocols (PROTOCOL_RDP)
```

### rdpCorrelationInfo(36 字节, 可选)
略

## X.224 Connection Confirm PDU 说明
> [微软官方文档](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/13757f8f-66db-4273-9d2c-385c33b1e483)

示例的 X.224 Connection Confirm PDU
```
 00000000 03 00 00 13 0e d0 00 00 12 34 00 02 00 08 00 00 .........4......
 00000010 00 00 00                                        ...
```

### tpktHeader(4 字节)
```
 03 -> TPKT Header: version = 3
 00 -> TPKT Header: Reserved = 0
 00 -> TPKT Header: Packet length - high part
 13 -> TPKT Header: Packet length - low part (total = 19 bytes)
```

### x224Ccf(7 字节)


```
 0e -> X.224: Length indicator (14 bytes) 
 d0 -> X.224: Type (high nibble) = 0xd = CC TPDU; credit (low nibble) = 0
 00 00 -> X.224: Destination reference = 0
 12 34 -> X.224: Source reference = 0x1234 (bogus value)
 00 -> X.224: Class and options = 0
```

- Length indicator 表示 `TPDU` 头部的长度, 最大值 254，此处等于 19 - 5 = 14
- Type 1101 高半字节是 **d**，表示是 CC 连接确认，Credit 信号量，也就是 CDT，用于流量控制
- Destination reference 目的端口 
- Source reference 源端口
- Class and options 类别选项

### rdpNegData(8 字节, 可选)
```
 02 -> RDP_NEG_RSP::type (TYPE_RDP_NEG_RSP)
 00 -> RDP_NEG_RSP::flags (0)
 08 00 -> RDP_NEG_RSP::length (8 bytes)
 00 00 00 00 -> RDP_NEG_RSP::selectedProtocol (PROTOCOL_RDP)
```
# 附录
> 传输单元 TPDU 参考图

![TPDU Code](/images/1.png)


TP0 ~ TP4 表示 OSI/RM 模型中的 5 类传输协议，协议复杂性依次递增
- 0 实现分段和重组
- 1 实现分段和重组, 差错恢复
- 2 实现分段和重组, 多路复用和解除复用
- 3 实现分段和重组, 差错恢复, 多路复用和解除复用
- 4 实现分段和重组, 差错恢复, 多路复用和解除复用, 差错检测

X.224 是强制实现 TP0 的，RDP 中采用 `Class 0` X.224

# Reference

https://xz.aliyun.com/t/11978

https://cloud.tencent.com/developer/article/1947969

https://nosec.org/home/detail/5084.html

https://cloud.tencent.com/developer/article/1888905

https://atsud0.me/2022/03/07/【域渗透】浅淡NTLM-内网小白的NTLM学习笔记/