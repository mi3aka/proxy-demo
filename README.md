>Demo样例,请勿用于实际环境,不足之处欢迎指点和纠正,感激不尽

## 参考链接

[理解socks5协议的工作过程和协议细节](https://wiyi.org/socks5-protocol-in-deep.html)

[写给开发人员的实用密码学](https://thiscute.world/posts/practical-cryptography-basics-5-key-exchange/)

[粘包拆包问题](https://learn.lianglianglee.com/%E4%B8%93%E6%A0%8F/Netty%20%E6%A0%B8%E5%BF%83%E5%8E%9F%E7%90%86%E5%89%96%E6%9E%90%E4%B8%8E%20RPC%20%E5%AE%9E%E8%B7%B5-%E5%AE%8C/06%20%20%E7%B2%98%E5%8C%85%E6%8B%86%E5%8C%85%E9%97%AE%E9%A2%98%EF%BC%9A%E5%A6%82%E4%BD%95%E8%8E%B7%E5%8F%96%E4%B8%80%E4%B8%AA%E5%AE%8C%E6%95%B4%E7%9A%84%E7%BD%91%E7%BB%9C%E5%8C%85%EF%BC%9F.md)

## alpha

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205231745700.png)

浏览器与远程服务器直接通过socks5连接,socks5协议的数据都是未加密的明文,因此可以被监听(不考虑应用层的加密协议,仅针对传输层)

---

>模拟172.17.0.1为浏览器,172.17.0.2为服务器

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205231950470.png)

浏览器尝试与远程服务器握手,发送`050100`表明socks5协议,仅支持无密码认证方式

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205231952390.png)

服务器选中一个方法返回给客户端,返回`0500`使用无密码认证方式

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205231959935.png)

浏览器向服务器发送请求细节,包含域名和端口`120.x.x.201:50735`

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205232001697.png)

服务器收到请求后,需要返回一个响应其中包含服务绑定的地址和端口

完成握手后,服务器开始进行中继

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205232003674.png)

浏览器向服务器发送请求,服务器收到后,解析内容,如果是TCP请求,服务器向目标建立TCP连接,将所有数据转发到目标(即`120.x.x.201:50735`)

可以看到数据被明文传输

## beta

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205231746054.png)

浏览器连接本地客户端,本地客户端与远程服务器通过socks5连接,传输数据为未加密的明文,因此可以被监听(不考虑应用层的加密协议,仅针对传输层)

与alpha的差别在于将传输流程拆分,本地客户端在浏览器与远程服务器之间起到了桥梁的作用,为后面添加加密操作打基础

## final

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205231747614.png)

浏览器连接本地客户端,本地客户端与远程服务器之间的数据传输被加密,无法被监听

---

EDCH握手示例

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205232217158.png)

客户端向服务器发送握手报文

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205232231183.png)

服务器生成共享密钥并回应握手报文

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205232232811.png)

客户端请求在经过RC4加密(密钥会该次EDCH握手协商得到的共享密钥)后发送到服务器

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205232301001.png)

服务器解密后发送到目标地址

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205232303788.png)

服务器接收目标地址的响应报文

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205232307204.png)

响应报文在经过RC4加密(密钥会该次EDCH握手协商得到的共享密钥)后发送到客户端

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205232309468.png)

客户端正确解密

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205232311586.png)

---

文件发送测试,客户端加密

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205241342985.png)

服务器解密并转发

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205241344673.png)

目的地址正确接收文件

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205241346918.png)
