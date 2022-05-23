>Demo样例,请勿用于实际环境,不足之处欢迎指点和纠正,感激不尽

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

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205232217158.png)
