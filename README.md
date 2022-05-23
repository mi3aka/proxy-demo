## alpha

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205231745700.png)

浏览器与远程服务器直接通过socks5连接,socks5协议的数据都是未加密的明文,因此可以被监听



## beta

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205231746054.png)

浏览器连接本地客户端,本地客户端与远程服务器通过socks5连接,传输数据为未加密的明文,因此可以被监听




## final

![](https://cdn.jsdelivr.net/gh/AMDyesIntelno/PicGoImg@master/202205231747614.png)

浏览器连接本地客户端,本地客户端与远程服务器之间的数据传输被加密,无法被监听
