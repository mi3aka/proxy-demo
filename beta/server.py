import sys
import socket
import select
import struct
import threading
import time
from configparser import ConfigParser


class Server:
    def __init__(self, config):
        self.config = config

    def socket_init(self):
        """
        socket初始化
        :return: sock
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.getint('server', 'timeout'))
        except socket.error as err:
            print("\033[31mFailed to init socket\033[0m")
            sys.exit(-1)
        return sock

    def bind_port(self, sock):
        """
        绑定端口
        :param sock:
        :return: sock
        """
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.config.get('server', 'address'), self.config.getint('server', 'port')))
        except socket.error as err:
            print("\033[31mFailed to bind port\033[0m")
            sock.close()
            sys.exit(-1)
        try:
            sock.listen(128)  # 启动一个服务器用于接受连接并手动设置连接队列的大小即backlog,内核中的默认值为512
        except socket.error as err:
            print("\033[31mFailed to listen\033[0m")
            sock.close()
            sys.exit(-1)
        return sock

    def negotiate_get_method(self, conn):
        """
        协商阶段获取认证方法,并检查是否支持免认证方式
        :param conn:
        :return:
        """
        try:
            data = conn.recv(self.config.getint('server', 'buffer_size'))
        except socket.error:
            return b'\xff'
        if b'\x05' != data[0:1]:
            return b'\xff'
        nmethods = data[1]
        methods = data[2:]
        if len(methods) != nmethods:
            return b'\xff'
        for method in methods:
            if method == 0:
                return b'\x00'
        return b'\xff'

    def negotiate(self, conn):
        """
        协商阶段,尝试使用免认证方式
        :param conn:
        :return:
        """
        method = self.negotiate_get_method(conn)
        if method != b'\x00':
            return False
        reply = b'\x05\x00'
        try:
            conn.sendall(reply)
        except socket.error:
            # error
            return False
        return True

    def parse_dst_from_request(self, conn):
        """
        从请求中提取目标地址和端口
        :param conn:
        :return:
        """
        try:
            data = conn.recv(self.config.getint('server', 'buffer_size'))
        except ConnectionResetError:
            conn.close()
            # error
            return False
        if data[0:3] != b'\x05\x01\x00':  # 版本号为5,CONNECT请求为0x01,0x00为保留字
            return False
        if data[3:4] == b'\x01':  # ATYP检查,1为ipv4
            addr = socket.inet_ntoa(data[4:8])  # addr是一个4字节的ipv4地址,inet_ntoa后得到10.11.12.13
            port = struct.unpack('>H', data[8:10])[0]  # 端口号是一个两字节的大端无符号整数
        elif data[3:4] == b'\x03':  # ATYP检查,3为域名
            addr_length = data[4]
            addr = data[5: 5 + addr_length]  # addr是一个可变长度字符串,以1字节长度开头,后跟最多255字节的域名
            port = struct.unpack('>H', data[5 + addr_length:7 + addr_length])[0]
        else:
            return False
        return addr, port

    def request(self, conn):
        """
        请求阶段
        :param conn:
        :return:
        """
        dst = self.parse_dst_from_request(conn)
        sock = None
        if dst:
            sock = self.socket_init()
            try:
                sock.connect(dst)
            except socket.error as err:
                # error
                return
        if not dst:
            rep = b'\x01'  # 无法初始化SOCKS服务
            bnd = b'\x00\x00\x00\x00\x00\x00'
        else:
            rep = b'\x00'  # 初始化完成
            bnd = socket.inet_aton(sock.getsockname()[0])  # 绑定地址
            bnd += struct.pack(">H", sock.getsockname()[1])  # 绑定端口
        response = b'\x05' + rep + b'\x00' + b'\x01' + bnd
        try:
            conn.sendall(response)
        except socket.error:
            conn.close()
            return
        if rep == b'\x00':
            self.relay(conn, sock)
        if conn:
            conn.close()
        if sock:
            sock.close()

    def relay(self, socket_src, socket_dst):
        """
        中继(relay)阶段
        :param socket_src:
        :param socket_dst:
        :return:
        """
        while True:
            try:
                rlist, wlist, xlist = select.select([socket_src, socket_dst], [], [])
            except select.error as err:
                # error
                return
            if not rlist:
                continue
            try:
                for sock in rlist:
                    data = sock.recv(self.config.getint('server', 'buffer_size'))
                    if data == b'':
                        return
                    if sock is socket_dst:
                        socket_src.send(data)
                    else:
                        socket_dst.send(data)
            except socket.error as err:
                # error
                return

    def handshake(self, conn):
        """
        握手阶段,包含协商和子协商阶段,子协商阶段因为不需要验证因此没有实现
        :param conn:
        :return:
        """
        if self.negotiate(conn):
            self.request(conn)

    def run(self):
        sock = self.socket_init()
        sock = self.bind_port(sock)  # socket链接到客户端
        while True:
            if threading.activeCount() > self.config.getint('server', 'threads'):  # 线程数量达到上限
                time.sleep(1)
                continue
            try:
                conn, address = sock.accept()  # conn是一个新的套接字对象,用于在客户端与服务端之间交换数据
                conn.setblocking(True)  # 设置套接字为阻塞模式,等待所有数据都被拷贝到发送缓冲区才会返回
            except socket.timeout:
                continue
            except socket.error:
                # error
                continue
            except TypeError:
                # error
                sys.exit(-1)
            thread = threading.Thread(target=self.handshake, args=(conn,))
            thread.start()
        sock.close()


def main():
    config = ConfigParser()
    config.read('config.ini')
    server = Server(config)
    server.run()


if __name__ == '__main__':
    main()
