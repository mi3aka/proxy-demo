import socket
import select
import crypto
import threading
import time
import logging
import struct
from configparser import ConfigParser


class Local:
    def __init__(self, config):
        self.config = config
        self.cipher = crypto.Cipher()
        logging.basicConfig(filename=self.config.get('log', 'filename'), filemode="w", format="%(asctime)s %(name)s:%(levelname)s:%(message)s", datefmt="%Y-%M-%d %H:%M:%S", level=logging.ERROR)

    def socket_init(self):
        """
        socket初始化
        :return: sock
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.getint('server', 'timeout'))
        except socket.error:
            logging.exception("Failed to init socket")
            exit(-1)
        return sock

    def bind_port(self, sock):
        """
        绑定端口
        :param sock:socket
        :return: sock
        """
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.config.get('local', 'address'), self.config.getint('local', 'port')))
        except socket.error:
            logging.exception("Failed to bind port")
            sock.close()
            exit(-1)
        try:
            sock.listen(128)  # 启动一个服务器用于接受连接并手动设置连接队列的大小即backlog,内核中的默认值为512
        except socket.error:
            logging.exception("Failed to listen")
            sock.close()
            exit(-1)
        return sock

    def negotiate_get_method(self, conn):
        """
        协商阶段获取认证方法,并检查是否支持免认证方式
        :param conn: socket
        :return: b'\xff' | b'\x00'
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

    def local_negotiate(self, conn):
        """
        本地协商阶段,尝试使用免认证方式
        :param conn: socket
        :return: 是否支持免认证方式
        """
        method = self.negotiate_get_method(conn)
        if method != b'\x00':
            return False
        reply = b'\x05\x00'
        try:
            conn.sendall(reply)
        except socket.error:
            logging.exception("Exception occurred")
            return False
        return True

    def parse_data_from_request(self, conn):
        """
        从请求中提取数据并检查数据是否符合格式要求
        :param conn: socket
        :return: 原始数据
        """
        try:
            data = conn.recv(self.config.getint('server', 'buffer_size'))
        except ConnectionResetError:
            conn.close()
            logging.exception("Exception occurred")
            return False
        if data[0:3] != b'\x05\x01\x00':  # 版本号为5,CONNECT请求为0x01,0x00为保留字
            return False
        return data

    def remote_handshake(self):
        """
        远程服务器握手
        :return: (加密密钥,socket)
        """
        sock = self.socket_init()
        try:
            sock.connect((self.config.get('local', 'remote'), self.config.getint('server', 'port')))
            encrypt = crypto.ECDH(self.config.get('encrypt', 'curve'))  # ECDH密钥协商
            data = encrypt.generate_first_handshake_data()
            sock.send(data)
            data = sock.recv(self.config.getint('server', 'buffer_size'))
            share_key = encrypt.parse_share_key_from_first_handshake_data(data)
            if share_key:
                key = share_key[10:42].encode()
            else:
                return
        except socket.error:
            logging.exception("Exception occurred")
            return
        return key, sock

    def relay(self, socket_src, socket_dst, key):
        """
        中继(relay)阶段
        :param socket_src: 源地址
        :param socket_dst: 目标地址
        :param key: 加密密钥
        """
        length_dict = {}
        while True:
            try:
                rlist, wlist, xlist = select.select([socket_src, socket_dst], [], [])
            except select.error:
                logging.exception("Exception occurred")
                return
            if not rlist:
                continue
            try:
                for sock in rlist:
                    data = sock.recv(self.config.getint('server', 'buffer_size'))
                    if data == b'':
                        return
                    if sock is socket_dst:
                        if sock not in length_dict.keys():
                            length = struct.unpack(">I", data[0:4])[0]
                            length_dict[sock] = [length, b'']
                        length_dict[sock][1] += data
                        if length_dict[sock][0] == len(length_dict[sock][1][4:]):
                            data = self.cipher.decrypt(key, length_dict[sock][1][4:])
                            socket_src.send(data)
                            length_dict.pop(sock)
                        elif length_dict[sock][0] < len(length_dict[sock][1][4:]):
                            data = self.cipher.decrypt(key, length_dict[sock][1][4:4 + length_dict[sock][0]])
                            socket_src.send(data)
                            length_dict[sock][1] = length_dict[sock][1][4 + length_dict[sock][0]:]
                            length_dict[sock][0] = struct.unpack(">I", length_dict[sock][1][0:4])[0]
                    else:
                        data = self.cipher.encrypt(key, data)
                        length = struct.pack(">I", len(data))
                        data = length + data
                        socket_dst.send(data)
            except socket.error:
                logging.exception("Exception occurred")
                return

    def request(self, conn):
        """
        请求阶段,满足条件则进行中继
        :param conn: socket
        """
        data = self.parse_data_from_request(conn)
        sock = None
        if data:
            try:
                key, sock = self.remote_handshake()  # 远程服务器握手并进行ECDH密钥协商
            except TypeError:
                logging.exception("Exception occurred")
                return
            try:
                send_data = self.cipher.encrypt(key, data)
                sock.send(send_data)  # 将请求转发到远程服务器
                response = sock.recv(self.config.getint('server', 'buffer_size'))  # todo
                response = self.cipher.decrypt(key, response)
                if response[0:4] != b'\x05\x00\x00\x01':
                    return
            except socket.error:
                logging.exception("Exception occurred")
                return
        if not data:
            rep = b'\x01'  # 无法初始化SOCKS服务
        else:
            rep = b'\x00'  # 初始化完成
        bnd = b'\x00\x00\x00\x00\x00\x00'
        response = b'\x05' + rep + b'\x00' + b'\x01' + bnd
        try:
            conn.sendall(response)
        except socket.error:
            logging.exception("Exception occurred")
            conn.close()
            return
        if rep == b'\x00':
            self.relay(conn, sock, key)
        if conn:
            conn.close()
        if sock:
            sock.close()

    def local_handshake(self, conn):
        """
        本地握手阶段,包含本地协商和请求中继阶段
        :param conn: socket
        """
        if self.local_negotiate(conn):
            self.request(conn)

    def run(self):
        sock = self.socket_init()
        sock = self.bind_port(sock)
        while True:
            if threading.activeCount() > self.config.getint('server', 'threads'):  # 线程数量达到上限
                time.sleep(1)
                continue
            try:
                conn, address = sock.accept()  # conn是一个新的套接字对象,用于在local和浏览器之间交换数据
                conn.setblocking(True)  # 设置套接字为阻塞模式
            except socket.timeout:
                continue
            except socket.error:
                logging.exception("Exception occurred")
                continue
            except TypeError:
                logging.exception("Exception occurred")
                exit(-1)
            thread = threading.Thread(target=self.local_handshake, args=(conn,))
            thread.start()
        sock.close()


def main():
    config = ConfigParser()
    config.read('config.ini')
    local = Local(config)
    local.run()


if __name__ == '__main__':
    main()
