import socket
import select
import struct
import crypto
import threading
import time
import logging
from configparser import ConfigParser


class Server:
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
        :param sock: socket
        :return: sock
        """
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.config.get('server', 'address'), self.config.getint('server', 'port')))
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

    def ECDH_negotiate(self, conn):
        """
        ECDH密钥协商阶段
        :param conn: socket
        :return: 协商密钥 | false
        """
        try:
            data = conn.recv(self.config.getint('server', 'buffer_size'))
        except socket.error:
            logging.exception("Exception occurred")
            return False
        encrypt = crypto.ECDH(self.config.get('encrypt', 'curve'))
        share_key = encrypt.parse_share_key_from_first_handshake_data(data)
        if share_key:
            data = encrypt.generate_first_handshake_data()
            try:
                conn.sendall(data)
            except socket.error:
                logging.exception("Exception occurred")
                return False
            return share_key
        else:
            return False

    def parse_dst_from_request(self, conn, key):
        """
        从请求中提取目标地址和端口
        :param conn: socket
        :param key: 密钥
        :return: (目标地址,端口)
        """
        try:
            data = conn.recv(self.config.getint('server', 'buffer_size'))
            data = self.cipher.decrypt(key, data)
        except ConnectionResetError:
            conn.close()
            logging.exception("Exception occurred")
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

    def request(self, conn, key):
        """
        请求阶段,满足条件则进行中继
        :param conn: socket
        :param key: 密钥
        :return:
        """
        dst = self.parse_dst_from_request(conn, key)
        sock = None
        if dst:
            sock = self.socket_init()
            try:
                sock.connect(dst)
            except socket.error:
                logging.exception("Exception occurred")
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
            response = self.cipher.encrypt(key, response)
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

    def relay(self, socket_src, socket_dst, key):
        """
        中继(relay)阶段
        :param socket_src: 来源地址
        :param socket_dst: 目标地址
        :param key: 密钥
        :return:
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
                        data = self.cipher.encrypt(key, data)
                        length = struct.pack(">I", len(data))
                        data = length + data
                        socket_src.send(data)
                    else:
                        if sock not in length_dict.keys():
                            length = struct.unpack(">I", data[0:4])[0]
                            length_dict[sock] = [length, b'']
                        length_dict[sock][1] += data
                        if length_dict[sock][0] == len(length_dict[sock][1][4:]):
                            data = self.cipher.decrypt(key, length_dict[sock][1][4:])
                            socket_dst.send(data)
                            length_dict.pop(sock)
                        elif length_dict[sock][0] < len(length_dict[sock][1][4:]):
                            data = self.cipher.decrypt(key, length_dict[sock][1][4:4 + length_dict[sock][0]])
                            socket_dst.send(data)
                            length_dict[sock][1] = length_dict[sock][1][4 + length_dict[sock][0]:]
                            length_dict[sock][0] = struct.unpack(">I", length_dict[sock][1][0:4])[0]
            except socket.error:
                logging.exception("Exception occurred")
                return

    def handshake(self, conn):
        """
        握手阶段,分为ECDH密钥协商阶段和请求中继阶段
        :param conn: socket
        :return:
        """
        share_key = self.ECDH_negotiate(conn)
        if share_key:
            key = share_key[10:42].encode()
            self.request(conn, key)

    def run(self):
        sock = self.socket_init()
        sock = self.bind_port(sock)  # socket链接到客户端
        while True:
            if threading.activeCount() > self.config.getint('server', 'threads'):  # 线程数量达到上限
                time.sleep(1)
                continue
            try:
                conn, address = sock.accept()  # conn是一个新的套接字对象,用于在客户端与服务端之间交换数据
                conn.setblocking(True)  # 设置套接字为阻塞模式
            except socket.timeout:
                continue
            except socket.error:
                logging.exception("Exception occurred")
                continue
            except TypeError:
                logging.exception("Exception occurred")
                exit(-1)
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
