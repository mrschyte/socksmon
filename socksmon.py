from twisted.internet import reactor, protocol, ssl
from twisted.internet.threads import deferToThread
from twisted.python.modules import getModule           
from twisted.protocols.socks import SOCKSv4Factory, SOCKSv4, SOCKSv4Outgoing
from twisted.application import internet, service
from twisted.web import server, resource

import logging
import threading
import requests, sys
import socket
import queue

logger = logging.Logger(__name__)

class Dispatcher(object):
    def __init__(self, webserver, webproxy):
        self.webserver = webserver
        self.webproxy = webproxy

    def onResponseReceived(self, peer, is_ssl, data):
        try:
            print('<- {}:{}'.format(peer.host, peer.port))
            if is_ssl:
                request_type = 'CRYPT'
            else:
                request_type = 'PLAIN'
            resp = requests.post('{}/{}:{}/RESPONSE/{}'.format(
                self.webserver, peer.host, peer.port, request_type),
                proxies=self.webproxy, data=data)
            return resp.content
        except Exception as ex:
            print(ex)

    def onRequestReceived(self, peer, is_ssl, data):
        try:
            print('-> {}:{}'.format(peer.host, peer.port))
            if is_ssl:
                request_type = 'CRYPT'
            else:
                request_type = 'PLAIN'
            resp = requests.post('{}/{}:{}/REQUEST/{}'.format(
                self.webserver, peer.host, peer.port, request_type),
                proxies=self.webproxy, data=data)
            return resp.content
        except Exception as ex:
            print(ex)

class MySOCKSv4Outgoing(SOCKSv4Outgoing):
    def __init__(self, socks):
        SOCKSv4Outgoing.__init__(self, socks)
        self.request_queue = ConcurrentQueue()
        self.response_queue = ConcurrentQueue()
        self.is_ssl = False

    def sslpeekcb(self, is_ssl):
        try:
            self.is_ssl = is_ssl
            if is_ssl:
                self.transport.startTLS(self.socks.factory.sslcert.options())
                self.socks.transport.startTLS(self.socks.factory.sslcert.options())
            self.socks.transport.socket.setblocking(0)
            self.transport.socket.setblocking(0)
            self.socks.transport.resumeProducing()
            self.transport.resumeProducing()
        except Exception as ex:
            print(ex)

    def do_sslpeek(self):
        try:
            packet = self.socks.transport.socket.recv(self.socks.bufsize, socket.MSG_PEEK)
            if packet.startswith(b'\x16\x03'):
                return True
            return False
        except Exception as ex:
            print(ex)

    def connectionMade(self):
        SOCKSv4Outgoing.connectionMade(self)
        self.socks.transport.pauseProducing()
        self.transport.pauseProducing()
        self.socks.transport.socket.setblocking(1)
        self.transport.socket.setblocking(1)
        deferred = deferToThread(self.do_sslpeek)
        deferred.addCallback(self.sslpeekcb)

    def do_receive(self, data, index):
        try:
            self.response_queue.set(index, data)
            self.response_queue.evict()
        except Exception as ex:
            print(ex)

    def do_write(self, data, index):
        try:
            self.request_queue.set(index, data)
            self.request_queue.evict()
        except Exception as ex:
            print(ex)

    def dataReceived(self, data):
        index = self.response_queue.append(lambda result: SOCKSv4Outgoing.dataReceived(self, result))
        deferred = deferToThread(self.socks.factory.dispatcher.onResponseReceived, self.transport.getPeer(), self.is_ssl, data)
        deferred.addCallback(lambda result: self.do_receive(result, index))

    def write(self, data):
        index = self.request_queue.append(lambda result: SOCKSv4Outgoing.write(self, result))
        deferred = deferToThread(self.socks.factory.dispatcher.onRequestReceived, self.transport.getPeer(), self.is_ssl, data)
        deferred.addCallback(lambda result: self.do_write(result, index))

class MySOCKSv4Factory(SOCKSv4Factory):
    def __init__(self, webserver, webproxy, sslcert, logging=None):
        self.dispatcher = Dispatcher(webserver, {
            "http": webproxy, "https": webproxy
        })
        self.webserver = webserver
        self.webproxy = webproxy
        self.sslcert = sslcert
        self.logging = logging
    
    def buildProtocol(self, addr):
        return MySOCKSv4(factory=self, reactor=reactor)

class MySOCKSv4(SOCKSv4):
    DEFAULT_BUFSIZE = 4096

    def __init__(self, factory, reactor=reactor):
        SOCKSv4.__init__(self, factory.logging, reactor)
        self.bufsize = self.DEFAULT_BUFSIZE
        self.factory = factory

    def connectClass(self, host, port, klass, *args):
        import ssl

        if klass == SOCKSv4Outgoing:
            return protocol.ClientCreator(reactor, MySOCKSv4Outgoing, *args).connectTCP(host, port)

        return protocol.ClientCreator(reactor, klass, *args).connectTCP(host, port)

class ConcurrentQueue(object):
    def __init__(self):
        self.values = {}
        self.lock = threading.Lock()
        self.queue = queue.deque()
        self.index = 0

    def append(self, callback):
        with self.lock:
            temp = self.index
            self.queue.append((temp, callback))
            self.index = self.index + 1
            return temp

    def set(self, index, value):
        with self.lock:
            self.values[index] = value

    def evict(self):
        with self.lock:
            beglen = len(self.queue)
            while len(self.queue) > 0:
                index, callback = self.queue[0]
                if index in self.values:
                    callback(self.values[index])
                    del self.values[index]
                    self.queue.popleft()
                else:
                    break

class WebEchoService(resource.Resource):
    isLeaf = True
    def render_GET(self, request):
        return "<html>socksmon</html>"

    def render_POST(self, request):
        return request.content.read()

def main():
    with open('/tmp/server.pem', 'rb') as fp:
        certData = fp.read()
    sslcert = ssl.PrivateCertificate.loadPEM(certData)

    logging.basicConfig(level=logging.INFO)

    socks = MySOCKSv4Factory("http://127.0.0.1:2357", "http://127.0.0.1:8080", sslcert)
    socks.protocol = MySOCKSv4

    srv = service.MultiService()
    srv.addService(internet.TCPServer(9050, socks))
    srv.addService(internet.TCPServer(2357, server.Site(WebEchoService())))

    application = service.Application("Receive Request")
    srv.setServiceParent(application)
    srv.startService()
    reactor.run()

if __name__ == '__main__':
    main()
