#!/usr/bin/env python
#coding=utf-8

import socket
import threading 
import sys
import os
import Queue
import struct
import fcntl 
import uuid
from optparse import  OptionParser
from IPy import IP
from struct import pack, unpack
import signal
import traceback
import binascii

nThread = 10
local = []
line = ''

ARP_GRATUITOUS = 1
ARP_STANDARD = 2

def val2int(val):
    return int(''.join(['%02d'%ord(c) for c in val]), 16)


class TimeoutError(Exception):
    pass

class ArpRequest:
    def __init__(self, ipaddr, if_name, arp_type=ARP_GRATUITOUS):
        self.timeout = threading.Event()
        self.arp_type = arp_type
        self.if_ipaddr = socket.gethostbyname(socket.gethostname())
        
        self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 
                                                        socket.SOCK_RAW)
        self.socket.bind((if_name, socket.SOCK_RAW))
        
        self.ipaddr = str(ipaddr)
        
    def request(self):
        for _ in range(5):
            self._send_arp_request()
        return self._wait_response()
        
    def _send_arp_request(self):
        if self.arp_type == ARP_STANDARD: 
            saddr = pack('!4B', 
                           *[int(x) for x in self.if_ipaddr.split('.')])
        else:
            saddr = pack('!4B', 
                              *[int(x) for x in self.ipaddr.split('.')])
        frame = [
            pack('!6B', *(0xFF,) * 6),
            self.socket.getsockname()[4],
            pack('!H', 0x0806),
            
            pack('!HHBB', 0x0001, 0x0800, 0x0006, 0x0004),
            pack('!H', 0x0001),
            self.socket.getsockname()[4],
            saddr,
            pack('!6B', *(0,) * 6),
            pack('!4B', *[int(x) for x in self.ipaddr.split('.')])
        ]
        
        self.socket.send(''.join(frame))
    
    def raise_timeout(self):
        self.timeout.set()

    def _wait_response(self):
        t = threading.Timer(2, self.raise_timeout)
        t.start()
        try:
            while 0xBeef:
                if self.timeout.is_set():
                    #print '!!!!!!!!!!!!11host %s timeout occur and has been return' % self.ipaddr
                    return None
                frame = self.socket.recv(1024)
            
                proto_type = val2int(unpack('!2s', frame[12:14])[0])
                if proto_type != 0x0806: 
                    continue

                op = val2int(unpack('!2s', frame[20:22])[0])
                if op != 2:  
                    continue 

                arp_headers = frame[18:20]
                arp_headers_values = unpack('!1s1s', arp_headers)
                hw_size, pt_size = [val2int(v) for v in arp_headers_values]
                total_addresses_byte = hw_size * 2 + pt_size * 2
                arp_addrs = frame[22:22 + total_addresses_byte]
                src_hw, src_pt, dst_hw, dst_pt = unpack('!%ss%ss%ss%ss' 
                        % (hw_size, pt_size, hw_size, pt_size), arp_addrs)
                if src_pt == pack('!4B', 
                             *[int(x) for x in self.ipaddr.split('.')]):
                    return binascii.hexlify(src_hw)
        except TimeoutError:
            return None

class NoResultPending(Exception):
    '''All works requests have been processed'''
    pass

class NoWorkersAvailable(Exception):
    '''No work threads availabe to process remaining requests'''

def handle_thread_exception(request, exc_info):
    traceback.print_exception(*exc_info)


class WorkThread(threading.Thread):
    def __init__(self, requestQueue, resultQueue, poll_timeout = 5, **kwargs):
        threading.Thread.__init__(self, **kwargs)
        self._requestQueue = requestQueue
        self._resultQueue = resultQueue
        self.setDaemon(True)
        self.poll_timeout = poll_timeout
        self._dismissed = threading.Event()
        self.start()

    def run(self):
        while True:
            if self._dismissed.is_set():
                self._requestQueue.put(request)
                break
            try:
                #print 'work thread start get request'
                request = self._requestQueue.get(True, self.poll_timeout)
                #print 'get request id %d and queue size %s' %(request.requestID, str(self._requestQueue.qsize()))
            except:
                continue
            else:
                if self._dismissed.is_set():
                    break
                try:
                    result = request.callable(*request.args, **request.kwargs)
                    #print 'request id %d has return' % request.requestID
                    self._resultQueue.put((request, result))
                except:
                    request.exception = True
                    self._resultQueue.put((request, sys.exc_info()))
    def dismiss(self):
        self._dismissed.set()


class WorkRequest:
    def __init__(self, callable, args = None, kwargs = None, requestID = None, callback = None, exc_callback = handle_thread_exception):
        if requestID == None:
            self.requestID = id(self)
        else:
            try:
                self.requestID = hash(RequestID)
            except TypeError:
                raise TypeError('RequestID must be hashable')
        self.args = args or []
        self.kwargs = kwargs or {}
        self.callable = callable
        self.callback = callback
        self.exception = False
        self.exc_callback = exc_callback

class ThreadPool:
    def __init__(self, num_threads, req_size = 3, result_size = 3, poll_timeout = 5):
        self._requestQueue = Queue.Queue(req_size)
        self._resultQueue = Queue.Queue(result_size)
        self.workers = []
        self.workRequest = {}
        self.createWorkers(num_threads, poll_timeout)

    def createWorkers(self, num_threads, poll_timeout):
        for x in range(num_threads):
            self.workers.append(WorkThread(self._requestQueue, self._resultQueue, poll_timeout))

    def dismissWorkers(self, number, do_join):
        dismiss_list = []
        for i in range(min(number, self.worksize())):
            work = self.workers.pop()
            work.dismiss()
            dismiss_list.append(work)
        if do_join:
            for worker in dismiss_list:
                work.join()
        else:
            self.dismissWorkers.extend(dismiss_list)

    def joinAlldismissWorkers():
        for worker in dismissWorkers: 
            worker.join()
        dismissWorkers = []

    def putRequest(self, request, block = True, timeout = None):
        assert isinstance(request, WorkRequest)
        assert not getattr(request, 'exception', None)
        #print 'Queue size : ' + str(self._requestQueue.full())
        self._requestQueue.put(request, True, timeout)
        self.workRequest[request.requestID] = request

    def poll(self, block = False):
        while True:
            '''
            if not self.workRequest:
                raise NoResultPending
            elif block and not self.workers:
                raise NoWorkersAvailable
                '''
            try:
                #print 'start get result queue ############'
                request, result = self._resultQueue.get(block = True)
                #print 'get result queue size ' + str(self.resultQueue.qsize())
                if request.exception and request.exc_callback:
                    request.exc_callback(request, result)
                if request.callback and not (request.exception and request.exc_callback):
                    request.callback(request, result)
                #del self.workRequest[request.reuqestID]
            except:
                continue

class HostSniffer(ThreadPool):
    def __init__(self, ip_range, num_threads = 10, ifname = 'ens33'):
        ThreadPool.__init__(self, num_threads)
        self.Hosts = map(lambda x: str(x), IP(ip_range))
        self.ifname = ifname
        self.HostReq = {}

    def sniffer(self):
        self.CreateArpReq()
        
    def CreateArpReq(self):
        for Host in self.Hosts:
            #print 'Host -> %s' % Host
            request = ArpRequest(Host, self.ifname)
            workReq = WorkRequest(request.request, callback = self.HostAliveConfirm) 
            self.HostReq[workReq.requestID] = Host
            self.putRequest(workReq)

    def HostAliveConfirm(self, request, result): 
        #line = 'Host %s Alive MAC: %s' % (self.HostReq[request.requestID], result.upper())
        print 'Host %s Alive MAC: %s' % (self.HostReq[request.requestID], result.upper())
        #output.write(line);
        del self.HostReq[request.requestID]
        
    def GetLocalHostInfo(ifname):
        LocalHost = {}
        node = uuid.getnode()
        LocalHost['mac'] = uuid.UUID(int = node).hex[-12:]
        s = socket.socket(socket.AF_INET, socket.DGREAM)
        LocalHost['ip'] = socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
        return LocalHost

def OptParser():
    usage = 'Sniffer Tool\nAuthor:Lucifer Version:1.0'
    opt = OptionParser(usage)
    opt.add_option('-s', '--subnet', dest = 'subnet', type = 'string', help ='Sniffer IP Subnet Range')
    option, args = opt.parse_args()
    return option.subnet

if __name__ == '__main__':
    subnet = OptParser()
    instance = HostSniffer(subnet)
    t = threading.Thread(target = instance.poll)
    t.start()
    #output = open("a.txt", "w")
    instance.sniffer()
