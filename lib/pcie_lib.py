#
# PREBOOT
#
# GuidePoint Security LLC
#
# Threat and Attack Simulation Team
#
import sys
import os
import time
import array
import fcntl
import errno
import random
import socket
import select
import signal
from struct import pack, unpack
from abc import ABCMeta, abstractmethod

PAGE_SIZE = 0x1000

align_up = lambda x, a: ((x + a - 1) // a) * a
align_down = lambda x, a: (x // a) * a

FMT_3_NO_DATA = 0
FMT_4_NO_DATA = 1
FMT_3_DATA    = 2
FMT_4_DATA    = 3 

tlp_types = { 0x00: 'MRd32',   0x20: 'MRd64',
              0x01: 'MRdLk32', 0x21: 'MRdLk64', 
              0x40: 'MWr32',   0x60: 'MWr64',
              0x02: 'IORd',    0x42: 'IOWr',
              0x04: 'CfgRd0',  0x44: 'CfgWr0',
              0x05: 'CfgRd1',  0x45: 'CfgWr1',
              0x0A: 'Cpl',     0x4A: 'CplD',
              0x0B: 'CplLk',   0x4B: 'CplLkD' }


dev_id_decode = lambda val: ((val >> 8) & 0xff, (val >> 3) & 0x1f, (val >> 0) & 0x07)
dev_id_encode = lambda bus, dev, func: ((bus << 8) | (dev << 3) | (func << 0))
dev_id_str    = lambda bus, dev, func: '%.2x:%.2x.%x' % (bus, dev, func)


def tlp_type_name(dw0): 

    return tlp_types[(dw0 >> 24) & 0xff]


def tlp_type_from_name(name):

    for key, val in tlp_types.items():

        if val == name:

            return ((key >> 5) & 0x3), ((key >> 0) & 0x1f)


def endpoint_init(*args, **kvargs):
    return EndpointTcp(*args, **kvargs)

class Device(object):

    __metaclass__ = ABCMeta

    class Error(Exception): 

        pass

    class Timeout(Exception): 

        pass    

    @abstractmethod
    def read(self, size, timeout = None):

        pass

    @abstractmethod
    def write(self, data):

        pass

    @abstractmethod
    def close(self):

        pass


class Socket(Device):

    def __init__(self, addr):

        assert addr is not None

        self.addr = addr
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.sock.connect(addr)

    def read(self, size, timeout = None):

        ret = b''

        assert self.sock is not None
        
        # check if there's any data to receive
        fd_read, fd_write, fd_err = select.select([ self.sock ], [], [], timeout)

        if self.sock in fd_err:

            # error occurred
            raise(self.Error('Connection error'))

        if not self.sock in fd_read:

            # timeout occurred
            raise(self.Timeout('Socket read timeout'))         

        while len(ret) < size:
            
            # receive needed amount of data
            data = self.sock.recv(size - len(ret))
            if len(data) == 0:

                # connection was closed by remote host
                raise(self.Error('Connection closed')) 

            ret += data            

        return ret

    def write(self, data):

        assert self.sock is not None        

        self.sock.sendall(data)

    def close(self):

        if self.sock is not None:

            self.sock.close()
            self.sock = None


class Endpoint(object):    

    RECV_TIMEOUT = 3

    ROM_CHUNK_LEN = 0x80

    status_bus_id = lambda self, s: s & 0xffff

    # pass memory read/write requests directly to the transport
    fast_flow = False

    class ErrorNotReady(Exception): 

        pass

    class ErrorTimeout(Exception): 

        pass

    def __init__(self, bus_id = None, force = False, timeout = None):

        self.bus_id = bus_id
        self.timeout = self.RECV_TIMEOUT if timeout is None else timeout

        # check connection        
        self.ping()

        if self.bus_id is None:

            # obtain bus id from the device
            bus_id = self.get_bus_id()

            if bus_id != 0:

                self.bus_id = dev_id_decode(bus_id)

            elif not force:

                raise(self.ErrorNotReady('PCI-E endpoint is not configured by root complex yet'))  

    def get_bus_id(self):

        return self.status_bus_id(self.get_status()) 

    @abstractmethod
    def ping(self):

        pass

    @abstractmethod
    def reset(self):

        pass

    @abstractmethod
    def get_status(self):

        pass

    @abstractmethod
    def read(self):

        pass

    @abstractmethod
    def write(self, data):

        pass

    @abstractmethod
    def mem_read(self, addr, size):

        pass

    @abstractmethod
    def mem_write(self, addr, data):

        pass

    @abstractmethod
    def close(self):

        pass

    
class EndpointStream(Endpoint):

    ENV_DEVICE = 'DEVICE'

    #
    # protocol control codes
    #
    CTL_PING                = 0
    CTL_RESET               = 1
    CTL_STATUS              = 2
    CTL_TLP_SEND            = 3
    CTL_TLP_RECV            = 4
    CTL_SUCCESS             = 5
    CTL_ERROR_FAILED        = 6
    CTL_ERROR_TIMEOUT       = 7
        
    def _read(self, no_timeout = False):

        return unpack('=BB', self.device.read(1 + 1, timeout = None if no_timeout else self.timeout))

    def _write(self, *args):

        self.device.write(pack('=BB', *args))    

    def ping(self):

        # send ping request
        self._write(self.CTL_PING, 0)

        try:

            # receive reply
            code, size = self._read()

        except self.device.Timeout:

            raise(self.ErrorTimeout('Device timeout occurred'))

        assert code == self.CTL_SUCCESS and size == 0

    def reset(self):

        # send reset request
        self._write(self.CTL_RESET, 0)

        # receive reply
        code, size = self._read()

        assert code == self.CTL_SUCCESS and size == 0

    def get_status(self):

        # send get status request
        self._write(self.CTL_STATUS, 0)

        # receive reply
        code, size = self._read()

        assert code == self.CTL_SUCCESS and size == 4

        # receive reply data
        return unpack('<I', self.device.read(size, timeout = self.timeout))[0]    

    def read(self):

        ret = []

        # send read TLP request
        self._write(self.CTL_TLP_RECV, 0)

        try:

            # receive reply
            code, size = self._read()

        except self.device.Timeout:

            raise(self.ErrorTimeout('TLP read timeout occurred'))

        if code == self.CTL_ERROR_TIMEOUT:

            raise(self.ErrorTimeout('TLP read timeout occurred'))

        assert code == self.CTL_TLP_RECV
        assert size > 8 and size % 4 == 0

        # receive reply data
        data = self.device.read(size, timeout = self.timeout)

        for i in range(0, int( size / 4 ) ):

            ret.append(unpack('<I', data[i * 4 : (i + 1) * 4])[0])        

        return ret

    def write(self, data):

        assert len(data) > 2

        # TLP send request
        buff = pack('=BB', self.CTL_TLP_SEND, len(data) * 4)

        for i in range(0, len(data)):

            # send request data
            buff += pack('<I', data[i])

        self.device.write(buff)

        # receive reply
        code, size = self._read()

        assert code == self.CTL_SUCCESS and size == 0    

    def mem_read(self, addr, size):

        raise(NotImplementedError())

    def mem_write(self, addr, data):

        raise(NotImplementedError()) 


class EndpointTcp(EndpointStream):

    def __init__(self, addr : tuple, *args, **kvargs):
        # initialize TCP/IP based device
        self.device = Socket( addr = addr )

        # initialize base class
        super(EndpointTcp, self).__init__(*args, **kvargs)

class TransactionLayer(object):

    ENV_DEBUG_TLP = 'DEBUG_TLP'

    #
    # Maximum bytes of data per each MWr and MRd TLP
    #
    MEM_WR_TLP_LEN = 0x04
    MEM_RD_TLP_LEN = 0x40

    # align memory reads and writes
    MEM_ALIGN = 0x4

    mem_write_1 = lambda self, addr, v: self.mem_write(addr, pack('B', v))
    mem_write_2 = lambda self, addr, v: self.mem_write(addr, pack('H', v))
    mem_write_4 = lambda self, addr, v: self.mem_write(addr, pack('I', v))
    mem_write_8 = lambda self, addr, v: self.mem_write(addr, pack('Q', v))

    mem_read_1 = lambda self, addr: unpack('B', self.mem_read(addr, 1))[0]
    mem_read_2 = lambda self, addr: unpack('H', self.mem_read(addr, 2))[0]
    mem_read_4 = lambda self, addr: unpack('I', self.mem_read(addr, 4))[0]
    mem_read_8 = lambda self, addr: unpack('Q', self.mem_read(addr, 8))[0]

    class ErrorBadCompletion(Exception): 

        pass

    class Packet(object): 

        # bus:device.function
        src_name = lambda self, src: '%.2x:%.2x.%x' % ((src >> 8) & 0xff,
                                                       (src >> 3) & 0x1f,
                                                       (src >> 0) & 0x07)

        get_data = lambda self: pack('>' + ('I' * self.h_length), *self.data)

        def __init__(self, tlp = None):

            if tlp is not None: self.decode(tlp)

        def decode(self, tlp):
            
            self.tlp = tlp
            self.tlp_size = 1

            assert len(tlp) > 0 

            # decode TLP header
            self.h_prefix = (tlp[0] >> 31) & 0x1
            self.h_format = (tlp[0] >> 29) & 0x3
            self.h_type   = (tlp[0] >> 24) & 0x1f
            self.h_length = (tlp[0] >>  0) & 0x3ff

            type_name = tlp_type_name(tlp[0])

            if hasattr(self, 'tlp_type'):

                assert self.tlp_type == type_name

            else:

                self.tlp_type = type_name

            # TODO: TLP prefixes decoding
            assert self.h_prefix == 0

            # check TLP size
            if   self.h_format == FMT_3_NO_DATA: self.tlp_size += 2
            elif self.h_format == FMT_4_NO_DATA: self.tlp_size += 3
            elif self.h_format == FMT_3_DATA:    self.tlp_size += 2 + self.h_length
            elif self.h_format == FMT_4_DATA:    self.tlp_size += 3 + self.h_length

            assert len(tlp) == self.tlp_size            

            # determinate header length
            self.header_size = 3 if self.h_format in [ FMT_3_NO_DATA, 
                                                       FMT_3_DATA ] else 4

            self.header = tlp[0 : self.header_size]

            if self.h_format in [ FMT_3_NO_DATA, FMT_4_NO_DATA ]:

                assert len(tlp) == self.header_size

                self.data = None

            else:

                self.data = tlp[self.header_size :]        

            # decode the rest of the TLP header           
            self.h_req_id = dev_id_decode((tlp[1] >> 16) & 0xffff)

        def decode_addr(self):

            self.h_tag = (self.tlp[1] >> 8) & 0xff
            self.h_last_dw_be = (self.tlp[1] >> 4) & 0xf
            self.h_first_dw_be = (self.tlp[1] >> 0) & 0xf

            if self.header_size == 3:

                # 32-bit address
                self.addr = (self.tlp[2] & 0xfffffffc)

            elif self.header_size == 4:

                # 64-bit address
                self.addr = (self.tlp[3] & 0xfffffffc) | (self.tlp[2] << 32)

        def decode_completion(self):

            self.h_completer = dev_id_decode((self.tlp[1] >> 16) & 0xffff)
            self.h_requester = dev_id_decode((self.tlp[2] >> 16) & 0xffff)
            self.h_byte_count = (self.tlp[1] >> 0) & 0xfff
            self.h_tag = (self.tlp[2] >> 8) & 0xff

        def encode(self):

            assert self.tlp_type in tlp_types.values()            

            self.h_prefix = 0;
            self.h_format, self.h_type = tlp_type_from_name(self.tlp_type)            

            # determinate header length            
            self.header_size = 3 if self.h_format in [ FMT_3_NO_DATA, 
                                                       FMT_3_DATA ] else 4

            self.tlp = []
            self.tlp_size = self.header_size

            if self.h_format in [ FMT_3_DATA, FMT_4_DATA ]:

                self.tlp_size += self.h_length            

            self.tlp.append((self.h_prefix << 31) | \
                            (self.h_format << 29) | \
                            (self.h_type   << 24) | \
                            (self.h_length << 0))

        def encode_addr(self):

            self.h_first_dw_be = 0xf                
            self.h_last_dw_be = 0xf if self.header_size == 4 else 0

            self.tlp.append((dev_id_encode(*self.h_req_id) << 16) |
                            (self.h_tag << 8) |
                            (self.h_last_dw_be << 4) |
                            (self.h_first_dw_be << 0))

            if self.header_size == 3:                

                assert self.addr & 0xfffffffc == self.addr
                assert self.addr < 0xffffffff

                # 32-bit address
                self.tlp.append(self.addr)

            elif self.header_size == 4:

                assert self.addr & 0xfffffffffffffffc == self.addr
                assert self.addr < 0xffffffffffffffff

                # 64-bit address
                self.tlp.append(self.addr >> 32)
                self.tlp.append(self.addr & 0xffffffff)

            # update header contents
            self.header = self.tlp[0 : self.header_size]

    class PacketMRd32(Packet): 

        tlp_type = 'MRd32'

        def __init__(self, req = None, addr = None, bytes_read = None, tag = None, tlp = None):

            TransactionLayer.Packet.__init__(self, tlp = tlp)

            if tlp is None:

                self.data = None

                self.h_tag = random.randrange(0, 0xff) if tag is None else tag
                self.h_req_id, self.addr, self.bytes_read = req, addr, bytes_read

                # create raw TLP from specified arguments
                self.encode()

        def decode(self, tlp):

            # decode packet header
            TransactionLayer.Packet.decode(self, tlp)

            # decode address word
            self.decode_addr()

            self.bytes_read = self.h_length * 4

        def encode(self):

            assert self.bytes_read % 4 == 0

            self.h_length = int( self.bytes_read / 4 )

            # encode packet header
            TransactionLayer.Packet.encode(self)

            # encode address dword
            self.encode_addr()


    class PacketMWr32(Packet): 

        tlp_type = 'MWr32'

        def __init__(self, req = None, addr = None, data = None, tag = None, tlp = None):

            TransactionLayer.Packet.__init__(self, tlp = tlp)

            if tlp is None:

                self.data = data if isinstance(data, list) else [ data ]

                self.h_tag = random.randrange(0, 0xff) if tag is None else tag
                self.h_req_id, self.addr, self.bytes_write = req, addr, len(self.data) * 4

                # create raw TLP from specified arguments
                self.encode()

        def decode(self, tlp):

            # decode packet header
            TransactionLayer.Packet.decode(self, tlp)

            # decode address word
            self.decode_addr()

            self.bytes_write = self.h_length * 4

        def encode(self):

            assert self.bytes_write % 4 == 0

            self.h_length = int( self.bytes_write / 4 )

            # encode packet header
            TransactionLayer.Packet.encode(self)

            # encode address dword
            self.encode_addr()

            self.tlp += self.data


    class PacketMRd64(PacketMRd32): 

        tlp_type = 'MRd64'


    class PacketMWr64(PacketMWr32): 

        tlp_type = 'MWr64'


    class PacketCplD(Packet): 

        tlp_type = 'CplD'

        def decode(self, tlp):

            # decode packet header
            TransactionLayer.Packet.decode(self, tlp)

            # decode completion information dwords
            self.decode_completion()

    def __init__(self, *args, **kvargs):

        # initialize link layer
        self.ep = endpoint_init(*args, **kvargs)

        self.bus_id = self.ep.bus_id        

    def read(self, raw = False):

        data = self.ep.read()

        # return not decoded TLP data if needed
        if raw: return data

        name = 'Packet' + tlp_type_name(data[0])

        # create appropriate object for each TLP type or use common one
        tlp = getattr(self, name)(tlp = data) if hasattr(self, name) else \
              self.Packet(tlp = data)

        return tlp

    def write(self, data):

        # get raw data in case when Packet instance was passed
        data = data.tlp if isinstance(data, self.Packet) else data

        self.ep.write(data)    

    def bridge(self, log = False, handler = None):        

        while True:

            # read incoming TLP
            tlp = self.read()
            tlp = tlp if handler is None else handler(self, tlp)

            # forward TLP
            if tlp is not None: self.write(tlp)

    def _mem_read(self, addr, size):

        output = b''
        chunk_size, ptr = min(size, self.MEM_RD_TLP_LEN), 0  

        assert addr % self.MEM_ALIGN == 0  
        assert size % self.MEM_ALIGN == 0

        assert self.bus_id is not None

        # read memory by blocks
        while ptr < size:

            chunk_addr = addr + ptr
            
            # memory r/w TLP should reside to the single memory page
            max_chunk_size = PAGE_SIZE if chunk_addr & 0xfff == 0 else \
                             (align_up(chunk_addr, PAGE_SIZE) - chunk_addr)

            cur_chunk_size = min(chunk_size, max_chunk_size)

            # create 64-bit memory read TLP            
            tlp_tx = self.PacketMRd64(self.bus_id, chunk_addr, cur_chunk_size)

            # send TLP to the system
            self.write(tlp_tx)

            data = b''

            while len(data) < cur_chunk_size:

                # read reply
                tlp_rx = self.read()

                if not isinstance(tlp_rx, self.PacketCplD):

                    raise(self.ErrorBadCompletion('Bad MRd TLP completion received'))

                assert tlp_tx.h_tag == tlp_rx.h_tag
                
                # decode data
                data += tlp_rx.get_data()

            output += data
            ptr += cur_chunk_size

        return output    

    def _mem_write(self, addr, data):

        size, chunk_size, ptr = len(data), min(len(data), self.MEM_WR_TLP_LEN), 0  

        assert addr % self.MEM_ALIGN == 0  
        assert size % self.MEM_ALIGN == 0

        assert self.bus_id is not None

        # read memory by blocks
        while ptr < size:

            chunk_addr = addr + ptr

            # memory r/w TLP should reside to the single memory page
            max_chunk_size = PAGE_SIZE if chunk_addr & 0xfff == 0 else \
                             (align_up(chunk_addr, PAGE_SIZE) - chunk_addr)

            cur_chunk_size = min(chunk_size, max_chunk_size)

            # get data chunk as dwords list
            tlp_data = unpack('>' + ('I' * (int( cur_chunk_size / 4))), data[ptr : ptr + cur_chunk_size])

            # create 64-bit memory read TLP
            tlp = self.PacketMWr64(self.bus_id, chunk_addr, list(tlp_data))

            # send TLP to the system
            self.write(tlp)

            ptr += cur_chunk_size

    def mem_read(self, addr, size):

        if self.ep.fast_flow:

            try:

                # pass memory read request directly to the transport
                return self.ep.mem_read(addr, size)

            except OSError as why:

                # check for the TLP completion error returned by the transport
                if why.errno == errno.EFAULT:

                    raise(self.ErrorBadCompletion('mem_read() returned EFAULT'))

        align = self.MEM_ALIGN

        read_addr = align_down(addr, align)
        read_size = align_up(size, align)

        if read_addr != addr or read_size != size:

            read_size += align

        ptr = addr - read_addr

        # align memory read request by MEM_ALIGN byte boundary
        return self._mem_read(read_addr, read_size)[ptr : ptr + size]

    def mem_write(self, addr, data):

        if self.ep.fast_flow:

            # pass memory write request directly to the transport
            self.ep.mem_write(addr, data)
            return

        align, size = self.MEM_ALIGN, len(data)

        write_addr = align_down(addr, align)
        write_size = align_up(size, align)

        if write_addr != addr or write_size != size:

            write_size += align

        # read the existing data
        write_data = self._mem_read(write_addr, write_size)

        ptr = addr - write_addr
        
        # align memory write request by MEM_ALIGN byte boundary
        self._mem_write(write_addr, write_data[: ptr] + data + write_data[ptr + size :])

    def close(self):

        self.ep.close()
