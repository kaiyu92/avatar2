from ctypes import Structure
import ctypes
import os
import socket
import time
from typing import Union


class SockMessageQueue:
    def __init__(
        self,
        name: str,
        flags: int,
        read: bool,
        write: bool,
    ):  
        # mqueue address names start with a "/", but we don't want that here.
        self.filename = f"/tmp/avatar2.sockmq.{name.removeprefix("/")}.sock"
        print(self.filename, name, read, write)
        self.flags = flags
        self.read = read
        self.write = write
        self.connected = False
        self.preemptve_unlink = False

        # try:
        #     self.unlink()
        # except ExistentialError:
        #     pass
        # one of them has to be True for any comm to happen
        assert read or write

        # read AND write not supported right now
        assert read != write

        # if flags & O_CREAT:
        #     self.

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
        if read:
            self.sock.bind(self.filename)
            # time.sleep(5)
            self.connected = True
            # time.sleep(10)

        if write:
            # if not os.path.exists(self.filename):
            #     # try:
            #     s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM, 0)
            #     # except:
            #     #     pass
            #     s.bind(self.filename)
            #     # s.close()
            tries = 0
            while True:
                try:
                    self.sock.connect(self.filename)
                    break
                except FileNotFoundError:
                    time.sleep(0.2)
                    if tries >=50:
                        self.connected = False
                        raise ExistentialError()
                tries+=1
            self.unlink()
            self.preemptve_unlink = True
            self.connected = True

    def unlink(self):
        # We only allow the client to unlink
        if self.read:
            return
        if self.preemptve_unlink:
            # After an explicit unlink, we want to be able to catch errors again.
            self.preemptve_unlink = False
            return

        print("unlink", self.filename)
        try:
            os.unlink(self.filename)
        except FileNotFoundError:
            raise ExistentialError

    def close(self):
        self.sock.close()

    def send(self, buf: Union[bytes, Structure]):
        assert self.write
        slen = self.sock.send(buf)

        if isinstance(buf, bytes):
            buflen = len(buf)
        elif isinstance(buf, Structure):
            buflen = ctypes.sizeof(buf)
        else:
            raise NotImplementedError()
        assert slen == buflen, (slen, buflen)

    def receive(self, timeout: int):
        assert self.read
        # this will (probably?) raise if 4096 bytes is not enough
        self.sock.settimeout(timeout)
        buf = self.sock.recv(4096)
        return (buf, 1)
        # assert slen == len(buf)


class ExistentialError(Exception): ...
