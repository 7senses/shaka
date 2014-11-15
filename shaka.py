import socket
import json
import sys, traceback

class http_parser:
    def __init__(self, sfhttp, is_client = True):
        self.__METHOD  = 0
        self.__RESP    = 1
        self.__HEADER  = 2
        self.__BODY    = 3
        self.__TRAILER = 4
        self.__CHUNK_LEN  = 5
        self.__CHUNK_BODY = 6
        self.__CHUNK_END  = 7

        self._sfhttp = sfhttp
        self._is_client = is_client

        if is_client:
            self._state = self.__METHOD
        else:
            self._state = self.__RESP

        self._data = []
        self.result = []

        self._ip        = ''
        self._port      = ''
        self._peer_ip   = ''
        self._peer_port = ''
        self._method    = {}
        self._response  = {}
        self._resp      = {}
        self._header    = {}
        self._trailer   = {}
        self._length    = 0
        self._remain    = 0

        self.__is_error = False

    def in_data(self, data, header):
        if self.__is_error:
            return

        if self._ip == '' or self._port == '':
            if header['from'] == '1':
                self._ip   = header['ip1']
                self._port = header['port1']
                self._peer_ip   = header['ip2']
                self._peer_port = header['port2']
            elif header['from'] == '2':
                self._ip   = header['ip2']
                self._port = header['port2']
                self._peer_ip   = header['ip1']
                self._peer_port = header['port1']

        self._data.append(data)

        try:
            self._parse(header)
        except Exception:
            self.__is_error = True

            print('parse error:', file=sys.stderr)

            exc_type, exc_value, exc_traceback = sys.exc_info()
            print("*** extract_tb:", file=sys.stderr)
            print(repr(traceback.extract_tb(exc_traceback)), file=sys.stderr)
            print("*** format_tb:", file=sys.stderr)
            print(repr(traceback.format_tb(exc_traceback)), file=sys.stderr)
            print("*** tb_lineno:", exc_traceback.tb_lineno, file=sys.stderr)

    def _push_data(self):
        result = {}

        if self._is_client:
            if self._method == {}:
                self.__is_error = True
                return
            result['method'] = self._method
        else:
            if self._response == {}:
                self.__is_error = True
                return
            result['response'] = self._response

        result['header']  = self._header
        result['trailer'] = self._trailer
        result['ip']      = self._ip
        result['port']    = self._port

        self.result.append(result)

        self._method   = {}
        self._response = {}
        self._resp     = {}
        self._header   = {}
        self._trailer  = {}
        self._length   = 0
        self._remain   = 0

    def _parse(self, header):
        while True:
            if self._state == self.__METHOD:
                if not self._parse_method():
                    break
            elif self._state == self.__RESP:
                if not self._parse_response():
                    break
            elif self._state == self.__HEADER:
                if not self._parse_header(header):
                    break
            elif self._state == self.__BODY:
                self._skip_body()
                if self._remain > 0:
                    break
            elif self._state == self.__CHUNK_LEN:
                if not self._parse_chunk_len():
                    break
            elif self._state == self.__CHUNK_BODY:
                self._skip_body()
                if self._remain > 0:
                    break

                self._state = self.__CHUNK_LEN
            elif self._state == self.__CHUNK_END:
                self._skip_body()
                if self._remain > 0:
                    break

                self._state = self.__TRAILER
            else:
                break

    def _parse_chunk_len(self):
        (result, line) = self._read_line()

        if result:
            self._remain = int(line.split(b';')[0], 16) + 2
            self._state = self.__CHUNK_BODY

            if self._remain == 2:
                self._state = self.__CHUNK_END
            return True
        else:
            return False

    def _parse_trailer(self):
        (result, line) = self._read_line()

        if result:
            if len(line) == 0:
                if self._is_client:
                    self._state = self.__METHOD
                else:
                    self._state = self.__RESP
            else:
                sp = line.split(b': ')

                val = (b': '.join(sp[1:])).decode('utf-8')
                val = val.strip()

                self._trailer[sp[0].decode('utf-8')] = val
            return True
        else:
            return False

    def _parse_method(self):
        (result, line) = self._read_line()

        if result:
            sp = line.split(b' ')

            self._method['method'] = sp[0].decode('utf-8')
            self._method['uri']    = sp[1].decode('utf-8')
            self._method['ver']    = sp[2].decode('utf-8')

            self._state = self.__HEADER
            return True
        else:
            return False

    def _parse_response(self):
        (result, line) = self._read_line()

        if result:
            sp = line.split(b' ')

            self._response['ver']  = sp[0].decode('utf-8')
            self._response['code'] = sp[1].decode('utf-8')
            self._response['msg']  = (b' '.join(sp[2:])).decode('utf-8')

            self._state = self.__HEADER
            return True
        else:
            return False

    def _parse_header(self, sftap_header):
        (result, line) = self._read_line()

        if result:
            if line == b'':
                if 'content-length' in self._header:
                    self._remain = int(self._header['content-length'])

                    if self._remain > 0:
                        self._state = self.__BODY
                    elif ('transfer-encoding' in self._header and
                          self._header['transfer-encoding'].lower() == 'chunked'):
                        self._state = self.__CHUNK_LEN
                    elif self._is_client:
                        self._push_data()
                        self._state = self.__METHOD
                    else:
                        self._push_data()
                        self._state = self.__RESP
                elif ('transfer-encoding' in self._header and
                      self._header['transfer-encoding'].lower() == 'chunked'):

                    self._state = self.__CHUNK_LEN
                elif self._is_client:
                    self._push_data()
                    self._state = self.__METHOD
                else:
                    self._push_data()
                    self._state = self.__RESP
            else:
                sp = line.split(b': ')

                val = (b': '.join(sp[1:])).decode('utf-8')
                val = val.strip()

                ctype = sp[0].decode('utf-8').lower()
                if ctype == 'content-type' and val.split('/')[0] == 'video':
                    self._sfhttp.input_video(val, sftap_header,
                                             self._ip, self._port,
                                             self._peer_ip, self._peer_port)

                self._header[sp[0].decode('utf-8').lower()] = val

            return True
        else:
            return False

    def _skip_body(self):
        while len(self._data) > 0:
            num = sum([len(x) for x in self._data[0]])
            if num <= self._remain:
                self._data.pop(0)
                self._remain -= num

                if self._remain == 0:
                    if self._is_client:
                        self._push_data()
                        self._state = self.__METHOD
                    else:
                        self._push_data()
                        self._state = self.__RESP
            else:
                while True:
                    num = len(self._data[0][0])
                    if num <= self._remain:
                        self._data[0].pop(0)
                        self._remain -= num
                    else:
                        self._data[0][0] = self._data[0][0][self._remain:]
                        self._remain = 0

                    if self._remain == 0:
                        if self._state == self.__BODY:
                            if self._is_client:
                                self._push_data()
                                self._state = self.__METHOD
                            else:
                                self._push_data()
                                self._state = self.__RESP

                        return

    def _read_line(self):
        line = b''
        for i, v in enumerate(self._data):
            for j, buf in enumerate(v):
                idx = buf.find(b'\n')
                if idx >= 0:
                    line += buf[:idx].rstrip()

                    self._data[i] = v[j:]

                    suffix = buf[idx + 1:]

                    if len(suffix) > 0:
                        self._data[i][0] = suffix
                    else:
                        self._data[i].pop(0)

                    if len(self._data[i]) > 0:
                        self._data = self._data[i:]
                    else:
                        self._data = self._data[i + 1:]

                    return (True, line)
                else:
                    line += buf

        return (False, None)

class sftap_http:
    def __init__(self, uxpath):
        self._content = []

        self._conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._conn.connect(uxpath)

        print('connected to', uxpath, file=sys.stderr)

        self._header = {}

        self.__HEADER = 0
        self.__DATA   = 1
        self._state = self.__HEADER

        self._http = {}

    def run(self):
        while True:
            buf = b'' + self._conn.recv(65536)
            if len(buf) == 0:
                print('remote socket was closed', file=sys.stderr)
                return

            self._content.append(buf)
            self._parse()

    def input_video(self, content, header, server_ip, server_port,
                    client_ip, client_port):
        flowid = (header['ip1'],
                  header['ip2'],
                  header['port1'],
                  header['port2'],
                  header['hop'])
        if flowid in self._http:
            self._http[flowid][2] = True
            print(content, client_ip, client_port, server_ip, server_port)

    def _parse(self):
        while True:
            if self._state == self.__HEADER:
                (result, line) = self._read_line()
                if result == False:
                    break

                self._header = self._parse_header(line)

                if self._header['event'] == 'DATA':
                    self._state = self.__DATA
                elif self._header['event'] == 'CREATED':
                    flowid = self._get_id()
                    self._http[flowid] = [http_parser(self, is_client = True),
                                          http_parser(self, is_client = False),
                                          False]
                elif self._header['event'] == 'DESTROYED':
                    try:
                        flowid = self._get_id()
                        c = self._http[flowid][0]
                        s = self._http[flowid][1]

                        if self._http[flowid][2] == True:
                            print('CLOSED', s._peer_ip, s._peer_port,
                                  s._ip, s._port)

                        del self._http[flowid]
                    except KeyError:
                        pass
            elif self._state == self.__DATA:
                num = int(self._header['len'])

                (result, buf) = self._read_bytes(num)
                if result == False:
                    break

                flowid = self._get_id()

                if flowid in self._http:
                    if self._header['match'] == 'up':
                        # client
                        self._http[flowid][0].in_data(buf, self._header)
                    elif self._header['match'] == 'down':
                        # server
                        self._http[flowid][1].in_data(buf, self._header)

                    while True:
                        if (len(self._http[flowid][0].result) > 0 and
                            len(self._http[flowid][1].result) > 0):
                            c = self._http[flowid][0].result.pop(0)
                            s = self._http[flowid][1].result.pop(0)
                        else:
                            break
                else:
                    pass

                self._state = self.__HEADER
            else:
                print("ERROR: unkown state", file=sys.stderr)
                exit(1)

    def _read_line(self):
        line = b''
        for i, buf in enumerate(self._content):
            idx = buf.find(b'\n')
            if idx >= 0:
                line += buf[:idx]

                self._content = self._content[i:]

                suffix = buf[idx + 1:]

                if len(suffix) > 0:
                    self._content[0] = suffix
                else:
                    self._content.pop(0)

                return (True, line)
            else:
                line += buf

        return (False, b'')

    def _read_bytes(self, num):
        n = 0
        for buf in self._content:
            n += len(buf)

        if n < num:
            return (False, None)

        data = []
        while True:
            buf = self._content.pop(0)
            if len(buf) <= num:
                data.append(buf)
                num -= len(buf)
            else:
                d = buf[:num]
                data.append(d)
                self._content.insert(0, buf[num:])
                num -= len(d)

            if num == 0:
                return (True, data)

        return (False, None)

    def _parse_header(self, line):
        d = {}
        for x in line.split(b','):
            m = x.split(b'=')
            d[m[0].decode('utf-8')] = m[1].decode('utf-8')

        return d

    def _get_id(self):
        return (self._header['ip1'],
                self._header['ip2'],
                self._header['port1'],
                self._header['port2'],
                self._header['hop'])

def main():
    uxpath = '/tmp/sf-tap/tcp/http'

    if len(sys.argv) > 1:
        uxpath = sys.argv[1]

    parser = sftap_http(uxpath)
    parser.run()

if __name__ == '__main__':
    main()
