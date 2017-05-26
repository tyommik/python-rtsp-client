#!/usr/bin/python
#-*- coding: UTF-8 -*-
# Date: 2015-04-09
#
# Stolen here: https://github.com/js2854/python-rtsp-client
# Some text google-translated from Chinese
# A bit adopted to be import'able
# -jno
#
#Ported to Python3, removed GoodThread
# -killian441

import ast, datetime, re, socket, sys, threading, time, traceback
from optparse import OptionParser
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse # for python < 3.0
try:
    from hashlib import md5
except ImportError:
    from md5 import md5 # for python < 2.5

DEFAULT_SERVER_PORT = 554
TRANSPORT_TYPE_LIST = []
CLIENT_PORT_RANGE   = '10014-10015'
NAT_IP_PORT         = ''
ENABLE_ARQ          = False
ENABLE_FEC          = False
PING                = False

TRANSPORT_TYPE_MAP  = {
                        'ts_over_tcp'   :   'MP2T/TCP;%s;interleaved=0-1, ',
                        'rtp_over_tcp'  :   'MP2T/RTP/TCP;%s;interleaved=0-1, ',
                        'ts_over_udp'   :   'MP2T/UDP;%s;destination=%s;client_port=%s, ',
                        'rtp_over_udp'  :   'MP2T/RTP/UDP;%s;destination=%s;client_port=%s, '
                      }

RTSP_VERSION        = 'RTSP/1.0'
DEFAULT_USERAGENT   = 'Python Rtsp Client 1.0'
HEARTBEAT_INTERVAL  = 10 # 10s

END_OF_LINE         = '\r\n'
HEADER_END_STR      = END_OF_LINE*2

CUR_RANGE           = 'npt=end-'
CUR_SCALE           = 1

#x-notice in ANNOUNCE, BOS-Begin of Stream, EOS-End of Stream
X_NOTICE_EOS, X_NOTICE_BOS, X_NOTICE_CLOSE = 2101, 2102, 2103

#--------------------------------------------------------------------------
# Colored Output in Console
#--------------------------------------------------------------------------
DEBUG = False
BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA,CYAN,WHITE = list(range(90, 98))
def COLOR_STR(msg, color=WHITE):
    return '\033[%dm%s\033[0m'%(color, msg)

def PRINT(msg, color=WHITE, out=sys.stdout):
    if DEBUG and out.isatty() :
        out.write(COLOR_STR(msg, color) + '\n')
#--------------------------------------------------------------------------

class RTSPError(Exception): pass
class RTSPURLError(RTSPError): pass
class RTSPNetError(RTSPError): pass

class RTSPClient(threading.Thread):
    def __init__(self, url, dest_ip=''):
        global CUR_RANGE
        threading.Thread.__init__(self)
        self._sock      = None
        self._orig_url  = url
        self._cseq      = 0
        self._session_id= ''
        self._cseq_map  = {} # {CSeq:Method} mapping
        self._dest_ip   = dest_ip
        self.running    = True
        self.playing    = False
        self.location   = ''
        self.response_buf = []
        self.response   = None
        #self._scheme, self._server_ip, self._server_port, self._target = self._parse_url(url)
        self._parsed_url = self._parse_url(url)
        self._server_port = self._parsed_url.port or DEFAULT_SERVER_PORT
        if '.sdp' not in self._parsed_url.path.lower():
            CUR_RANGE = 'npt=0.00000-' # On demand starts from the beginning
        self._connect_server()
        self._update_dest_ip()
        self.closed = False
        self.start()

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def flush(self):
        while self.response_buf:
            x = self.response_buf.pop()
            del x

    def set_cache(self, s):
        self.flush()
        self.response_buf.append(s)

    def cache(self, s=None):
        if s is None:
            return ''.join(self.response_buf)
        else:
            self.response_buf.append(s)

    def close(self):
        if not self.closed:
            self.closed = True
            self.running = False
            self.playing = False
            self._sock.close()

    def run(self):
        try:
            while self.running:
                self.response = msg = self.recv_msg()
                if msg.startswith('RTSP'):
                    self._process_response(msg)
                elif msg.startswith('ANNOUNCE'):
                    self._process_announce(msg)
        except Exception as e:
            raise RTSPError('Run time error: %s' % e)
        self.running = False
        self.close()

    def _parse_url(self, url):
        '''Resolve url, return (ip, port, target) triplet'''
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        ip = parsed.hostname
        port = parsed.port and int(parsed.port) or DEFAULT_SERVER_PORT
        target = parsed.path
        if parsed.query:
            target += '?' + parsed.query
        if parsed.fragment:
            target += '#' + parsed.fragment

        if not scheme:
            raise RTSPURLError('Bad URL "%s"' % url)
        if scheme not in ('rtsp',): # 'rtspu'):
            raise RTSPURLError('Unsupported scheme "%s" in URL "%s"' % (scheme, url))
        if not ip or not target:
            raise RTSPURLError('Invalid url: %s (host="%s" port=%u target="%s")' %
                            (url, ip, port, target))
        #return scheme, ip, port, target
        return parsed

    def _connect_server(self):
        '''Connect to the server and create a socket'''
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.connect((self._parsed_url.hostname, self._server_port))
        except socket.error as e:
            raise RTSPNetError('socket error: %s [%s:%d]' % (e, self._parsed_url.hostname, self._server_port))

    def _update_dest_ip(self):
        '''If DEST_IP is not specified, the same IP is used by default with RTSP'''
        if not self._dest_ip:
            self._dest_ip = self._sock.getsockname()[0]
            PRINT('DEST_IP: %s\n' % self._dest_ip, CYAN)

    def recv_msg(self):
        '''A complete response message or an ANNOUNCE notification message is received'''
        try:
            while not (not self.running or HEADER_END_STR in self.cache()):
                more = self._sock.recv(2048)
                if not more:
                    break
                self.cache(more.decode())
        except socket.error as e:
            RTSPNetError('Receive data error: %s' % e)

        msg = ''
        if self.cache():
            tmp = self.cache()
            (msg, tmp) = tmp.split(HEADER_END_STR, 1)
            content_length = self._get_content_length(msg)
            msg += HEADER_END_STR + tmp[:content_length]
            self.set_cache(tmp[content_length:])
        return msg

    def _add_auth(self, msg):
        '''Authentication request string, everything after www-authentication'''
        #TODO: this is too simplistic and will fail if more than one method is acceptable, among other issues
        if msg.lower().startswith('basic'):
            pass
        elif msg.lower().startswith('digest '):
            mod_msg = '{'+msg[7:].replace('=',':')+'}'
            mod_msg = mod_msg.replace('realm','"realm"')
            mod_msg = mod_msg.replace('nonce','"nonce"')
            msg_dict = ast.literal_eval(mod_msg)
            response = self._auth_digest(msg_dict)
            auth_string = 'Digest ' \
                          'username="{}", ' \
                          'algorithm="MD5", ' \
                          'realm="{}", ' \
                          'nonce="{}", ' \
                          'uri="{}", ' \
                          'response="{}"'.format(
                          self._parsed_url.username,
                          msg_dict['realm'],
                          msg_dict['nonce'],
                          self._parsed_url.path,
                          response)
            return auth_string
        else: # Some other failure
            PRINT('Authentication failure')
            self.do_teardown()

    def _auth_digest(self, auth_parameters):
        '''Creates a response string for digest authorization, only works with MD5 at the moment'''
        #TODO expand to more than MD5
        if self._parsed_url.username:
            HA1 = md5("{}:{}:{}".format(self._parsed_url.username,
                                        auth_parameters['realm'],
                                        self._parsed_url.password).encode()).hexdigest()
            HA2 = md5("{}:{}".format(self._cseq_map[self._cseq],
                                     self._parsed_url.path).encode()).hexdigest()
            response = md5("{}:{}:{}".format(HA1,
                                             auth_parameters['nonce'],
                                             HA2).encode()).hexdigest()
            return response
        else:
            PRINT('Authentication failure')
            self.do_teardown()

    def _get_content_length(self, msg):
        '''Content-length is parsed from the message'''
        m = re.search(r'[Cc]ontent-length:\s?(?P<len>\d+)', msg, re.S)
        return (m and int(m.group('len'))) or 0

    def _get_time_str(self):
        # python 2.6 above only support% f parameters,
        # compatible with the lower version of the following wording
        dt = datetime.datetime.now()
        return dt.strftime('%Y-%m-%d %H:%M:%S.') + str(dt.microsecond)

    def _process_response(self, msg):
        '''Process the response message'''
        status, headers, body = self._parse_response(msg)
        rsp_cseq = int(headers['cseq'])
        if self._cseq_map[rsp_cseq] != 'GET_PARAMETER':
            PRINT(self._get_time_str() + '\n' + msg)
        if status == 401:
            auth_string = self._add_auth(headers['www-authenticate'])
            if self._cseq_map[self._cseq] == 'DESCRIBE':
                self.do_describe({'Authorization':auth_string})
            #self.do_teardown()
        elif status == 302:
            self.location = headers['location']
        elif status != 200:
            self.do_teardown()
        elif self._cseq_map[rsp_cseq] == 'DESCRIBE': #Implies status 200
            track_id_str = self._parse_track_id(body)
            self.do_setup(track_id_str)
        elif self._cseq_map[rsp_cseq] == 'SETUP':
            self._session_id = headers['session']
            self.do_play(CUR_RANGE, CUR_SCALE)
            self.send_heart_beat_msg()
        elif self._cseq_map[rsp_cseq] == 'PLAY':
            self.playing = True

    def _process_announce(self, msg):
        '''Processes the ANNOUNCE notification message'''
        global CUR_RANGE, CUR_SCALE
        PRINT(msg)
        headers = self._parse_header_params(msg.splitlines()[1:])
        x_notice_val = int(headers['x-notice'])
        if x_notice_val in (X_NOTICE_EOS, X_NOTICE_BOS):
            CUR_SCALE = 1
            self.do_play(CUR_RANGE, CUR_SCALE)
        elif x_notice_val == X_NOTICE_CLOSE:
            self.do_teardown()

    def _parse_response(self, msg):
        '''Resolve the response message'''
        header, body = msg.split(HEADER_END_STR)[:2]
        header_lines = header.splitlines()
        version, status = header_lines[0].split(None, 2)[:2]
        headers = self._parse_header_params(header_lines[1:])
        return int(status), headers, body

    def _parse_header_params(self, header_param_lines):
        '''Parse header parameters'''
        headers = {}
        for line in header_param_lines:
            if line.strip():
                key, val = line.split(':', 1)
                headers[key.lower()] = val.strip()
        return headers

    def _parse_track_id(self, sdp):
        '''Resolves a string of the form trackID = 2 from sdp'''
        m = re.search(r'a=control:(?P<trackid>[\w=\d]+)', sdp, re.S)
        return m and m.group('trackid') or ''

    def _next_seq(self):
        self._cseq += 1
        return self._cseq

    def _sendmsg(self, method, url, headers):
        '''Send a message'''
        self.flush() # clear recv buffer
        msg = '%s %s %s'%(method, url, RTSP_VERSION)
        headers['User-Agent'] = DEFAULT_USERAGENT
        cseq = self._next_seq()
        self._cseq_map[cseq] = method
        headers['CSeq'] = str(cseq)
        if self._session_id:
            headers['Session'] = self._session_id
        for (k, v) in list(headers.items()):
            msg += END_OF_LINE + '%s: %s'%(k, str(v))
        msg += HEADER_END_STR # End headers
        if method != 'GET_PARAMETER' or 'x-RetransSeq' in headers:
            PRINT(self._get_time_str() + END_OF_LINE + msg)
        try:
            self._sock.send(msg.encode())
        except socket.error as e:
            PRINT('Send msg error: %s'%e, RED)
            raise RTSPNetError(e)

    def _get_transport_type(self):
        '''The Transport string parameter that is required to get SETUP'''
        transport_str = ''
        ip_type = 'unicast' #if IPAddress(DEST_IP).is_unicast() else 'multicast'
        for t in TRANSPORT_TYPE_LIST:
            if t not in TRANSPORT_TYPE_MAP:
                raise RTSPError('Error param: %s' % t)
            if t.endswith('tcp'):
                transport_str += TRANSPORT_TYPE_MAP[t]%ip_type
            else:
                transport_str += TRANSPORT_TYPE_MAP[t]%(ip_type, self._dest_ip, CLIENT_PORT_RANGE)
        return transport_str

    def do_describe(self, headers={}):
        headers['Accept'] = 'application/sdp'
        if ENABLE_ARQ:
            headers['x-Retrans'] = 'yes'
            headers['x-Burst'] = 'yes'
        if ENABLE_FEC: headers['x-zmssFecCDN'] = 'yes'
        if NAT_IP_PORT: headers['x-NAT'] = NAT_IP_PORT
        self._sendmsg('DESCRIBE', self._orig_url, headers)

    def do_setup(self, track_id_str='', headers={}):
        headers['Transport'] = self._get_transport_type()
        self._sendmsg('SETUP', self._orig_url+'/'+track_id_str, headers)

    def do_play(self, range='npt=end-', scale=1, headers={}):
        headers['Range'] = range
        headers['Scale'] = scale
        self._sendmsg('PLAY', self._orig_url, headers)

    def do_pause(self, headers={}):
        self._sendmsg('PAUSE', self._orig_url, headers)

    def do_teardown(self, headers={}):
        self._sendmsg('TEARDOWN', self._orig_url, headers)
        self.running = False

    def do_options(self, headers={}):
        self._sendmsg('OPTIONS', self._orig_url, headers)

    def do_get_parameter(self, headers={}):
        self._sendmsg('GET_PARAMETER', self._orig_url, headers)

    def send_heart_beat_msg(self):
        '''Timed sending GET_PARAMETER message keep alive'''
        if not self.running:
            self.do_get_parameter()
            threading.Timer(HEARTBEAT_INTERVAL, self.send_heart_beat_msg).start()

    def ping(self, timeout=0.01):
        '''No exceptions == service available'''
        self.do_options()
        time.sleep(timeout)
        self.close()
        return self.response

#-----------------------------------------------------------------------
# Input with autocompletion
#-----------------------------------------------------------------------
import readline
COMMANDS = (
        'backward',
        'begin',
        'exit',
        'forward',
        'help',
        'live',
        'pause',
        'play',
        'range:',
        'scale:',
        'teardown',
)

def complete(text, state):
    options = [i for i in COMMANDS if i.startswith(text)]
    return (state < len(options) and options[state]) or None

def input_cmd():
    readline.set_completer_delims(' \t\n')
    readline.parse_and_bind("tab: complete")
    readline.set_completer(complete)
    cmd = input(COLOR_STR('Input Command # ', CYAN))
    PRINT('') # add one line
    return cmd
#-----------------------------------------------------------------------

def exec_cmd(rtsp, cmd):
    '''Execute the operation according to the command'''
    global CUR_RANGE, CUR_SCALE
    if cmd in ('exit', 'teardown'):
        rtsp.do_teardown()
    elif cmd == 'pause':
        CUR_SCALE = 1; CUR_RANGE = 'npt=now-'
        rtsp.do_pause()
    elif cmd == 'help':
        PRINT(play_ctrl_help())
    elif cmd == 'forward':
        if CUR_SCALE < 0: CUR_SCALE = 1
        CUR_SCALE *= 2; CUR_RANGE = 'npt=now-'
    elif cmd == 'backward':
        if CUR_SCALE > 0: CUR_SCALE = -1
        CUR_SCALE *= 2; CUR_RANGE = 'npt=now-'
    elif cmd == 'begin':
        CUR_SCALE = 1; CUR_RANGE = 'npt=beginning-'
    elif cmd == 'live':
        CUR_SCALE = 1; CUR_RANGE = 'npt=end-'
    elif cmd.startswith('play'):
        m = re.search(r'range[:\s]+(?P<range>[^\s]+)', cmd)
        if m: CUR_RANGE = m.group('range')
        m = re.search(r'scale[:\s]+(?P<scale>[\d\.]+)', cmd)
        if m: CUR_SCALE = int(m.group('scale'))

    if cmd not in ('pause', 'exit', 'teardown', 'help'):
        rtsp.do_play(CUR_RANGE, CUR_SCALE)

def main(url, dest_ip):
    rtsp = RTSPClient(url, dest_ip)

    if PING:
        PRINT('PING START', YELLOW)
        rtsp.ping()
        PRINT('PING DONE', YELLOW)
        sys.exit(0)
        return

    try:
        rtsp.do_describe()
        while rtsp.location and rtsp.running:
            if rtsp.playing:
                cmd = input_cmd()
                exec_cmd(rtsp, cmd)
            # 302 redirect to re-establish chain
            if not rtsp.running and rtsp.location:
                rtsp = RTSPClient(rtsp.location)
                rtsp.do_describe()
            time.sleep(0.5)
    except KeyboardInterrupt:
        rtsp.do_teardown()
        print('\n^C received, Exit.')

def play_ctrl_help():
    help = COLOR_STR('In running, you can control play by input "' \
                    +'forward", "backward", "begin", "live", "pause"\n', MAGENTA)
    help += COLOR_STR('or "play" with "range" and "scale" parameter, ' \
                     +'such as "play range:npt=beginning- scale:2"\n', MAGENTA)
    help += COLOR_STR('You can input "exit", "teardown" or ctrl+c to quit\n', MAGENTA)
    return help

if __name__ == '__main__':
    usage = COLOR_STR('%prog [options] url\n\n', GREEN) + play_ctrl_help()

    parser = OptionParser(usage=usage)
    parser.add_option('-t', '--transport', dest='transport', default='rtp_over_udp',
                      help='Set transport type when SETUP: ts_over_tcp, ts_over_udp, '
                          +' rtp_over_tcp, rtp_over_udp [default]')
    parser.add_option('-d', '--dest_ip', dest='dest_ip',
                      help='Set dest ip of udp data transmission, default use same ip with rtsp')
    parser.add_option('-p', '--client_port', dest='client_port',
                      help='Set client port range when SETUP of udp, default is "10014-10015"')
    parser.add_option('-n', '--nat', dest='nat',
                      help='Add "x-NAT" when DESCRIBE, arg format "192.168.1.100:20008"')
    parser.add_option('-r', '--arq', dest='arq', action="store_true",
                      help='Add "x-Retrans:yes" when DESCRIBE')
    parser.add_option('-f', '--fec', dest='fec', action="store_true",
                      help='Add "x-zmssFecCDN:yes" when DESCRIBE')
    parser.add_option('-P', '--ping', dest='ping', action="store_true",
                      help='Just perform DESCRIBE and exit.')

    (options, args) = parser.parse_args()
    if len(args) < 1:
        parser.print_help()
        sys.exit()

    if options.transport:   TRANSPORT_TYPE_LIST = options.transport.split(',')
    if options.client_port: CLIENT_PORT_RANGE = options.client_port
    if options.nat:         NAT_IP_PORT = options.nat
    if options.arq:         ENABLE_ARQ  = options.arq
    if options.fec:         ENABLE_FEC  = options.fec
    if options.ping:        PING  = options.ping

    url = args[0]

    DEBUG = True
    main(url, options.dest_ip)
# EOF #
