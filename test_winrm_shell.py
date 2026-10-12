#!/usr/bin/env python3
"""Tests for winrm_shell.py -- validates protocol logic without a live target."""

import base64
import socket
import struct
import threading
import time
import unittest
import xml.etree.ElementTree as ET

import winrm_shell as ws


class TestPSEncoding(unittest.TestCase):
    """PowerShell EncodedCommand generation."""

    def test_encode_simple(self):
        client = ws.WinRMClient.__new__(ws.WinRMClient)
        client.timeout = 60
        encoded = client._ps_encode("whoami")
        decoded = base64.b64decode(encoded).decode("utf-16-le")
        self.assertEqual(decoded, "whoami")

    def test_encode_unicode(self):
        client = ws.WinRMClient.__new__(ws.WinRMClient)
        client.timeout = 60
        cmd = 'Write-Output "héllo wörld"'
        encoded = client._ps_encode(cmd)
        decoded = base64.b64decode(encoded).decode("utf-16-le")
        self.assertEqual(decoded, cmd)

    def test_encode_multiline(self):
        client = ws.WinRMClient.__new__(ws.WinRMClient)
        client.timeout = 60
        cmd = "$x = 1\n$y = 2\n$x + $y"
        encoded = client._ps_encode(cmd)
        decoded = base64.b64decode(encoded).decode("utf-16-le")
        self.assertEqual(decoded, cmd)


class TestSOAPEnvelope(unittest.TestCase):
    """WSMan SOAP envelope generation and structure."""

    def _make_client(self):
        c = ws.WinRMClient.__new__(ws.WinRMClient)
        c.endpoint = "http://10.10.10.1:5985/wsman"
        c.host = "10.10.10.1"
        c.timeout = 60
        c.shell_id = None
        c._lock = threading.RLock()
        return c

    def test_create_envelope_valid_xml(self):
        c = self._make_client()
        xml = c._envelope(ws.ACTION_CREATE, "<rsp:Shell/>")
        root = ET.fromstring(xml)
        self.assertEqual(root.tag, f"{{{ws.XMLNS_SOAP}}}Envelope")

    def test_envelope_contains_action(self):
        c = self._make_client()
        xml = c._envelope(ws.ACTION_CREATE, "")
        self.assertIn(ws.ACTION_CREATE, xml)

    def test_envelope_contains_endpoint(self):
        c = self._make_client()
        xml = c._envelope(ws.ACTION_CREATE, "")
        self.assertIn("http://10.10.10.1:5985/wsman", xml)

    def test_envelope_with_shell_selector(self):
        c = self._make_client()
        xml = c._envelope(ws.ACTION_COMMAND, "", shell_id="ABCD-1234")
        self.assertIn("ABCD-1234", xml)
        self.assertIn("ShellId", xml)

    def test_envelope_with_options(self):
        c = self._make_client()
        xml = c._envelope(ws.ACTION_CREATE, "",
                          options={"WINRS_NOPROFILE": "TRUE"})
        self.assertIn("WINRS_NOPROFILE", xml)
        self.assertIn("TRUE", xml)

    def test_envelope_custom_timeout(self):
        c = self._make_client()
        xml = c._envelope(ws.ACTION_RECEIVE, "", op_timeout=3)
        self.assertIn("PT3S", xml)
        self.assertNotIn("PT60S", xml)

    def test_envelope_max_envelope_size(self):
        c = self._make_client()
        xml = c._envelope(ws.ACTION_RECEIVE, "", max_env=8388608)
        self.assertIn("8388608", xml)

    def test_command_envelope_structure(self):
        c = self._make_client()
        body = (
            '<rsp:CommandLine>'
            '<rsp:Command>powershell.exe</rsp:Command>'
            '<rsp:Arguments>-NoProfile</rsp:Arguments>'
            '</rsp:CommandLine>'
        )
        xml = c._envelope(ws.ACTION_COMMAND, body, shell_id="TEST-SHELL",
                          options={"WINRS_CONSOLEMODE_STDIN": "TRUE"})
        root = ET.fromstring(xml)
        ns = {"rsp": ws.XMLNS_RSP}
        cmd_el = root.find(".//rsp:Command", ns)
        self.assertIsNotNone(cmd_el)
        self.assertEqual(cmd_el.text, "powershell.exe")

    def test_receive_envelope_structure(self):
        c = self._make_client()
        body = (
            '<rsp:Receive>'
            '<rsp:DesiredStream CommandId="CMD-123">stdout stderr</rsp:DesiredStream>'
            '</rsp:Receive>'
        )
        xml = c._envelope(ws.ACTION_RECEIVE, body, shell_id="SHELL-456")
        root = ET.fromstring(xml)
        ns = {"rsp": ws.XMLNS_RSP}
        stream = root.find(".//rsp:DesiredStream", ns)
        self.assertIsNotNone(stream)
        self.assertEqual(stream.get("CommandId"), "CMD-123")

    def test_send_envelope_structure(self):
        c = self._make_client()
        data = base64.b64encode(b"hello").decode()
        body = (
            f'<rsp:Send>'
            f'<rsp:Stream Name="stdin" CommandId="CMD-789">{data}</rsp:Stream>'
            f'</rsp:Send>'
        )
        xml = c._envelope(ws.ACTION_SEND, body, shell_id="SHELL-ABC")
        root = ET.fromstring(xml)
        self.assertIn(ws.ACTION_SEND, xml)
        ns = {"rsp": ws.XMLNS_RSP}
        stream = root.find(".//rsp:Stream", ns)
        self.assertIsNotNone(stream)
        self.assertEqual(stream.get("Name"), "stdin")


class TestResponseParsing(unittest.TestCase):
    """Parse simulated WSMan XML responses."""

    def test_parse_shell_id(self):
        xml = f'''<s:Envelope xmlns:s="{ws.XMLNS_SOAP}" xmlns:rsp="{ws.XMLNS_RSP}">
            <s:Body><rsp:Shell><rsp:ShellId>DEADBEEF-1234</rsp:ShellId></rsp:Shell></s:Body>
        </s:Envelope>'''
        root = ET.fromstring(xml)
        sid = root.find(f".//{{{ws.XMLNS_RSP}}}ShellId")
        self.assertIsNotNone(sid)
        self.assertEqual(sid.text, "DEADBEEF-1234")

    def test_parse_command_id(self):
        xml = f'''<s:Envelope xmlns:s="{ws.XMLNS_SOAP}" xmlns:rsp="{ws.XMLNS_RSP}">
            <s:Body><rsp:CommandResponse><rsp:CommandId>CMD-5678</rsp:CommandId></rsp:CommandResponse></s:Body>
        </s:Envelope>'''
        root = ET.fromstring(xml)
        cid = root.find(f".//{{{ws.XMLNS_RSP}}}CommandId")
        self.assertEqual(cid.text, "CMD-5678")

    def test_parse_output_streams(self):
        stdout_b64 = base64.b64encode(b"hello world").decode()
        stderr_b64 = base64.b64encode(b"an error").decode()
        xml = f'''<s:Envelope xmlns:s="{ws.XMLNS_SOAP}" xmlns:rsp="{ws.XMLNS_RSP}">
            <s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="C1">{stdout_b64}</rsp:Stream>
                <rsp:Stream Name="stderr" CommandId="C1">{stderr_b64}</rsp:Stream>
                <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                    <rsp:ExitCode>0</rsp:ExitCode>
                </rsp:CommandState>
            </rsp:ReceiveResponse></s:Body>
        </s:Envelope>'''
        root = ET.fromstring(xml)
        stdout_parts = []
        stderr_parts = []
        for stream in root.findall(f".//{{{ws.XMLNS_RSP}}}Stream"):
            if stream.text:
                decoded = base64.b64decode(stream.text)
                if stream.get("Name") == "stdout":
                    stdout_parts.append(decoded)
                elif stream.get("Name") == "stderr":
                    stderr_parts.append(decoded)
        self.assertEqual(b"".join(stdout_parts), b"hello world")
        self.assertEqual(b"".join(stderr_parts), b"an error")

        state = root.find(f".//{{{ws.XMLNS_RSP}}}CommandState")
        self.assertTrue(state.get("State").endswith("Done"))
        ec = state.find(f"{{{ws.XMLNS_RSP}}}ExitCode")
        self.assertEqual(ec.text, "0")

    def test_parse_soap_fault(self):
        xml = f'''<s:Envelope xmlns:s="{ws.XMLNS_SOAP}">
            <s:Body><s:Fault><s:Reason><s:Text>Access denied</s:Text></s:Reason></s:Fault></s:Body>
        </s:Envelope>'''
        c = ws.WinRMClient.__new__(ws.WinRMClient)
        result = c._parse_fault(xml)
        self.assertEqual(result, "Access denied")

    def test_parse_fault_invalid_xml(self):
        c = ws.WinRMClient.__new__(ws.WinRMClient)
        result = c._parse_fault("not xml at all")
        self.assertIsNone(result)


class TestCWDTracking(unittest.TestCase):
    """CWD marker parsing in execute_ps_with_cwd output."""

    def test_cwd_extraction(self):
        client = ws.WinRMClient.__new__(ws.WinRMClient)
        client._cwd_marker = "::CWD_TEST::"

        raw_output = "file1.txt\nfile2.txt\n::CWD_TEST::C:\\Users\\admin\n"
        lines = raw_output.rstrip("\r\n").split("\n")
        clean_lines = []
        new_cwd = "C:\\"
        for line in lines:
            if client._cwd_marker in line:
                new_cwd = line.split(client._cwd_marker, 1)[1].strip()
            else:
                clean_lines.append(line)

        self.assertEqual(new_cwd, "C:\\Users\\admin")
        self.assertEqual(clean_lines, ["file1.txt", "file2.txt"])

    def test_cwd_no_marker(self):
        client = ws.WinRMClient.__new__(ws.WinRMClient)
        client._cwd_marker = "::CWD_TEST::"

        raw_output = "some output\n"
        lines = raw_output.rstrip("\r\n").split("\n")
        clean_lines = []
        new_cwd = "C:\\original"
        for line in lines:
            if client._cwd_marker in line:
                new_cwd = line.split(client._cwd_marker, 1)[1].strip()
            else:
                clean_lines.append(line)

        self.assertEqual(new_cwd, "C:\\original")
        self.assertEqual(clean_lines, ["some output"])


class TestClientClone(unittest.TestCase):
    """WinRMClient.clone() produces an independent copy."""

    def test_clone_independent_session(self):
        c = ws.WinRMClient.__new__(ws.WinRMClient)
        c.endpoint = "http://host:5985/wsman"
        c.host = "host"
        c.timeout = 60
        c.shell_id = "ORIGINAL"
        c._cwd_marker = "::CWD::"
        c._lock = threading.RLock()
        c.session = type("S", (), {
            "verify": False,
            "auth": None,
            "headers": {"Content-Type": "application/soap+xml;charset=UTF-8"},
        })()
        c.session.headers = dict(c.session.headers)

        clone = c.clone()
        self.assertEqual(clone.endpoint, c.endpoint)
        self.assertIsNone(clone.shell_id)
        self.assertIsNot(clone._lock, c._lock)


class TestSOCKS5Handshake(unittest.TestCase):
    """SOCKS5 protocol parsing in TunnelConnection."""

    def _make_tunnel(self, client_sock):
        main_client = ws.WinRMClient.__new__(ws.WinRMClient)
        main_client.endpoint = "http://host:5985/wsman"
        main_client.host = "host"
        main_client.timeout = 60
        main_client.shell_id = None
        main_client._cwd_marker = "::CWD::"
        main_client._lock = threading.RLock()
        main_client.session = type("S", (), {
            "verify": False,
            "auth": None,
            "headers": {"Content-Type": "application/soap+xml;charset=UTF-8"},
        })()
        main_client.session.headers = dict(main_client.session.headers)
        main_client.session.close = lambda: None
        tunnel = ws.TunnelConnection(main_client, client_sock, ("127.0.0.1", 9999))
        return tunnel

    def test_socks5_ipv4(self):
        """Full SOCKS5 handshake with IPv4 destination."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(1)

        result = {}

        def client_side():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", port))
            # SOCKS5 greeting: version 5, 1 method (no auth)
            s.sendall(b"\x05\x01\x00")
            resp = s.recv(2)
            result["greeting"] = resp
            # CONNECT to 192.168.1.1:8080
            target_ip = socket.inet_aton("192.168.1.1")
            target_port = struct.pack("!H", 8080)
            s.sendall(b"\x05\x01\x00\x01" + target_ip + target_port)
            resp = s.recv(32)
            result["connect_reply"] = resp
            s.close()

        t = threading.Thread(target=client_side)
        t.start()

        conn, _ = server_sock.accept()
        tunnel = self._make_tunnel(conn)
        dst = tunnel._socks5_handshake()
        result["dst"] = dst

        t.join(timeout=5)
        server_sock.close()

        self.assertEqual(result["greeting"], b"\x05\x00")
        self.assertEqual(result["dst"], ("192.168.1.1", 8080))

    def test_socks5_domain(self):
        """SOCKS5 handshake with domain name destination."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("127.0.0.1", 0))
        port = server_sock.getsockname()[1]
        server_sock.listen(1)

        result = {}

        def client_side():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", port))
            s.sendall(b"\x05\x01\x00")
            s.recv(2)
            domain = b"internal.corp.local"
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(domain)]) +
                      domain + struct.pack("!H", 443))
            s.recv(32)
            s.close()

        t = threading.Thread(target=client_side)
        t.start()

        conn, _ = server_sock.accept()
        tunnel = self._make_tunnel(conn)
        dst = tunnel._socks5_handshake()
        result["dst"] = dst

        t.join(timeout=5)
        server_sock.close()

        self.assertEqual(result["dst"], ("internal.corp.local", 443))


class TestSocksProxyLifecycle(unittest.TestCase):
    """SocksProxy start/stop and port binding."""

    def test_start_stop(self):
        main_client = ws.WinRMClient.__new__(ws.WinRMClient)
        main_client.endpoint = "http://host:5985/wsman"
        main_client.host = "host"
        main_client.timeout = 60
        main_client.shell_id = None
        main_client._cwd_marker = "::CWD::"
        main_client._lock = threading.RLock()
        main_client.session = type("S", (), {
            "verify": False,
            "auth": None,
            "headers": {"Content-Type": "application/soap+xml;charset=UTF-8"},
        })()
        main_client.session.headers = dict(main_client.session.headers)
        main_client.session.close = lambda: None

        proxy = ws.SocksProxy(main_client, listen_port=0)
        proxy.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy.server_sock.bind(("127.0.0.1", 0))
        actual_port = proxy.server_sock.getsockname()[1]
        proxy.listen_port = actual_port
        proxy.server_sock.listen(10)
        proxy.running = True
        proxy._accept_thread = threading.Thread(target=proxy._accept_loop, daemon=True)
        proxy._accept_thread.start()

        # Verify port is listening
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.settimeout(2)
        connected = False
        try:
            test_sock.connect(("127.0.0.1", actual_port))
            connected = True
        except OSError:
            pass
        finally:
            test_sock.close()

        self.assertTrue(connected, "SOCKS proxy port should be listening")
        self.assertTrue(proxy.running)

        proxy.stop()
        self.assertFalse(proxy.running)


class TestRelayScript(unittest.TestCase):
    """Verify the PowerShell relay script template."""

    def test_template_substitution(self):
        script = ws.RELAY_PS.replace("__HOST__", "10.0.0.5").replace("__PORT__", "3389")
        self.assertIn("10.0.0.5", script)
        self.assertIn("3389", script)
        self.assertNotIn("__HOST__", script)
        self.assertNotIn("__PORT__", script)

    def test_template_has_async_read(self):
        self.assertIn("BeginRead", ws.RELAY_PS)
        self.assertIn("WaitOne", ws.RELAY_PS)

    def test_template_has_success_marker(self):
        self.assertIn("WriteByte(1)", ws.RELAY_PS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
