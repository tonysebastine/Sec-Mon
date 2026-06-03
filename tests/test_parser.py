"""Tests for the SSH auth.log parser."""

import os
import sys
import pytest

# Ensure plugin root is importable
PLUGIN_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)

from modules.ssh_monitor.parser import parse_line, parse_lines, ParsedEvent

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures")
FIXTURE_LOG = os.path.join(FIXTURE_DIR, "auth_sample.log")
CURRENT_YEAR = 2026


class TestParseAcceptedPassword:
    def test_accepted_password(self):
        line = "Jun  3 10:00:01 server sshd[12345]: Accepted password for admin from 192.168.1.100 port 22 ssh2"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "login.success"
        assert ev.username == "admin"
        assert ev.ip_address == "192.168.1.100"
        assert ev.port == 22
        assert ev.timestamp is not None
        assert ev.timestamp.month == 6
        assert ev.timestamp.day == 3

    def test_accepted_publickey(self):
        line = "Jun  3 10:01:22 server sshd[12346]: Accepted publickey for deploy from 10.0.0.5 port 44122 ssh2"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "login.success"
        assert ev.username == "deploy"
        assert ev.ip_address == "10.0.0.5"
        assert ev.port == 44122


class TestParseFailedLogin:
    def test_failed_password(self):
        line = "Jun  3 10:05:43 server sshd[12347]: Failed password for root from 45.33.32.156 port 34512 ssh2"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "login.failure"
        assert ev.username == "root"
        assert ev.ip_address == "45.33.32.156"
        assert ev.metadata is not None
        assert ev.metadata.get("root_attempt") is True

    def test_failed_password_invalid_user(self):
        line = "Jun  3 10:06:01 server sshd[12350]: Failed password for invalid user testuser from 185.224.128.0 port 18900 ssh2"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "login.failure"
        assert ev.username == "testuser"
        assert ev.ip_address == "185.224.128.0"

    def test_invalid_user(self):
        line = "Jun  3 10:10:00 server sshd[12352]: Invalid user hacker from 203.0.113.50"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "login.failure"
        assert ev.username == "hacker"
        assert ev.ip_address == "203.0.113.50"

    def test_failed_publickey(self):
        line = "Jun  3 11:10:00 server sshd[12365]: Failed publickey for deploy from 10.0.0.99 port 12345 ssh2"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "login.failure"
        assert ev.username == "deploy"
        assert ev.ip_address == "10.0.0.99"


class TestParseSessionEvents:
    def test_session_open(self):
        line = "Jun  3 10:15:30 server sshd[12354]: pam_unix(sshd:session): session opened for user=root by (uid=0)"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "session.open"
        assert ev.username == "root"

    def test_session_close(self):
        line = "Jun  3 10:45:00 server sshd[12361]: pam_unix(sshd:session): session closed for user=root"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "session.close"
        assert ev.username == "root"


class TestParseSudo:
    def test_sudo_command(self):
        line = "Jun  3 10:15:31 server sudo: root : TTY=pts/0 ; PWD=/root ; USER=deploy ; COMMAND=/bin/systemctl status nginx"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "sudo.command"
        assert ev.username == "root"
        assert ev.metadata is not None
        assert ev.metadata["target_user"] == "deploy"
        assert "nginx" in ev.metadata["command"]
        assert ev.metadata["tty"] == "pts/0"


class TestParseSu:
    def test_su_transition(self):
        line = "Jun  3 10:40:00 server su: pam_unix(su:session): session opened for user=deploy by root"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "su.transition"
        assert ev.metadata is not None
        assert ev.metadata["target_user"] == "deploy"


class TestParseConnectionEvents:
    def test_connection_closed_with_user(self):
        line = "Jun  3 10:20:00 server sshd[12355]: Connection closed by authenticating user admin 192.168.1.100 port 22 ssh2 [preauth]"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "connection.closed"
        assert ev.username == "admin"
        assert ev.ip_address == "192.168.1.100"

    def test_connection_closed_ip_only(self):
        line = "Jun  3 10:50:00 server sshd[12362]: Connection closed by unknown user 198.51.100.23 port 9999 ssh2 [preauth]"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "connection.closed"
        assert ev.ip_address == "198.51.100.23"

    def test_received_disconnect(self):
        line = "Jun  3 10:25:00 server sshd[12356]: Received disconnect from 45.33.32.156 port 34515:11: disconnected by user"
        ev = parse_line(line, CURRENT_YEAR)
        assert ev is not None
        assert ev.event_type == "connection.disconnect"
        assert ev.ip_address == "45.33.32.156"


class TestParseUnrecognised:
    def test_empty_line(self):
        assert parse_line("", CURRENT_YEAR) is None

    def test_irrelevant_line(self):
        line = "Jun  3 11:15:00 server sshd[12366]: pam_env(sshd:setenv): session opened for user=root by (uid=0)"
        ev = parse_line(line, CURRENT_YEAR)
        # pam_env is not one of our patterns
        assert ev is None

    def test_kernel_line(self):
        line = "Jun  3 11:20:00 server kernel: [UFW BLOCK] IN=eth0 OUT= SRC=45.33.32.156 DST=192.168.1.10 PROTO=TCP DPT=22"
        ev = parse_line(line, CURRENT_YEAR)
        # Kernel lines are not SSH events
        assert ev is None


class TestParseLinesBatch:
    def test_parse_lines_returns_only_recognised(self):
        with open(FIXTURE_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
        events = parse_lines(lines, CURRENT_YEAR)

        # The fixture has 25 lines.  Not all will be parsed (kernel lines,
        # pam_env).  We should get at least 20 recognised events.
        assert len(events) >= 20

    def test_all_event_types_present(self):
        with open(FIXTURE_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
        events = parse_lines(lines, CURRENT_YEAR)
        types_found = {ev.event_type for ev in events}

        expected = {
            "login.success",
            "login.failure",
            "session.open",
            "session.close",
            "sudo.command",
            "su.transition",
            "connection.closed",
            "connection.disconnect",
        }
        # Every expected type should be in the parsed results
        assert expected.issubset(types_found), f"Missing types: {expected - types_found}"