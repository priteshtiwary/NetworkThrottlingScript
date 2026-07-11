"""Unit tests for traffic monitoring (tcpdump parsing + endpoint aggregation)."""

from throttle import monitor


def test_parse_tcpdump_aggregates_remote_endpoints(tcpdump_output):
    endpoints = monitor.parse_tcpdump(tcpdump_output, "192.168.2.2")
    by_ip = {e.ip: e for e in endpoints}

    # The busiest CDN endpoint should be first and counted correctly.
    assert endpoints[0].ip == "142.250.183.14"
    assert by_ip["142.250.183.14"].packets == 4
    assert 443 in by_ip["142.250.183.14"].ports

    # Second CDN endpoint captured too.
    assert "23.53.140.11" in by_ip
    assert by_ip["23.53.140.11"].packets == 2


def test_parse_tcpdump_excludes_device_and_multicast(tcpdump_output):
    endpoints = monitor.parse_tcpdump(tcpdump_output, "192.168.2.2")
    ips = {e.ip for e in endpoints}
    # Device's own IP never appears as a remote endpoint.
    assert "192.168.2.2" not in ips
    # Multicast mDNS destination excluded.
    assert "224.0.0.251" not in ips
    # Traffic between two unrelated hosts (not the device) excluded.
    assert "10.0.0.5" not in ips
    assert "10.0.0.9" not in ips


def test_parse_tcpdump_includes_dhcp_gateway_and_dns(tcpdump_output):
    endpoints = monitor.parse_tcpdump(tcpdump_output, "192.168.2.2")
    ips = {e.ip for e in endpoints}
    # Gateway (DHCP) and DNS server are legitimate remote endpoints.
    assert "192.168.2.1" in ips
    assert "8.8.8.8" in ips


def test_parse_tcpdump_sorted_by_packets(tcpdump_output):
    endpoints = monitor.parse_tcpdump(tcpdump_output, "192.168.2.2")
    counts = [e.packets for e in endpoints]
    assert counts == sorted(counts, reverse=True)


def test_parse_tcpdump_empty():
    assert monitor.parse_tcpdump("", "192.168.2.2") == []


def test_endpoint_is_private():
    assert monitor.Endpoint(ip="192.168.2.1").is_private is True
    assert monitor.Endpoint(ip="142.250.183.14").is_private is False
    assert monitor.Endpoint(ip="not-an-ip").is_private is False


def test_resolve_hostname_parses_pointer(fake_runner):
    fake_runner.set_response(
        "host",
        stdout="14.183.250.142.in-addr.arpa domain name pointer bom12s.1e100.net.\n",
    )
    assert monitor.resolve_hostname("142.250.183.14") == "bom12s.1e100.net"


def test_resolve_hostname_none_when_no_pointer(fake_runner):
    fake_runner.set_response("host", stdout="Host 1.2.3.4 not found: 3(NXDOMAIN)\n")
    assert monitor.resolve_hostname("1.2.3.4") is None


def test_resolve_hostname_none_on_command_failure(fake_runner):
    fake_runner.set_response("host", stdout="", returncode=1)
    assert monitor.resolve_hostname("1.2.3.4") is None


def test_parse_tcpdump_skips_non_ip_and_unrelated_lines():
    text = (
        "12:00:00 ARP, Request who-has 192.168.2.1 tell 192.168.2.2\n"
        "IP 192.168.2.2.51514 > 142.250.183.14.443: Flags [S], length 0\n"
        "garbage line without a match\n"
    )
    endpoints = monitor.parse_tcpdump(text, "192.168.2.2")
    assert [e.ip for e in endpoints] == ["142.250.183.14"]


def test_parse_tcpdump_skips_loopback_and_unspecified():
    text = (
        "IP 192.168.2.2.5 > 127.0.0.1.80: Flags [S], length 0\n"
        "IP 192.168.2.2.5 > 0.0.0.0.80: Flags [S], length 0\n"
    )
    assert monitor.parse_tcpdump(text, "192.168.2.2") == []


def test_monitor_device_builds_tcpdump_command(fake_runner, tcpdump_output, temp_state_dir):
    fake_runner.set_response("tcpdump", stdout=tcpdump_output)
    fake_runner.set_response("host", stdout="")  # no PTR records
    endpoints = monitor.monitor_device(
        "192.168.2.2", "bridge100", duration=5, resolve=False
    )
    capture_cmd = fake_runner.commands()[0]
    assert capture_cmd.startswith("tcpdump")
    assert "-i bridge100" in capture_cmd
    assert "host 192.168.2.2" in capture_cmd
    assert "-G 5" in capture_cmd
    assert "-w " in capture_cmd
    # A second tcpdump reads the capture back for parsing.
    assert any("-r " in c for c in fake_runner.commands())
    assert endpoints[0].ip == "142.250.183.14"


def test_monitor_device_dry_run_returns_empty(fake_runner, temp_state_dir):
    endpoints = monitor.monitor_device(
        "192.168.2.2", "bridge100", duration=5, dry_run=True
    )
    assert endpoints == []
    assert fake_runner.calls[0]["dry_run"] is True


def test_monitor_device_resolves_public_only(fake_runner, tcpdump_output, temp_state_dir, monkeypatch):
    fake_runner.set_response("tcpdump", stdout=tcpdump_output)
    calls = []

    def fake_resolve(ip, dry_run=False):
        calls.append(ip)
        return "example.net"

    monkeypatch.setattr(monitor, "resolve_hostname", fake_resolve)
    endpoints = monitor.monitor_device(
        "192.168.2.2", "bridge100", duration=5, resolve=True
    )
    # Private endpoints (gateway) must not be reverse-resolved.
    assert "192.168.2.1" not in calls
    assert "142.250.183.14" in calls
    public = next(e for e in endpoints if e.ip == "142.250.183.14")
    assert public.hostname == "example.net"
