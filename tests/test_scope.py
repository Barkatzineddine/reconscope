"""Tests for the authorization gate -- the most important part to get right."""

from __future__ import annotations

import ipaddress

import pytest

from reconscope.scope import MAX_EXPANDED_HOSTS, Scope, ScopeError, expand_targets

BASE = {
    "authorization": "test engagement",
    "allow": {"hosts": ["10.0.0.0/24", "host.example.test"], "ports": ["22", "80-82"]},
    "deny": {"hosts": ["10.0.0.1"]},
    "rate": {"max_concurrency": 10, "requests_per_second": 5},
}


def test_from_dict_parses_everything() -> None:
    scope = Scope.from_dict(BASE)
    assert scope.authorization == "test engagement"
    assert ipaddress.ip_network("10.0.0.0/24") in scope.allow_networks
    assert "host.example.test" in scope.allow_names
    assert scope.ports == {22, 80, 81, 82}
    assert scope.rate.max_concurrency == 10


def test_missing_authorization_is_refused() -> None:
    data = {**BASE, "authorization": "  "}
    with pytest.raises(ScopeError, match="authorization"):
        Scope.from_dict(data)


def test_empty_allow_hosts_is_refused() -> None:
    data = {**BASE, "allow": {"hosts": [], "ports": ["80"]}}
    with pytest.raises(ScopeError, match="authorizes nothing"):
        Scope.from_dict(data)


def test_empty_ports_is_refused() -> None:
    data = {**BASE, "allow": {"hosts": ["10.0.0.5"], "ports": []}}
    with pytest.raises(ScopeError, match="no ports"):
        Scope.from_dict(data)


@pytest.mark.parametrize("bad", [["0"], ["70000"], ["1-70000"]])
def test_out_of_range_ports_refused(bad: list[str]) -> None:
    data = {**BASE, "allow": {"hosts": ["10.0.0.5"], "ports": bad}}
    with pytest.raises(ScopeError):
        Scope.from_dict(data)


def test_reversed_port_range_is_normalised() -> None:
    scope = Scope.from_dict({**BASE, "allow": {"hosts": ["10.0.0.5"], "ports": ["82-80"]}})
    assert scope.ports == {80, 81, 82}


def test_bad_rate_refused() -> None:
    data = {**BASE, "rate": {"max_concurrency": 0, "requests_per_second": 5}}
    with pytest.raises(ScopeError, match="max_concurrency"):
        Scope.from_dict(data)
    data = {**BASE, "rate": {"max_concurrency": 5, "requests_per_second": 0}}
    with pytest.raises(ScopeError, match="requests_per_second"):
        Scope.from_dict(data)


def test_authorize_ip_in_network() -> None:
    scope = Scope.from_dict(BASE)
    assert scope.authorize_host("10.0.0.5").allowed
    assert not scope.authorize_host("10.0.1.5").allowed


def test_authorize_ip_denied_wins() -> None:
    scope = Scope.from_dict(BASE)
    decision = scope.authorize_host("10.0.0.1")
    assert not decision.allowed
    assert "deny" in decision.reason


def test_authorize_name_must_be_listed() -> None:
    scope = Scope.from_dict(BASE)
    assert scope.authorize_host("host.example.test").allowed
    assert scope.authorize_host("HOST.EXAMPLE.TEST.").allowed  # case and trailing dot
    assert not scope.authorize_host("other.example.test").allowed


def test_authorize_empty_target() -> None:
    scope = Scope.from_dict(BASE)
    assert not scope.authorize_host("   ").allowed


def test_authorize_resolved_checks_networks() -> None:
    scope = Scope.from_dict(BASE)
    assert scope.authorize_resolved(ipaddress.ip_address("10.0.0.9")).allowed
    assert not scope.authorize_resolved(ipaddress.ip_address("8.8.8.8")).allowed
    assert not scope.authorize_resolved(ipaddress.ip_address("10.0.0.1")).allowed


def test_authorize_resolved_name_only_scope() -> None:
    data = {**BASE, "allow": {"hosts": ["host.example.test"], "ports": ["80"]}}
    scope = Scope.from_dict(data)
    # With no allow networks, a resolved address is covered by the allowed name.
    assert scope.authorize_resolved(ipaddress.ip_address("203.0.113.5")).allowed


def test_port_allowed_and_defaults() -> None:
    scope = Scope.from_dict(BASE)
    assert scope.port_allowed(22)
    assert not scope.port_allowed(23)
    assert scope.default_targets() == ["10.0.0.0/24", "host.example.test"]


def test_summary_shape() -> None:
    summary = Scope.from_dict(BASE).summary()
    assert summary["ports_in_scope"] == 4
    assert summary["allow_names"] == ["host.example.test"]


def test_expand_targets_cidr() -> None:
    hosts = expand_targets(["10.0.0.0/30", "name.test", "10.0.0.5"])
    assert "10.0.0.1" in hosts and "10.0.0.2" in hosts
    assert "name.test" in hosts and "10.0.0.5" in hosts


def test_expand_single_address_network() -> None:
    assert expand_targets(["10.0.0.7/32"]) == ["10.0.0.7"]


def test_expand_rejects_huge_range() -> None:
    assert MAX_EXPANDED_HOSTS < 2**16
    with pytest.raises(ScopeError, match="limit"):
        expand_targets(["10.0.0.0/8"])


def test_expand_skips_blank_and_passes_bad_cidr() -> None:
    assert expand_targets(["", "  ", "not/a/cidr"]) == ["not/a/cidr"]


def test_from_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "scope.yml"
    path.write_text("authorization: f\nallow:\n  hosts: ['1.2.3.4']\n  ports: ['80']\n", encoding="utf-8")
    scope = Scope.from_file(path)
    assert scope.authorize_host("1.2.3.4").allowed


def test_from_file_not_mapping(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "scope.yml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(ScopeError, match="mapping"):
        Scope.from_file(path)
