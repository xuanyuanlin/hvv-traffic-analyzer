"""流量过滤引擎

支持五元组过滤（IP/端口/协议）和内容正则匹配。
多规则 OR 匹配：任一规则命中即返回。
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

from .parser import Packet


@dataclass
class FilterRule:
    """单条过滤规则"""
    name: str = ""
    # 五元组过滤
    src_ips: Optional[list[str]] = None        # ["10.0.0.1", "192.168.0.0/16"]
    dst_ips: Optional[list[str]] = None
    exclude_ips: Optional[list[str]] = None
    src_ports: Optional[list[int]] = None
    dst_ports: Optional[list[int]] = None
    protocols: Optional[list[str]] = None      # ["HTTP", "DNS", "TLS", "SMB", ...]

    # 内容匹配
    content_patterns: Optional[list[str]] = None

    # HTTP 特定过滤
    http_methods: Optional[list[str]] = None
    http_uri_pattern: Optional[str] = None
    http_ua_pattern: Optional[str] = None
    http_content_type: Optional[str] = None
    http_status_codes: Optional[list[int]] = None

    # DNS 特定过滤
    dns_domain_pattern: Optional[str] = None
    dns_types: Optional[list[str]] = None

    # 时间范围
    time_start: Optional[str] = None   # "09:00"
    time_end: Optional[str] = None     # "18:00"


class TrafficFilter:
    """过滤引擎，支持多规则 OR 匹配（任一规则命中即告警）"""

    def __init__(self):
        self.rules: list[FilterRule] = []
        self._compiled_patterns: dict[str, re.Pattern] = {}

    def add_rule(self, rule: FilterRule) -> None:
        """添加过滤规则，预编译正则"""
        self.rules.append(rule)
        # 预编译内容匹配正则
        if rule.content_patterns:
            for p in rule.content_patterns:
                if p not in self._compiled_patterns:
                    self._compiled_patterns[p] = re.compile(p)
        if rule.http_uri_pattern and rule.http_uri_pattern not in self._compiled_patterns:
            self._compiled_patterns[rule.http_uri_pattern] = re.compile(rule.http_uri_pattern)
        if rule.http_ua_pattern and rule.http_ua_pattern not in self._compiled_patterns:
            self._compiled_patterns[rule.http_ua_pattern] = re.compile(rule.http_ua_pattern)
        if rule.dns_domain_pattern and rule.dns_domain_pattern not in self._compiled_patterns:
            self._compiled_patterns[rule.dns_domain_pattern] = re.compile(rule.dns_domain_pattern)

    def match(self, packet: Packet) -> list[FilterRule]:
        """返回命中的规则列表，空列表表示未命中"""
        if not self.rules:
            return []  # 无规则时不过滤

        matched = []
        for rule in self.rules:
            if self._match_rule(packet, rule):
                matched.append(rule)
        return matched

    def _match_rule(self, pkt: Packet, rule: FilterRule) -> bool:
        """检查单条规则是否命中（所有条件 AND）"""

        # --- 协议过滤 ---
        if rule.protocols:
            if not pkt.protocol:
                return False
            if pkt.protocol.lower() not in [p.lower() for p in rule.protocols]:
                return False

        # --- 源 IP 过滤 ---
        if rule.src_ips:
            if not self._match_ip(pkt.src_ip, rule.src_ips, rule.exclude_ips):
                return False
        elif rule.exclude_ips:
            if self._match_ip(pkt.src_ip, [], rule.exclude_ips):
                return False

        # --- 目的 IP 过滤 ---
        if rule.dst_ips:
            if not self._match_ip(pkt.dst_ip, rule.dst_ips, None):
                return False

        # --- 端口过滤 ---
        if rule.src_ports and pkt.src_port not in rule.src_ports:
            return False
        if rule.dst_ports and pkt.dst_port not in rule.dst_ports:
            return False

        # --- 内容匹配 ---
        if rule.content_patterns:
            payload = pkt.payload_preview
            if not self._match_content(payload, rule.content_patterns):
                return False

        # --- HTTP 过滤 ---
        if pkt.http:
            if rule.http_methods:
                if pkt.http.method.upper() not in [m.upper() for m in rule.http_methods]:
                    return False
            if rule.http_uri_pattern:
                uri = pkt.http.uri or pkt.http.full_uri
                pattern = self._compiled_patterns.get(rule.http_uri_pattern)
                if pattern and not pattern.search(uri):
                    return False
            if rule.http_ua_pattern:
                ua = pkt.http.user_agent
                pattern = self._compiled_patterns.get(rule.http_ua_pattern)
                if pattern and not pattern.search(ua):
                    return False
            if rule.http_content_type:
                ct = pkt.http.content_type
                if rule.http_content_type.lower() not in ct.lower():
                    return False
            if rule.http_status_codes:
                if pkt.http.status_code not in rule.http_status_codes:
                    return False

        # --- DNS 过滤 ---
        if pkt.dns:
            if rule.dns_domain_pattern:
                pattern = self._compiled_patterns.get(rule.dns_domain_pattern)
                if pattern and not pattern.search(pkt.dns.query_name):
                    return False
            if rule.dns_types:
                if pkt.dns.query_type.upper() not in [t.upper() for t in rule.dns_types]:
                    return False

        return True

    def _match_ip(self, ip: str, include: Optional[list[str]],
                  exclude: Optional[list[str]]) -> bool:
        """IP 匹配，支持 CIDR"""
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False

        # 排除规则
        if exclude:
            for ex in exclude:
                try:
                    net = ipaddress.ip_network(ex, strict=False)
                    if addr in net:
                        return False
                except ValueError:
                    if ip == ex:
                        return False

        # 包含规则
        if include:
            for inc in include:
                try:
                    net = ipaddress.ip_network(inc, strict=False)
                    if addr in net:
                        return True
                except ValueError:
                    if ip == inc:
                        return True
            return False  # 有包含列表但没匹配到

        return True

    def _match_content(self, payload: str, patterns: list[str]) -> bool:
        """正则匹配 payload 内容，所有模式 AND"""
        if not payload:
            return False
        for p in patterns:
            pattern = self._compiled_patterns.get(p)
            if pattern and not pattern.search(payload):
                return False
        return True
