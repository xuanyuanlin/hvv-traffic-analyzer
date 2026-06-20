"""IOC（威胁情报指标）自动提取模块

从流量中提取 IP、域名、URL、User-Agent、TLS 指纹等 IOC。
支持白名单过滤、去重、时间追踪。
"""

import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

import yaml

from .parser import Packet


@dataclass
class IOC:
    """单条 IOC 记录"""
    type: str              # ip / domain / url / ua / ja3 / ja4
    value: str
    source: str            # 来源描述
    first_seen: str = ""
    last_seen: str = ""
    count: int = 1
    suspicious: bool = False


class IOCExtractor:
    """从流量中自动提取 IOC"""

    def __init__(self, whitelist_path: Optional[str] = None,
                 patterns_path: Optional[str] = None):
        self.iocs: dict[str, dict[str, IOC]] = defaultdict(dict)
        self.whitelist: set[str] = set()
        self._patterns: dict = {}

        if whitelist_path and os.path.exists(whitelist_path):
            self._load_whitelist(whitelist_path)

        if patterns_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            patterns_path = os.path.join(base_dir, "rules", "ioc_patterns.yaml")

        self._load_patterns(patterns_path)

    def _load_whitelist(self, path: str) -> None:
        """加载白名单文件（每行一个 IP 或域名）"""
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    self.whitelist.add(line.lower())

    def _load_patterns(self, path: str) -> None:
        """加载 IOC 提取模式"""
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if data:
            self._patterns = data.get("patterns", {})

    def extract(self, packet: Packet) -> list[IOC]:
        """从单个包提取所有可能的 IOC"""
        iocs: list[IOC] = []
        iocs.extend(self._extract_ips(packet))
        iocs.extend(self._extract_domains(packet))
        iocs.extend(self._extract_urls(packet))
        iocs.extend(self._extract_user_agents(packet))
        iocs.extend(self._extract_tls_fingerprints(packet))

        # 更新去重记录
        for ioc in iocs:
            self._update_ioc(ioc)

        return iocs

    def summary(self) -> dict[str, dict[str, IOC]]:
        """返回去重后的 IOC 汇总"""
        return dict(self.iocs)

    def summary_counts(self) -> dict[str, int]:
        """返回各类型 IOC 数量"""
        return {k: len(v) for k, v in self.iocs.items()}

    def export_iocs(self, path: str, ioc_data: dict = None) -> None:
        """导出 IOC 到 JSON 文件"""
        import json
        data = ioc_data or self.iocs
        export = {}
        for ioc_type, bucket in data.items():
            export[ioc_type] = {}
            for value, ioc in bucket.items():
                export[ioc_type][value] = {
                    "count": ioc.count,
                    "suspicious": ioc.suspicious,
                    "source": ioc.source,
                    "first_seen": ioc.first_seen,
                    "last_seen": ioc.last_seen,
                }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(export, f, ensure_ascii=False, indent=2)

    def _update_ioc(self, ioc: IOC) -> None:
        """更新或新增 IOC 记录"""
        bucket = self.iocs[ioc.type]
        if ioc.value in bucket:
            existing = bucket[ioc.value]
            existing.count += 1
            existing.last_seen = ioc.last_seen
            if ioc.suspicious:
                existing.suspicious = True
        else:
            bucket[ioc.value] = ioc

    def _is_whitelisted(self, value: str) -> bool:
        """检查是否在白名单中"""
        return value.lower() in self.whitelist

    def _extract_ips(self, packet: Packet) -> list[IOC]:
        """提取 IP 地址"""
        iocs = []
        ip_pattern = self._patterns.get("ip", {}).get("regex", "")
        if not ip_pattern:
            ip_pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'

        # 从源/目的 IP 提取
        for ip, direction in [(packet.src_ip, "src"), (packet.dst_ip, "dst")]:
            if ip and not self._is_whitelisted(ip):
                iocs.append(IOC(
                    type="ip",
                    value=ip,
                    source=f"packet {direction} IP",
                    first_seen=packet.timestamp_str,
                    last_seen=packet.timestamp_str,
                ))

        # 从 payload 中提取额外 IP
        if packet.payload_preview:
            for match in re.finditer(ip_pattern, packet.payload_preview):
                ip = match.group(0)
                if not self._is_whitelisted(ip) and ip not in (packet.src_ip, packet.dst_ip):
                    iocs.append(IOC(
                        type="ip",
                        value=ip,
                        source="payload content",
                        first_seen=packet.timestamp_str,
                        last_seen=packet.timestamp_str,
                        suspicious=True,
                    ))

        return iocs

    def _extract_domains(self, packet: Packet) -> list[IOC]:
        """提取域名"""
        iocs = []
        domain_pattern = self._patterns.get("domain", {}).get("regex", "")
        if not domain_pattern:
            domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'

        exclude_tlds = set(self._patterns.get("domain", {}).get("exclude_tlds", []))

        sources = []

        # HTTP Host
        if packet.http and packet.http.host:
            sources.append((packet.http.host, "HTTP Host header"))

        # DNS 查询
        if packet.dns and packet.dns.query_name:
            sources.append((packet.dns.query_name, "DNS query"))

        # TLS SNI
        if packet.tls and packet.tls.sni:
            sources.append((packet.tls.sni, "TLS SNI"))

        for domain, source in sources:
            domain = domain.lower().rstrip(".")
            if not domain:
                continue
            # 检查 TLD 排除
            tld = "." + domain.rsplit(".", 1)[-1] if "." in domain else ""
            if tld in exclude_tlds:
                continue
            if not self._is_whitelisted(domain):
                iocs.append(IOC(
                    type="domain",
                    value=domain,
                    source=source,
                    first_seen=packet.timestamp_str,
                    last_seen=packet.timestamp_str,
                ))

        return iocs

    def _extract_urls(self, packet: Packet) -> list[IOC]:
        """提取 URL"""
        iocs = []
        if not packet.http:
            return iocs

        host = packet.http.host
        uri = packet.http.full_uri or packet.http.uri
        if not uri:
            return iocs

        # 构建完整 URL
        if uri.startswith("http"):
            url = uri
        elif host:
            scheme = "https" if packet.dst_port == 443 else "http"
            url = f"{scheme}://{host}{uri}"
        else:
            return iocs

        if not self._is_whitelisted(url):
            iocs.append(IOC(
                type="url",
                value=url,
                source="HTTP request",
                first_seen=packet.timestamp_str,
                last_seen=packet.timestamp_str,
            ))

        return iocs

    def _extract_user_agents(self, packet: Packet) -> list[IOC]:
        """提取可疑 User-Agent"""
        iocs = []
        if not packet.http or not packet.http.user_agent:
            return iocs

        ua = packet.http.user_agent.strip()
        if not ua:
            return iocs

        # 检查是否匹配可疑模式
        suspicious_patterns = self._patterns.get("user_agent", {}).get("suspicious_patterns", [])
        is_suspicious = False
        for p in suspicious_patterns:
            try:
                if re.search(p, ua, re.IGNORECASE):
                    is_suspicious = True
                    break
            except re.error:
                pass

        # 非常见浏览器 UA 也标记为可疑
        common_browsers = [
            "Mozilla/", "Chrome/", "Firefox/", "Safari/", "Edge/",
            "Opera/", "MSIE ", "Trident/"
        ]
        is_browser = any(b in ua for b in common_browsers)

        if is_suspicious or not is_browser:
            iocs.append(IOC(
                type="ua",
                value=ua[:200],  # 截断过长 UA
                source="HTTP User-Agent header",
                first_seen=packet.timestamp_str,
                last_seen=packet.timestamp_str,
                suspicious=is_suspicious or not is_browser,
            ))

        return iocs

    def _extract_tls_fingerprints(self, packet: Packet) -> list[IOC]:
        """提取 TLS 指纹（JA3/JA4）"""
        iocs = []
        if not packet.tls:
            return iocs

        if packet.tls.ja3:
            iocs.append(IOC(
                type="ja3",
                value=packet.tls.ja3,
                source="TLS Client Hello",
                first_seen=packet.timestamp_str,
                last_seen=packet.timestamp_str,
            ))

        if packet.tls.ja3s:
            iocs.append(IOC(
                type="ja3s",
                value=packet.tls.ja3s,
                source="TLS Server Hello",
                first_seen=packet.timestamp_str,
                last_seen=packet.timestamp_str,
            ))

        if packet.tls.ja4:
            iocs.append(IOC(
                type="ja4",
                value=packet.tls.ja4,
                source="TLS Client Hello (JA4)",
                first_seen=packet.timestamp_str,
                last_seen=packet.timestamp_str,
            ))

        if packet.tls.ja4s:
            iocs.append(IOC(
                type="ja4s",
                value=packet.tls.ja4s,
                source="TLS Server Hello (JA4S)",
                first_seen=packet.timestamp_str,
                last_seen=packet.timestamp_str,
            ))

        return iocs
