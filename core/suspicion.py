"""可疑流量检测引擎

对不构成确认告警但值得关注的流量进行分类和导出。
判定结果分三级：high_suspicion / medium_suspicion / low_suspicion
导出格式包含 Wireshark 过滤表达式和 grep 关键字。
"""

import ipaddress
import math
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import yaml

from .parser import Packet


@dataclass
class SuspiciousItem:
    """单条可疑流量记录"""
    rule_id: str
    rule_name: str
    category: str
    severity: str           # high_suspicion / medium_suspicion / low_suspicion
    description: str
    packet: Packet
    matched_detail: str
    timestamp: str
    wireshark_filter: str   # Wireshark 可直接使用的过滤表达式
    grep_keywords: list[str] = field(default_factory=list)  # grep/搜索关键字


# 常见浏览器 UA 关键字（非浏览器 UA 视为可疑）
BROWSER_UA_KEYWORDS = [
    "Mozilla/", "Chrome/", "Firefox/", "Safari/", "Edge/",
    "Opera/", "MSIE ", "Trident/", "Chromium/", "Brave/",
    "Vivaldi/", "Seamonkey/", "Waterfox/",
]

# 常见扫描/攻击工具 UA
TOOL_UA_PATTERNS = [
    r'(?i)sqlmap', r'(?i)nikto', r'(?i)nmap', r'(?i)masscan',
    r'(?i)zgrab', r'(?i)goby', r'(?i)dirsearch', r'(?i)gobuster',
    r'(?i)ffuf', r'(?i)wfuzz', r'(?i)burpsuite', r'(?i)hydra',
    r'(?i)medusa', r'(?i)wpscan', r'(?i)joomscan', r'(?i)whatweb',
    r'(?i)httpx', r'(?i)nuclei', r'(?i)subfinder', r'(?i)amass',
    r'(?i)cobalt', r'(?i)sliver', r'(?i)havoc',
]
COMPILED_TOOL_UA = [re.compile(p) for p in TOOL_UA_PATTERNS]


class SuspicionEngine:
    """可疑流量检测引擎"""

    def __init__(self, rules_path: Optional[str] = None):
        self.rules: list[dict] = []
        self._compiled: dict[str, re.Pattern] = {}
        self._lock = threading.Lock()

        # 统计计数器（用于 rate-based 规则）
        self._error_counts: dict[str, int] = {}  # src_ip -> 4xx count
        self._dns_nxdomain: dict[str, int] = {}  # src_ip -> NXDOMAIN count

        if rules_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            rules_path = os.path.join(base_dir, "rules", "suspicion.yaml")

        self._load_rules(rules_path)

    def _load_rules(self, path: str) -> None:
        """加载 YAML 规则库"""
        if not os.path.exists(path):
            return
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not data:
            return

        for rule in data.get("rules", []):
            # 预编译正则
            for p in rule.get("patterns", []):
                if p not in self._compiled:
                    try:
                        self._compiled[p] = re.compile(p)
                    except re.error:
                        pass
            for cond in rule.get("conditions", []):
                if cond.get("operator") in ("regex",):
                    v = cond.get("value", "")
                    if v and v not in self._compiled:
                        try:
                            self._compiled[v] = re.compile(v)
                        except re.error:
                            pass
            self.rules.append(rule)

    def detect(self, packet: Packet) -> list[SuspiciousItem]:
        """对单个包进行可疑检测"""
        items: list[SuspiciousItem] = []

        for rule in self.rules:
            # 协议过滤
            rule_proto = rule.get("protocol", "").lower()
            if rule_proto and packet.protocol:
                if rule_proto not in packet.protocol.lower():
                    # TCP 规则也需要匹配（HTTP 在 TCP 之上）
                    if rule_proto == "tcp" and packet.protocol.upper() not in ("TCP", "HTTP"):
                        continue
                    elif rule_proto != "tcp":
                        continue

            detail = None
            mode = rule.get("mode", "condition")

            if mode == "pattern":
                detail = self._check_patterns(packet, rule)
            elif mode == "condition":
                detail = self._check_conditions(packet, rule)

            if detail is not None:
                wf = self._build_wireshark_filter(packet, rule)
                gk = self._build_grep_keywords(packet, rule)

                items.append(SuspiciousItem(
                    rule_id=rule.get("id", ""),
                    rule_name=rule.get("name", ""),
                    category=rule.get("category", ""),
                    severity=rule.get("severity", "medium_suspicion"),
                    description=rule.get("description", ""),
                    packet=packet,
                    matched_detail=detail,
                    timestamp=packet.timestamp_str,
                    wireshark_filter=wf,
                    grep_keywords=gk,
                ))

        return items

    def _check_patterns(self, packet: Packet, rule: dict) -> Optional[str]:
        """正则模式匹配"""
        target_fields = rule.get("target_fields", [])
        patterns = rule.get("patterns", [])

        for field_name in target_fields:
            value = self._get_field(packet, field_name)
            if not value:
                continue
            for p in patterns:
                compiled = self._compiled.get(p)
                if compiled:
                    m = compiled.search(value)
                    if m:
                        return f"{field_name}: ...{m.group(0)[:80]}..."
        return None

    def _check_conditions(self, packet: Packet, rule: dict) -> Optional[str]:
        """复合条件匹配"""
        conditions = rule.get("conditions", [])
        details = []

        for cond in conditions:
            field_name = cond.get("field", "")
            operator = cond.get("operator", "")
            expected = cond.get("value")

            result = self._eval_condition(packet, field_name, operator, expected)
            if result is None:
                return None
            if result:
                details.append(result)

        return " | ".join(details) if details else None

    def _eval_condition(self, pkt: Packet, field_name: str,
                        operator: str, expected) -> Optional[str | None]:
        """评估单个条件，返回描述字符串(True) / None(不匹配/跳过) / False(条件失败)"""
        # 获取实际值
        actual = self._get_condition_value(pkt, field_name)
        if actual is None:
            return None  # 字段不存在，跳过此条件

        if operator == "eq":
            if str(actual).lower() == str(expected).lower():
                return f"{field_name}={actual}"
            return None

        elif operator == "contains":
            if str(expected).lower() in str(actual).lower():
                return f"{field_name}: {actual}"
            return None

        elif operator == "regex":
            pattern = self._compiled.get(str(expected))
            if pattern and pattern.search(str(actual)):
                return f"{field_name}: matched"
            return None

        elif operator == "not_browser_ua":
            # 非浏览器 UA 检测
            ua = str(actual)
            is_browser = any(kw in ua for kw in BROWSER_UA_KEYWORDS)
            if not is_browser and ua:
                # 检查是否是已知工具
                is_tool = any(p.search(ua) for p in COMPILED_TOOL_UA)
                if is_tool:
                    return f"UA(工具): {ua[:100]}"
                return f"UA(非浏览器): {ua[:100]}"
            return None

        elif operator == "not_in":
            allowed = [s.strip().upper() for s in str(expected).split(",")]
            if str(actual).upper() not in allowed:
                return f"method={actual}"
            return None

        elif operator == "in_list":
            values = [s.strip() for s in str(expected).split(",")]
            if str(actual) in values:
                return f"{field_name}={actual}"
            return None

        elif operator == "range":
            # 范围匹配，如 "5.0-7.0" 或 "400-499"
            try:
                parts = str(expected).split("-")
                low, high = float(parts[0]), float(parts[1])
                val = float(actual)
                if low <= val <= high:
                    return f"{field_name}={actual}"
            except (ValueError, IndexError):
                pass
            return None

        elif operator == "is_private":
            try:
                addr = ipaddress.ip_address(str(actual))
                if addr.is_private == expected:
                    return None  # 条件满足但不输出详情
            except ValueError:
                pass
            return None

        elif operator == "is_public":
            try:
                addr = ipaddress.ip_address(str(actual))
                if not addr.is_private and not addr.is_loopback:
                    return None
            except ValueError:
                pass
            return None

        elif operator == "hour_range":
            # 检查时间是否在指定小时范围内
            try:
                parts = str(expected).split("-")
                start_h, end_h = int(parts[0]), int(parts[1])
                if pkt.timestamp:
                    hour = datetime.fromtimestamp(pkt.timestamp).hour
                    if start_h <= hour < end_h:
                        return f"time={datetime.fromtimestamp(pkt.timestamp).strftime('%H:%M')}"
            except (ValueError, IndexError):
                pass
            return None

        return None

    def _get_condition_value(self, pkt: Packet, field_name: str):
        """获取条件字段的值"""
        if field_name == "method":
            return pkt.http.method if pkt.http else None
        elif field_name == "content_type":
            return pkt.http.content_type if pkt.http else None
        elif field_name == "user_agent":
            return pkt.http.user_agent if pkt.http else None
        elif field_name == "cookie":
            return pkt.http.cookie if pkt.http else None
        elif field_name == "status_code":
            return pkt.http.status_code if pkt.http else None
        elif field_name == "body_entropy":
            if pkt.http and pkt.http.request_body_raw:
                return self._calc_entropy(pkt.http.request_body_raw)
            return None
        elif field_name == "query_name":
            return pkt.dns.query_name if pkt.dns else None
        elif field_name == "query_type":
            return pkt.dns.query_type if pkt.dns else None
        elif field_name == "subdomain_length":
            if pkt.dns and pkt.dns.query_name:
                parts = pkt.dns.query_name.split(".")
                if len(parts) > 1:
                    return len(parts[0])
            return None
        elif field_name == "dst_port":
            return str(pkt.dst_port) if pkt.dst_port else None
        elif field_name == "src_ip":
            return pkt.src_ip
        elif field_name == "dst_ip":
            return pkt.dst_ip
        elif field_name == "cert_equals":
            if pkt.tls and pkt.tls.cert_subject and pkt.tls.cert_issuer:
                if pkt.tls.cert_subject == pkt.tls.cert_issuer:
                    return "self-signed"
            return None
        elif field_name == "tls_version":
            return pkt.tls.version if pkt.tls else None
        return None

    def _get_field(self, packet: Packet, field_name: str) -> str:
        """从数据包提取字段值"""
        if field_name == "uri":
            if packet.http:
                return packet.http.uri or packet.http.full_uri
        elif field_name == "body":
            if packet.http:
                return packet.http.request_body
        elif field_name == "header":
            if packet.http:
                parts = [packet.http.user_agent, packet.http.content_type,
                         packet.http.referer, packet.http.cookie]
                return " ".join(p for p in parts if p)
        elif field_name == "payload":
            return packet.payload_preview
        return ""

    def _build_wireshark_filter(self, pkt: Packet, rule: dict) -> str:
        """构建 Wireshark 过滤表达式"""
        parts = []

        # 基础过滤：IP + 端口
        if pkt.src_ip:
            parts.append(f"ip.addr=={pkt.src_ip}")
        if pkt.dst_port:
            parts.append(f"tcp.port=={pkt.dst_port}")

        # 根据类别添加特定过滤
        cat = rule.get("category", "")

        if cat == "sensitive_path":
            if pkt.http and pkt.http.uri:
                # 提取路径关键字
                uri = pkt.http.uri
                keywords = ["/actuator", "/env", "/.git", "/swagger", "/admin",
                            "/phpinfo", "/phpmyadmin", "/debug", "/console",
                            "/manage", "/nacos", "/eureka", "/druid", "/heapdump"]
                for kw in keywords:
                    if kw.lower() in uri.lower():
                        parts.append(f'http.request.uri contains "{kw}"')
                        break
        elif cat == "suspicious_ua":
            if pkt.http and pkt.http.user_agent:
                ua = pkt.http.user_agent[:50]
                parts.append(f'http.user_agent contains "{ua}"')
        elif cat == "unusual_method":
            if pkt.http and pkt.http.method:
                parts.append(f'http.request.method == "{pkt.http.method}"')
        elif cat == "dns_anomaly":
            if pkt.dns and pkt.dns.query_name:
                domain = pkt.dns.query_name
                parts = [f'dns.qry.name contains "{domain}"']
        elif cat == "high_entropy":
            parts.append('http.request.method == "POST"')
            if pkt.http and pkt.http.content_type:
                parts.append(f'http.content_type contains "{pkt.http.content_type}"')
        elif cat == "tls_anomaly":
            parts = [f'ip.addr=={pkt.src_ip}']
            if pkt.tls and pkt.tls.sni:
                parts.append(f'tls.handshake.extensions_server_name == "{pkt.tls.sni}"')

        return " && ".join(parts) if parts else f"frame.number == {pkt.frame_num}"

    def _build_grep_keywords(self, pkt: Packet, rule: dict) -> list[str]:
        """构建 grep/搜索关键字列表"""
        keywords = []

        # IP 地址（始终包含）
        if pkt.src_ip:
            keywords.append(pkt.src_ip)
        if pkt.dst_ip:
            keywords.append(pkt.dst_ip)

        cat = rule.get("category", "")

        if cat == "sensitive_path":
            if pkt.http and pkt.http.uri:
                # 提取路径片段
                uri = pkt.http.uri.split("?")[0]
                if len(uri) > 3:
                    keywords.append(uri)
        elif cat == "suspicious_ua":
            if pkt.http and pkt.http.user_agent:
                # 取 UA 的工具名部分
                ua = pkt.http.user_agent.split("/")[0].strip()
                if ua:
                    keywords.append(ua)
        elif cat == "dns_anomaly":
            if pkt.dns and pkt.dns.query_name:
                keywords.append(pkt.dns.query_name)
        elif cat == "unusual_port":
            keywords.append(str(pkt.dst_port))
        elif cat == "high_entropy":
            if pkt.http and pkt.http.uri:
                keywords.append(pkt.http.uri.split("?")[0])
        elif cat == "tls_anomaly":
            if pkt.tls and pkt.tls.sni:
                keywords.append(pkt.tls.sni)

        # 端口（始终包含）
        if pkt.dst_port:
            keywords.append(str(pkt.dst_port))

        # 去重
        seen = set()
        result = []
        for kw in keywords:
            if kw not in seen:
                seen.add(kw)
                result.append(kw)
        return result

    @staticmethod
    def _calc_entropy(data: bytes) -> float:
        """计算香农熵"""
        if not data:
            return 0.0
        length = len(data)
        freq: dict[int, int] = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 2)


class SuspiciousExporter:
    """可疑流量导出器"""

    def __init__(self, output_path: str):
        self.output_path = output_path
        self._lock = threading.Lock()
        self._count = 0
        self._file = None

    def open(self):
        """打开导出文件"""
        self._file = open(self.output_path, "w", encoding="utf-8")
        # 写入表头
        self._file.write("# 可疑流量导出报告\n")
        self._file.write(f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._file.write("# 格式: [时间] | 严重度 | src:port -> dst:port | proto | 指标摘要 | Wireshark过滤器 | grep关键字\n")
        self._file.write("#" + "=" * 120 + "\n")

    def close(self):
        """关闭导出文件"""
        if self._file:
            self._file.write("#" + "=" * 120 + "\n")
            self._file.write(f"# 共导出 {self._count} 条可疑流量\n")
            self._file.close()

    def write(self, item: SuspiciousItem) -> None:
        """写入一条可疑记录"""
        with self._lock:
            if not self._file:
                return

            pkt = item.packet
            src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_ip else "N/A"
            dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_ip else "N/A"
            proto = pkt.protocol or "N/A"

            # 简洁单行格式
            sev_tag = item.severity.replace("_suspicion", "").upper()
            grep_str = "|".join(item.grep_keywords[:5])

            line = (
                f"{item.timestamp} | {sev_tag} | {src} -> {dst} | {proto} | "
                f"{item.matched_detail} | {item.wireshark_filter} | {grep_str}"
            )

            self._file.write(line + "\n")
            self._file.flush()
            self._count += 1

    @property
    def count(self) -> int:
        return self._count
