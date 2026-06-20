"""攻击特征检测引擎

基于 YAML 规则库的攻击特征检测，支持正则模式匹配和复合条件匹配。
覆盖 9 大类攻击：SQL注入、XSS、命令注入、目录遍历、文件上传、
反序列化、Webshell通信、C2通信、Log4Shell。
"""

import math
import os
import re
from dataclasses import dataclass
from typing import Optional

import yaml

from .parser import Packet


@dataclass
class Alert:
    """检测告警"""
    rule_id: str
    rule_name: str
    category: str
    severity: str
    packet: Packet
    matched_detail: str
    timestamp: str


class AttackDetector:
    """基于 YAML 规则库的攻击特征检测"""

    def __init__(self, rules_path: Optional[str] = None):
        self.rules: list[dict] = []
        self.enabled_categories: set[str] = set()  # 空 = 全部启用
        self._compiled: dict[str, re.Pattern] = {}  # 正则缓存

        if rules_path is None:
            # 默认规则文件路径（相对于本文件所在目录）
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            rules_path = os.path.join(base_dir, "rules", "signatures.yaml")

        self._load_rules(rules_path)

    def _load_rules(self, path: str) -> None:
        """加载 YAML 规则库"""
        if not os.path.exists(path):
            print(f"[WARN] 规则文件不存在: {path}")
            return

        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        raw_rules = data.get("rules", [])
        for rule in raw_rules:
            # 预编译规则中的正则
            patterns = rule.get("patterns", [])
            for p in patterns:
                if p not in self._compiled:
                    try:
                        self._compiled[p] = re.compile(p)
                    except re.error as e:
                        print(f"[WARN] 正则编译失败 [{rule.get('id')}]: {p} - {e}")

            # 编译条件中的正则
            for cond in rule.get("conditions", []):
                if cond.get("operator") == "regex":
                    v = cond.get("value", "")
                    if v and v not in self._compiled:
                        try:
                            self._compiled[v] = re.compile(v)
                        except re.error as e:
                            print(f"[WARN] 条件正则编译失败 [{rule.get('id')}]: {v} - {e}")

            self.rules.append(rule)

    def enable_categories(self, categories: list[str]) -> None:
        """选择性启用检测类别"""
        self.enabled_categories = set(categories)

    def detect(self, packet: Packet) -> list[Alert]:
        """对单个包运行所有启用的规则，返回告警列表"""
        alerts = []

        for rule in self.rules:
            # 类别过滤
            if self.enabled_categories:
                if rule.get("category") not in self.enabled_categories:
                    continue

            # 协议过滤
            rule_proto = rule.get("protocol", "").lower()
            if rule_proto and packet.protocol:
                if rule_proto not in packet.protocol.lower():
                    continue

            matched_detail = None
            mode = rule.get("mode", "pattern")

            if mode == "pattern":
                matched_detail = self._check_patterns(packet, rule)
            elif mode == "condition":
                matched_detail = self._check_conditions(packet, rule)

            if matched_detail is not None:
                alerts.append(Alert(
                    rule_id=rule.get("id", ""),
                    rule_name=rule.get("name", ""),
                    category=rule.get("category", ""),
                    severity=rule.get("severity", "medium"),
                    packet=packet,
                    matched_detail=matched_detail,
                    timestamp=packet.timestamp_str,
                ))

        return alerts

    def _get_field_value(self, packet: Packet, field: str) -> str:
        """从数据包中提取指定字段的值"""
        if field == "uri":
            if packet.http:
                return packet.http.uri or packet.http.full_uri
        elif field == "body":
            if packet.http:
                return packet.http.request_body
        elif field == "cookie":
            if packet.http:
                return packet.http.cookie
        elif field == "header":
            # 拼接所有 HTTP 头
            if packet.http:
                parts = [
                    packet.http.user_agent,
                    packet.http.content_type,
                    packet.http.referer,
                    packet.http.cookie,
                ]
                return " ".join(p for p in parts if p)
        elif field == "user_agent":
            if packet.http:
                return packet.http.user_agent
        elif field == "content_type":
            if packet.http:
                return packet.http.content_type
        elif field == "method":
            if packet.http:
                return packet.http.method
        elif field == "query_name":
            if packet.dns:
                return packet.dns.query_name
        elif field == "query_type":
            if packet.dns:
                return packet.dns.query_type
        elif field == "payload":
            return packet.payload_preview

        return ""

    def _check_patterns(self, packet: Packet, rule: dict) -> Optional[str]:
        """检查正则模式匹配，返回匹配详情或 None"""
        target_fields = rule.get("target_fields", [])
        patterns = rule.get("patterns", [])

        if not patterns:
            return None

        for field_name in target_fields:
            value = self._get_field_value(packet, field_name)
            if not value:
                continue
            for p in patterns:
                compiled = self._compiled.get(p)
                if compiled and compiled.search(value):
                    # 截取匹配内容作为详情
                    match = compiled.search(value)
                    match_text = match.group(0)[:100]
                    return f"{field_name}: ...{match_text}..."

        return None

    def _check_conditions(self, packet: Packet, rule: dict) -> Optional[str]:
        """检查复合条件（所有条件 AND），返回匹配详情或 None"""
        conditions = rule.get("conditions", [])
        if not conditions:
            return None

        details = []

        for cond in conditions:
            field = cond.get("field", "")
            operator = cond.get("operator", "")
            expected = cond.get("value")

            actual = self._get_condition_value(packet, field)
            if actual is None:
                return None

            result = self._evaluate_condition(actual, operator, expected)
            if not result:
                return None

            details.append(f"{field}={actual}")

        return " | ".join(details)

    def _get_condition_value(self, packet: Packet, field: str):
        """获取条件字段的值（返回原始类型）"""
        if field == "method":
            return packet.http.method if packet.http else None
        elif field == "content_type":
            return packet.http.content_type if packet.http else None
        elif field == "user_agent":
            return packet.http.user_agent if packet.http else None
        elif field == "cookie":
            return packet.http.cookie if packet.http else None
        elif field == "body":
            return packet.http.request_body if packet.http else None
        elif field == "body_entropy":
            if packet.http and packet.http.request_body_raw:
                return self._calc_entropy(packet.http.request_body_raw)
            return None
        elif field == "body_length_mod16":
            if packet.http and packet.http.request_body_raw:
                return len(packet.http.request_body_raw) % 16
            return None
        elif field == "query_name":
            return packet.dns.query_name if packet.dns else None
        elif field == "query_type":
            return packet.dns.query_type if packet.dns else None
        elif field == "query_frequency":
            # 此字段需要外部统计，这里返回 0（外部处理）
            return 0
        elif field == "subdomain_entropy":
            if packet.dns and packet.dns.query_name:
                return self._subdomain_entropy(packet.dns.query_name)
            return None
        elif field == "subdomain_length":
            if packet.dns and packet.dns.query_name:
                name = packet.dns.query_name
                parts = name.split(".")
                if len(parts) > 1:
                    return len(parts[0])  # 子域名长度
            return None
        return None

    def _evaluate_condition(self, actual, operator: str, expected) -> bool:
        """评估条件表达式"""
        if operator == "eq":
            if isinstance(actual, str):
                return actual.lower() == str(expected).lower()
            return actual == expected
        elif operator == "contains":
            return str(expected).lower() in str(actual).lower()
        elif operator == "regex":
            pattern = self._compiled.get(str(expected))
            if pattern:
                return bool(pattern.search(str(actual)))
            return False
        elif operator == "gte":
            if isinstance(actual, (int, float)):
                return actual >= float(expected)
            return False
        elif operator == "lte":
            if isinstance(actual, (int, float)):
                return actual <= float(expected)
            return False
        elif operator == "subdomain_entropy":
            if isinstance(actual, (int, float)):
                return actual >= float(expected)
            return False
        elif operator == "subdomain_length":
            if isinstance(actual, (int, float)):
                return actual >= float(expected)
            return False
        return False

    @staticmethod
    def _calc_entropy(data: bytes) -> float:
        """计算香农熵值，加密数据通常 > 7.0"""
        if not data:
            return 0.0
        length = len(data)
        freq: dict[int, int] = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 2)

    @staticmethod
    def _subdomain_entropy(domain: str) -> float:
        """计算子域名部分的熵值"""
        parts = domain.split(".")
        if len(parts) < 2:
            return 0.0
        subdomain = parts[0]
        if not subdomain:
            return 0.0
        length = len(subdomain)
        freq: dict[str, int] = {}
        for ch in subdomain:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 2)
