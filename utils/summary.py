"""统计报告生成模块

收集运行时的统计数据，生成流量分析报告。
"""

import json
import os
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

from core.detector import Alert
from core.extractor import IOC


class StatsCollector:
    """统计数据收集与报告生成"""

    def __init__(self):
        self._lock = threading.Lock()

        # 计数器
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.total_packets: int = 0
        self.total_bytes: int = 0

        # 协议分布
        self.protocol_counts: dict[str, int] = defaultdict(int)

        # 告警统计
        self.alerts: list[Alert] = []
        self.alerts_by_category: dict[str, int] = defaultdict(int)
        self.alerts_by_severity: dict[str, list[Alert]] = defaultdict(list)

        # 可疑流量统计
        self.suspicious_count: int = 0
        self.suspicious_by_severity: dict[str, int] = defaultdict(int)
        self.suspicious_by_category: dict[str, int] = defaultdict(int)

        # 攻击源统计
        self.attack_sources: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

        # IOC 计数
        self.ioc_counts: dict[str, int] = defaultdict(int)

    def start(self):
        """记录开始时间"""
        self.start_time = time.time()

    def stop(self):
        """记录结束时间"""
        self.end_time = time.time()

    def record_packet(self, packet) -> None:
        """记录一个数据包的统计信息"""
        with self._lock:
            self.total_packets += 1
            self.total_bytes += packet.length
            if packet.protocol:
                self.protocol_counts[packet.protocol.upper()] += 1

    def record_alert(self, alert: Alert) -> None:
        """记录一条告警"""
        with self._lock:
            self.alerts.append(alert)
            self.alerts_by_category[alert.category] += 1
            self.alerts_by_severity[alert.severity].append(alert)

            # 攻击源统计
            src_ip = alert.packet.src_ip
            if src_ip:
                self.attack_sources[src_ip][alert.category] += 1

    def record_iocs(self, iocs: list[IOC]) -> None:
        """记录 IOC"""
        with self._lock:
            for ioc in iocs:
                self.ioc_counts[ioc.type] += 1

    def record_suspicious(self, item) -> None:
        """记录可疑流量"""
        with self._lock:
            self.suspicious_count += 1
            self.suspicious_by_severity[item.severity] += 1
            self.suspicious_by_category[item.category] += 1

    def generate_report(self, ioc_summary: dict = None) -> str:
        """生成统计报告"""
        with self._lock:
            return self._build_report(ioc_summary)

    def export_json(self, path: str, ioc_summary: dict = None) -> None:
        """导出详细数据为 JSON"""
        with self._lock:
            data = {
                "period": {
                    "start": datetime.fromtimestamp(self.start_time).isoformat() if self.start_time else "",
                    "end": datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else "",
                    "duration_seconds": round(self.end_time - self.start_time, 1) if self.end_time else 0,
                },
                "traffic": {
                    "total_packets": self.total_packets,
                    "total_bytes": self.total_bytes,
                    "protocol_distribution": dict(self.protocol_counts),
                },
                "alerts": {
                    "total": len(self.alerts),
                    "by_severity": {
                        sev: len(alerts) for sev, alerts in self.alerts_by_severity.items()
                    },
                    "by_category": dict(self.alerts_by_category),
                    "details": [
                        {
                            "timestamp": a.timestamp,
                            "rule_id": a.rule_id,
                            "rule_name": a.rule_name,
                            "category": a.category,
                            "severity": a.severity,
                            "src_ip": a.packet.src_ip,
                            "dst_ip": a.packet.dst_ip,
                            "src_port": a.packet.src_port,
                            "dst_port": a.packet.dst_port,
                            "protocol": a.packet.protocol,
                            "detail": a.matched_detail,
                        }
                        for a in self.alerts
                    ],
                },
                "attack_sources": {
                    ip: dict(cats) for ip, cats in self.attack_sources.items()
                },
                "ioc_summary": {
                    ioc_type: {
                        value: {
                            "count": ioc.count,
                            "suspicious": ioc.suspicious,
                            "source": ioc.source,
                            "first_seen": ioc.first_seen,
                            "last_seen": ioc.last_seen,
                        }
                        for value, ioc in bucket.items()
                    }
                    for ioc_type, bucket in (ioc_summary or {}).items()
                },
            }

            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

    def _build_report(self, ioc_summary: dict = None) -> str:
        """构建报告文本"""
        lines = []
        sep = "═" * 56

        lines.append(sep)
        lines.append("  流量分析报告")
        lines.append(sep)
        lines.append("")

        # 流量统计
        duration = 0.0
        if self.start_time:
            end = self.end_time or time.time()
            duration = end - self.start_time

        lines.append("[流量统计]")
        lines.append(f"  总包数:   {self.total_packets:,}")
        lines.append(f"  总字节:   {self._format_bytes(self.total_bytes)}")
        lines.append(f"  监控时长: {duration:.0f}s")
        if duration > 0:
            bps = (self.total_bytes * 8) / duration
            lines.append(f"  平均速率: {self._format_bps(bps)}")
        lines.append("")

        # 协议分布
        if self.protocol_counts:
            total_proto = sum(self.protocol_counts.values())
            lines.append("[协议分布]")
            sorted_proto = sorted(self.protocol_counts.items(), key=lambda x: -x[1])
            for proto, count in sorted_proto[:10]:
                pct = (count / total_proto * 100) if total_proto > 0 else 0
                lines.append(f"  {proto:<16} {count:>10,} ({pct:5.1f}%)")
            lines.append("")

        # 告警统计
        total_alerts = len(self.alerts)
        lines.append(f"[攻击检测] 共 {total_alerts} 条告警")

        severity_order = ["critical", "high", "medium", "low"]
        for sev in severity_order:
            alerts = self.alerts_by_severity.get(sev, [])
            if not alerts:
                continue
            lines.append(f"  {sev.upper()} ({len(alerts)}):")
            # 按类别聚合
            cat_counts = defaultdict(int)
            for a in alerts:
                cat_counts[a.category] += 1
            for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
                cat_name = self._category_name(cat)
                lines.append(f"    · {cat_name:<28} {count} 条")
        lines.append("")

        # 可疑流量统计
        if self.suspicious_count > 0:
            lines.append(f"[可疑流量] 共 {self.suspicious_count} 条（已导出）")
            sev_names = {"high": "高度可疑", "medium": "中度可疑", "low": "低度可疑"}
            for sev_key in ["high_suspicion", "medium_suspicion", "low_suspicion"]:
                count = self.suspicious_by_severity.get(sev_key, 0)
                if count > 0:
                    label = sev_names.get(sev_key.split("_")[0], sev_key)
                    lines.append(f"  {label}: {count} 条")
            # 按类别 top 5
            if self.suspicious_by_category:
                sorted_cats = sorted(self.suspicious_by_category.items(), key=lambda x: -x[1])
                lines.append("  类别分布:")
                for cat, count in sorted_cats[:5]:
                    lines.append(f"    · {cat:<28} {count} 条")
            lines.append("")

        # IOC 汇总
        if ioc_summary:
            lines.append("[IOC 汇总]")
            type_names = {
                "ip": "恶意 IP", "domain": "恶意域名", "url": "可疑 URL",
                "ua": "异常 UA", "ja3": "JA3 指纹", "ja4": "JA4 指纹",
                "ja3s": "JA3S 指纹", "ja4s": "JA4S 指纹",
            }
            for ioc_type, bucket in ioc_summary.items():
                name = type_names.get(ioc_type, ioc_type.upper())
                lines.append(f"  {name}: {len(bucket)} 个")
            lines.append("")

        # Top 攻击源
        if self.attack_sources:
            lines.append("[Top 攻击源 IP]")
            sorted_sources = sorted(
                self.attack_sources.items(),
                key=lambda x: sum(x[1].values()),
                reverse=True
            )
            for rank, (ip, cats) in enumerate(sorted_sources[:10], 1):
                total = sum(cats.values())
                detail = ", ".join(f"{k}:{v}" for k, v in sorted(cats.items(), key=lambda x: -x[1]))
                lines.append(f"  {rank}. {ip:<18} {total:>3} 次告警 ({detail})")
            lines.append("")

        lines.append(sep)
        return "\n".join(lines)

    @staticmethod
    def _format_bytes(b: int) -> str:
        """格式化字节数"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if b < 1024:
                return f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} PB"

    @staticmethod
    def _format_bps(bps: float) -> str:
        """格式化比特率"""
        for unit in ["bps", "Kbps", "Mbps", "Gbps"]:
            if bps < 1000:
                return f"{bps:.1f} {unit}"
            bps /= 1000
        return f"{bps:.1f} Tbps"

    @staticmethod
    def _category_name(category: str) -> str:
        """类别 ID 转中文名"""
        names = {
            "sql_injection": "SQL 注入",
            "xss": "XSS 跨站脚本",
            "cmd_injection": "命令注入",
            "dir_traversal": "目录遍历",
            "file_upload": "文件上传",
            "deserialization": "反序列化",
            "webshell": "Webshell 通信",
            "c2": "C2 通信",
            "log4shell": "Log4Shell",
        }
        return names.get(category, category)
