"""终端彩色输出与告警格式化模块

基于 colorama 实现跨平台彩色终端输出。
"""

import sys
from datetime import datetime

try:
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    # 定义空替代
    class _Dummy:
        def __getattr__(self, _):
            return ""
    Fore = _Dummy()
    Style = _Dummy()
    Back = _Dummy()


# 严重程度颜色映射
SEVERITY_COLORS = {
    "critical": Fore.RED + Style.BRIGHT,
    "high": Fore.YELLOW + Style.BRIGHT,
    "medium": Fore.CYAN,
    "low": Fore.GREEN,
}

SEVERITY_ICONS = {
    "critical": "⚠",
    "high": "◆",
    "medium": "▸",
    "low": "•",
}


class OutputManager:
    """终端输出管理器"""

    def __init__(self, no_color: bool = False, quiet: bool = False,
                 log_file: str = None):
        self.no_color = no_color or not HAS_COLOR
        self.quiet = quiet
        self._log_file = None
        if log_file:
            self._log_file = open(log_file, "w", encoding="utf-8")

    def close(self):
        """关闭日志文件"""
        if self._log_file:
            self._log_file.close()

    def _print(self, text: str, color: str = ""):
        """打印到终端和日志文件"""
        if not self.no_color and color:
            print(f"{color}{text}{Style.RESET_ALL}")
        else:
            print(text)
        if self._log_file:
            self._log_file.write(text + "\n")
            self._log_file.flush()

    def info(self, msg: str):
        """普通信息"""
        if not self.quiet:
            self._print(f"[INFO] {msg}", Fore.WHITE)

    def warning(self, msg: str):
        """警告"""
        self._print(f"[WARN] {msg}", Fore.YELLOW)

    def error(self, msg: str):
        """错误"""
        self._print(f"[ERROR] {msg}", Fore.RED)

    def alert(self, alert) -> None:
        """格式化输出告警信息

        Args:
            alert: core.detector.Alert 对象
        """
        sev = alert.severity.lower()
        color = SEVERITY_COLORS.get(sev, "")
        icon = SEVERITY_ICONS.get(sev, "*")

        pkt = alert.packet
        src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_ip else "N/A"
        dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_ip else "N/A"
        proto = pkt.protocol or "N/A"

        # 构建详情行
        lines = [
            f"[{alert.timestamp}] [{alert.severity.upper()}] {icon} {alert.rule_name}",
            f"  ┌ 攻击源:  {src}",
            f"  ├ 目  标:  {dst} ({proto})",
            f"  ├ 详  情:  {alert.matched_detail}",
            f"  ├ 规  则:  {alert.rule_id}",
        ]

        # 协议详情
        if pkt.http:
            method = pkt.http.method or ""
            uri = pkt.http.uri or pkt.http.full_uri or ""
            lines.append(f"  └ 协  议:  HTTP {method} -> {uri}")
        elif pkt.dns:
            lines.append(f"  └ 协  议:  DNS {pkt.dns.query_type} {pkt.dns.query_name}")
        else:
            lines.append(f"  └ 协  议:  {proto}")

        # 打印
        for i, line in enumerate(lines):
            if i == 0:
                self._print(line, color)
            else:
                self._print(line, Fore.WHITE)

        # 空行分隔
        print()

    def ioc_found(self, ioc_type: str, iocs: list) -> None:
        """输出新发现的 IOC"""
        if not iocs:
            return
        for ioc in iocs:
            suspicious_mark = " (suspicious)" if ioc.suspicious else ""
            self._print(
                f"  [{ioc.type.upper()}] {ioc.value}{suspicious_mark} - {ioc.source}",
                Fore.MAGENTA
            )

    def suspicious(self, item) -> None:
        """格式化输出可疑流量信息（黄色）

        Args:
            item: core.suspicion.SuspiciousItem 对象
        """
        pkt = item.packet
        src = f"{pkt.src_ip}:{pkt.src_port}" if pkt.src_ip else "N/A"
        dst = f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.dst_ip else "N/A"
        proto = pkt.protocol or "N/A"

        sev_tag = item.severity.replace("_suspicion", "").upper()

        lines = [
            f"[{item.timestamp}] [{sev_tag}] ? {item.rule_name}",
            f"  ┌ 源 -> 目标:  {src} -> {dst} ({proto})",
            f"  ├ 详  情:  {item.matched_detail}",
            f"  ├ 规  则:  {item.rule_id} — {item.description}",
            f"  ├ Wireshark:  {item.wireshark_filter}",
            f"  └ 关键字:  {' | '.join(item.grep_keywords[:5])}",
        ]

        for i, line in enumerate(lines):
            if i == 0:
                self._print(line, Fore.YELLOW)
            else:
                self._print(line, Fore.YELLOW)
        print()

    def banner(self, interface: str, bpf_filter: str = None,
               categories: list[str] = None):
        """启动横幅"""
        self._print("=" * 60, Fore.CYAN)
        self._print("  HVV Traffic Analyzer - 护网行动流量分析工具", Fore.CYAN + Style.BRIGHT)
        self._print("=" * 60, Fore.CYAN)
        self.info(f"监控网卡: {interface}")
        if bpf_filter:
            self.info(f"BPF 过滤: {bpf_filter}")
        if categories:
            self.info(f"检测类别: {', '.join(categories)}")
        else:
            self.info("检测类别: 全部启用")
        self._print("-" * 60, Fore.CYAN)
        self.info("等待流量... (Ctrl+C 停止监控)")
        print()

    def print_report(self, report: str):
        """打印统计报告"""
        self._print(report, Fore.CYAN)
