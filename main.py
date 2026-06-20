"""护网行动流量分析工具 — CLI 入口

三分类流量分析：
- 确认攻击：实时告警（终端彩色 + 统计报告）
- 可疑流量：实时提示 + 导出文本文件（含 Wireshark 检索词）
- 普通流量：仅统计计数
"""

import argparse
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime

# 将项目根目录加入 path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.capture import TsharkCapture
from core.parser import parse_packet
from core.filter import TrafficFilter, FilterRule
from core.detector import AttackDetector
from core.extractor import IOCExtractor
from core.suspicion import SuspicionEngine, SuspiciousExporter
from utils.output import OutputManager
from utils.summary import StatsCollector

# 合法的检测类别
VALID_DETECT_CATEGORIES = {
    "sql_injection", "xss", "cmd_injection", "dir_traversal",
    "file_upload", "deserialization", "webshell", "c2", "log4shell"
}


def validate_ip(ip_str: str, label: str) -> bool:
    """验证 IP 地址或 CIDR 格式是否合法"""
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            print(f"错误: {label} 格式无效: '{ip_str}'")
            print(f"  正确格式: 10.0.0.1 或 192.168.0.0/16")
            return False


def validate_port(port: int) -> bool:
    """验证端口号是否合法"""
    if port < 1 or port > 65535:
        print(f"错误: 端口号无效: {port}（有效范围: 1-65535）")
        return False
    return True


def validate_detect_categories(categories_str: str) -> list[str] | None:
    """验证检测类别是否合法，返回合法类别列表或 None（表示有错误）"""
    categories = [c.strip() for c in categories_str.split(",")]
    invalid = [c for c in categories if c not in VALID_DETECT_CATEGORIES]
    if invalid:
        print(f"错误: 无效的检测类别: {', '.join(invalid)}")
        print(f"  可选类别: {', '.join(sorted(VALID_DETECT_CATEGORIES))}")
        return None
    return categories


def validate_file_exists(path: str, label: str) -> bool:
    """验证文件是否存在"""
    if not os.path.exists(path):
        print(f"错误: {label} 文件不存在: {path}")
        return False
    return True


def validate_interface(interface: str) -> bool:
    """验证网卡是否可用（尝试用 tshark -i <iface> -c 0 测试）"""
    try:
        # -c 0: 不抓包，只测试接口是否可用
        result = subprocess.run(
            ["tshark", "-i", interface, "-c", "0"],
            capture_output=True, text=True, timeout=5,
            encoding="utf-8", errors="replace"
        )
        # tshark 对无效接口返回非零退出码，且 stderr 有错误信息
        if result.returncode != 0:
            stderr = result.stderr.strip()
            if "The capture session could not be initiated" in stderr or \
               "couldn't open" in stderr.lower() or \
               "exit" in stderr.lower():
                print(f"错误: 网卡不可用: '{interface}'")
                # 尝试从 stderr 提取有用信息
                for line in stderr.splitlines():
                    line = line.strip()
                    if line and "tshark" not in line.lower():
                        print(f"  {line}")
                print(f"\n  使用 --list-interfaces 查看可用网卡")
                return False
        return True
    except subprocess.TimeoutExpired:
        # 超时通常意味着接口可用但等待数据包
        return True
    except FileNotFoundError:
        print("错误: tshark 未找到，请确认 Wireshark 已安装且 tshark 在 PATH 中")
        return False
    except Exception as e:
        print(f"警告: 无法验证网卡: {e}")
        return True  # 不确定时放行


def auto_output_path(prefix: str, ext: str) -> str:
    """自动生成输出文件路径"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.{ext}"


def parse_args() -> argparse.Namespace:
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="护网行动实时流量分析工具 - HVV Traffic Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py -i "以太网"                          # 全量监控（默认）
  python main.py -i "以太网" -f "port 80 or port 53"  # 仅 HTTP + DNS
  python main.py -i "以太网" --src-ip 10.0.0.50       # 指定源 IP
  python main.py -i "以太网" --detect webshell,c2     # 仅检测 Webshell 和 C2
  python main.py -i "以太网" --suspicious-export       # 导出可疑流量
  python main.py --list-interfaces                     # 列出可用网卡
        """
    )

    # 基本参数
    parser.add_argument("-i", "--interface", help="网卡名或索引（用 --list-interfaces 查看）")
    parser.add_argument("--list-interfaces", action="store_true", help="列出所有可用网卡")
    parser.add_argument("--duration", type=int, help="抓包时长（秒），默认持续运行")

    # 过滤选项
    filt = parser.add_argument_group("过滤选项")
    filt.add_argument("-f", "--bpf-filter", help='BPF 过滤表达式（如 "port 80 or port 53"）')
    filt.add_argument("--src-ip", help="源 IP 过滤（支持 CIDR）")
    filt.add_argument("--dst-ip", help="目的 IP 过滤（支持 CIDR）")
    filt.add_argument("--port", type=int, help="端口过滤（1-65535）")
    filt.add_argument("--protocol", help="协议过滤（http/dns/tls/smb/rdp/ssh）")
    filt.add_argument("--content", help="Payload 内容正则匹配")
    filt.add_argument("--http-method", help="HTTP 方法过滤")
    filt.add_argument("--http-uri", help="HTTP URI 正则匹配")
    filt.add_argument("--ua-pattern", help="User-Agent 正则匹配")

    # 检测选项
    det = parser.add_argument_group("检测选项")
    det.add_argument("--detect", help="启用的检测类别（逗号分隔），可选: sql_injection,xss,"
                                      "cmd_injection,dir_traversal,file_upload,"
                                      "deserialization,webshell,c2,log4shell")
    det.add_argument("--rules", help="自定义确认攻击规则文件路径")
    det.add_argument("--no-detect", action="store_true", help="禁用所有确认攻击检测")

    # IOC 选项
    ioc = parser.add_argument_group("IOC 提取选项")
    ioc.add_argument("--extract-ioc", action="store_true", help="启用 IOC 自动提取")
    ioc.add_argument("--ioc-whitelist", help="IOC 白名单文件路径")
    ioc.add_argument("--ioc-export", nargs="?", const="auto",
                     help="导出 IOC 到 JSON 文件（不指定路径则自动生成: ioc_<timestamp>.json）")

    # 可疑流量选项
    sus = parser.add_argument_group("可疑流量选项")
    sus.add_argument("--suspicious-export", nargs="?", const="auto",
                     help="导出可疑流量到文本文件（不指定路径则自动生成: suspicious_traffic_<timestamp>.txt）")
    sus.add_argument("--no-suspicious", action="store_true",
                     help="禁用可疑流量检测")
    sus.add_argument("--suspicious-rules", help="自定义可疑流量规则文件路径")

    # 输出选项
    out = parser.add_argument_group("输出选项")
    out.add_argument("-o", "--output", nargs="?", const="auto",
                     help="保存终端输出到日志文件（不指定路径则自动生成: capture_<timestamp>.log）")
    out.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    out.add_argument("--quiet", action="store_true", help="静默模式（仅输出告警和可疑）")
    out.add_argument("--summary-interval", type=int, default=300,
                     help="定期输出统计摘要间隔（秒，默认 300）")

    return parser.parse_args()


def build_filter(args) -> TrafficFilter:
    """根据 CLI 参数构建过滤规则"""
    tf = TrafficFilter()

    has_filter = any([
        args.src_ip, args.dst_ip, args.port, args.protocol,
        args.content, args.http_method, args.http_uri,
        args.ua_pattern
    ])
    if not has_filter:
        return tf

    rule = FilterRule(name="cli_filter")

    if args.src_ip:
        rule.src_ips = [args.src_ip]
    if args.dst_ip:
        rule.dst_ips = [args.dst_ip]
    if args.port:
        rule.dst_ports = [args.port]
        rule.src_ports = [args.port]
    if args.protocol:
        rule.protocols = [args.protocol]
    if args.content:
        rule.content_patterns = [args.content]
    if args.http_method:
        rule.http_methods = [args.http_method.split(",")]
    if args.http_uri:
        rule.http_uri_pattern = args.http_uri
    if args.ua_pattern:
        rule.http_ua_pattern = args.ua_pattern

    tf.add_rule(rule)
    return tf


def main():
    args = parse_args()

    # --- 列出网卡 ---
    if args.list_interfaces:
        try:
            interfaces = TsharkCapture.list_interfaces()
            if not interfaces:
                print("未找到可用网卡。请确认 Wireshark/tshark 已安装。")
                sys.exit(1)
            print("\n可用网卡列表:")
            print("-" * 60)
            for iface in interfaces:
                desc = f" ({iface['desc']})" if iface['desc'] else ""
                print(f"  {iface['index']:>2}. {iface['name']}{desc}")
            print("-" * 60)
            print(f"\n使用方式: python main.py -i \"{interfaces[0]['name']}\"")
        except Exception as e:
            print(f"错误: {e}")
            sys.exit(1)
        sys.exit(0)

    # --- 检查网卡参数 ---
    if not args.interface:
        print("错误: 请指定网卡")
        print("  使用 -i <网卡名> 指定，或 --list-interfaces 查看可用网卡")
        print("  示例: python main.py -i \"以太网\"")
        sys.exit(1)

    # ========== 参数验证 ==========
    errors = []

    # 验证 IP 格式
    if args.src_ip and not validate_ip(args.src_ip, "源 IP (--src-ip)"):
        errors.append("src_ip")
    if args.dst_ip and not validate_ip(args.dst_ip, "目的 IP (--dst-ip)"):
        errors.append("dst_ip")

    # 验证端口范围
    if args.port is not None and not validate_port(args.port):
        errors.append("port")

    # 验证检测类别
    detected_categories = None
    if args.detect:
        detected_categories = validate_detect_categories(args.detect)
        if detected_categories is None:
            errors.append("detect")

    # 验证时长
    if args.duration is not None and args.duration <= 0:
        print(f"错误: 时长必须大于 0（你输入了: {args.duration}）")
        errors.append("duration")

    # 验证自定义规则文件存在
    if args.rules and not validate_file_exists(args.rules, "确认攻击规则 (--rules)"):
        errors.append("rules")
    if args.suspicious_rules and not validate_file_exists(args.suspicious_rules, "可疑流量规则 (--suspicious-rules)"):
        errors.append("suspicious_rules")
    if args.ioc_whitelist and not validate_file_exists(args.ioc_whitelist, "IOC 白名单 (--ioc-whitelist)"):
        errors.append("ioc_whitelist")

    # 验证正则表达式语法
    if args.content:
        try:
            re.compile(args.content)
        except re.error as e:
            print(f"错误: --content 正则表达式语法无效: {e}")
            errors.append("content")
    if args.http_uri:
        try:
            re.compile(args.http_uri)
        except re.error as e:
            print(f"错误: --http-uri 正则表达式语法无效: {e}")
            errors.append("http_uri")
    if args.ua_pattern:
        try:
            re.compile(args.ua_pattern)
        except re.error as e:
            print(f"错误: --ua-pattern 正则表达式语法无效: {e}")
            errors.append("ua_pattern")

    if errors:
        print(f"\n共 {len(errors)} 个参数错误，请修正后重试。")
        sys.exit(1)

    # ========== 自动生成文件路径 ==========
    # -o 自动路径
    if args.output == "auto":
        args.output = auto_output_path("capture", "log")

    # --ioc-export 自动路径
    ioc_export_path = None
    if args.ioc_export == "auto":
        ioc_export_path = auto_output_path("ioc", "json")
    elif args.ioc_export:
        ioc_export_path = args.ioc_export

    # --suspicious-export 自动路径
    sus_export_path = None
    if args.suspicious_export == "auto":
        sus_export_path = auto_output_path("suspicious_traffic", "txt")
    elif args.suspicious_export:
        sus_export_path = args.suspicious_export

    # ========== 验证网卡可用性 ==========
    if not validate_interface(args.interface):
        sys.exit(1)

    # ========== 初始化模块 ==========
    out_mgr = OutputManager(
        no_color=args.no_color,
        quiet=args.quiet,
        log_file=args.output if args.output else None,
    )
    stats = StatsCollector()
    traffic_filter = build_filter(args)

    # 检测引擎
    detector = None
    if not args.no_detect:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        rules_path = args.rules or os.path.join(base_dir, "rules", "signatures.yaml")
        detector = AttackDetector(rules_path)
        if detected_categories:
            detector.enable_categories(detected_categories)
            out_mgr.info(f"检测类别: {', '.join(detected_categories)}")

    # IOC 提取器
    extractor = None
    if args.extract_ioc:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        patterns_path = os.path.join(base_dir, "rules", "ioc_patterns.yaml")
        extractor = IOCExtractor(
            whitelist_path=args.ioc_whitelist,
            patterns_path=patterns_path,
        )

    # 可疑流量检测引擎
    suspicion_engine = None
    suspicious_exporter = None
    if not args.no_suspicious:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        sus_rules_path = args.suspicious_rules or os.path.join(base_dir, "rules", "suspicion.yaml")
        suspicion_engine = SuspicionEngine(sus_rules_path)

        if sus_export_path:
            suspicious_exporter = SuspiciousExporter(sus_export_path)
            suspicious_exporter.open()

    # ========== 启动抓包 ==========
    capture = TsharkCapture(
        interface=args.interface,
        bpf_filter=args.bpf_filter,
        duration=args.duration,
    )

    # 优雅退出
    stop_event = threading.Event()

    def signal_handler(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)

    # 启动横幅
    categories_list = detected_categories if detected_categories else None
    out_mgr.banner(args.interface, args.bpf_filter, categories_list)

    # 显示启用的功能
    features = []
    if detector:
        features.append("确认攻击检测")
    if suspicion_engine:
        features.append("可疑流量检测")
    if suspicious_exporter:
        features.append(f"可疑流量导出 -> {sus_export_path}")
    if extractor:
        features.append("IOC 提取")
    if ioc_export_path:
        features.append(f"IOC 导出 -> {ioc_export_path}")
    if args.output:
        features.append(f"日志文件 -> {args.output}")
    if features:
        out_mgr.info(f"已启用: {' | '.join(features)}")

    try:
        capture.start()
    except Exception as e:
        out_mgr.error(f"启动 tshark 失败: {e}")
        out_mgr.error("请确认: 1) Wireshark/tshark 已安装  2) 以管理员权限运行")
        sys.exit(1)

    stats.start()
    last_summary_time = time.time()

    try:
        for raw in capture.packets():
            if stop_event.is_set():
                break

            # 解析数据包
            packet = parse_packet(raw)

            # 统计
            stats.record_packet(packet)

            # 过滤
            if traffic_filter.rules:
                matched_rules = traffic_filter.match(packet)
                if not matched_rules:
                    continue

            # 攻击检测（确认攻击）
            is_confirmed_attack = False
            if detector:
                alerts = detector.detect(packet)
                for alert in alerts:
                    stats.record_alert(alert)
                    out_mgr.alert(alert)
                    is_confirmed_attack = True

            # 可疑流量检测（仅对非确认攻击的包）
            if suspicion_engine and not is_confirmed_attack:
                suspicious_items = suspicion_engine.detect(packet)
                for item in suspicious_items:
                    stats.record_suspicious(item)
                    out_mgr.suspicious(item)
                    if suspicious_exporter:
                        suspicious_exporter.write(item)

            # IOC 提取
            if extractor:
                iocs = extractor.extract(packet)
                if iocs:
                    stats.record_iocs(iocs)
                    suspicious = [i for i in iocs if i.suspicious]
                    if suspicious:
                        out_mgr.ioc_found("ioc", suspicious)

            # 定期摘要
            now = time.time()
            if now - last_summary_time >= args.summary_interval:
                report = stats.generate_report(
                    extractor.summary() if extractor else None
                )
                out_mgr.print_report(report)
                last_summary_time = now

    except KeyboardInterrupt:
        pass
    finally:
        capture.stop()
        stats.stop()
        if suspicious_exporter:
            suspicious_exporter.close()
        out_mgr.info("正在停止抓包...")
        print()

    # ========== 最终报告 ==========
    ioc_data = extractor.summary() if extractor else None
    report = stats.generate_report(ioc_data)
    out_mgr.print_report(report)

    # 导出文件提示
    if suspicious_exporter:
        out_mgr.info(f"可疑流量已导出: {suspicious_exporter.output_path} ({suspicious_exporter.count} 条)")

    if ioc_export_path and extractor:
        extractor.export_iocs(ioc_export_path, ioc_data)
        out_mgr.info(f"IOC 已导出: {ioc_export_path}")

    if args.output:
        json_path = args.output.rsplit(".", 1)[0] + "_report.json"
        stats.export_json(json_path, ioc_data)
        out_mgr.info(f"详细报告已导出: {json_path}")

    out_mgr.close()


if __name__ == "__main__":
    main()
