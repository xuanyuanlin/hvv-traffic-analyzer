"""护网行动流量分析工具 — CLI 入口 + 交互式菜单

支持两种启动方式:
  python main.py                  # 交互式菜单模式
  python main.py -i "以太网" ...  # CLI 直接运行模式

三分类流量分析：
- 确认攻击：实时告警（终端彩色 + 统计报告）
- 可疑流量：实时提示 + 导出文本文件（含 Wireshark 检索词）
- 普通流量：仅统计计数
"""

import argparse
import ipaddress
import json
import math
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime

# 彩色终端
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False
    class _Dummy:
        def __getattr__(self, _): return ""
    Fore = _Dummy()
    Style = _Dummy()

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

# Windows 单键输入
try:
    import msvcrt
    HAS_MSVCRT = True
except ImportError:
    HAS_MSVCrt = False  # noqa: F841
    HAS_MSVCRT = False

# ─── 版本信息 ───────────────────────────────────────────
VERSION = "v2.0"
DEVELOPER = "lin"
REPO_URL = "https://github.com/xuanyuanlin/hvv-traffic-analyzer"

# ─── 合法的检测类别 ──────────────────────────────────────
VALID_DETECT_CATEGORIES = {
    "sql_injection", "xss", "cmd_injection", "dir_traversal",
    "file_upload", "deserialization", "webshell", "c2", "log4shell"
}

# ─── 检测类别中文映射 ────────────────────────────────────
CATEGORY_LABELS = {
    "sql_injection": "SQL 注入",
    "xss": "跨站脚本",
    "cmd_injection": "命令注入",
    "dir_traversal": "目录遍历",
    "file_upload": "文件上传",
    "deserialization": "反序列化",
    "webshell": "Webshell 通信",
    "c2": "C2 通信",
    "log4shell": "Log4Shell",
}


# ═══════════════════════════════════════════════════════════
#  公共工具函数
# ═══════════════════════════════════════════════════════════

def clear_screen():
    """清屏"""
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    """打印抬头页面（菜单模式）— 全蓝色"""
    blue = Fore.CYAN + Style.BRIGHT
    line = "═" * 100
    print(f"{blue}{line}")
    print(f"{blue}              HVV Traffic Analyzer - 护网行动流量分析工具     {VERSION}   开发者：{DEVELOPER}")
    print(f"{blue}                下载链接：{REPO_URL}")
    print(f"{blue}{line}{Style.RESET_ALL}")


def print_banner_capture(interface, categories=None, bpf_filter=None):
    """打印监控模式横幅"""
    blue = Fore.CYAN + Style.BRIGHT
    line = "=" * 100
    print(f"{blue}{line}")
    print(f"{blue}              HVV Traffic Analyzer - 护网行动流量分析工具")
    print(f"{blue}{line}{Style.RESET_ALL}")
    print(f"  [INFO] 监控网卡: {interface}")
    if bpf_filter:
        print(f"  [INFO] BPF 过滤: {bpf_filter}")
    if categories:
        print(f"  [INFO] 检测类别: {', '.join(categories)}")
    else:
        print("  [INFO] 检测类别: 全部启用")
    print("-" * 100)
    print("  [INFO] 等待流量... (Ctrl+C 停止监控)")
    print()


def readkey():
    """读取单个按键（Windows: msvcrt，其他: 回退 input）"""
    if HAS_MSVCRT:
        ch = msvcrt.getch()
        if ch in (b"\x00", b"\xe0"):  # 特殊键前缀
            ch2 = msvcrt.getch()
            if ch2 == b"H":
                return "up"
            elif ch2 == b"P":
                return "down"
            return ""
        elif ch == b"\r":
            return "enter"
        elif ch == b"\x1b":
            return "esc"
        elif ch == b" ":
            return "space"
        elif ch == b"\x03":
            raise KeyboardInterrupt
        try:
            return ch.decode("utf-8", errors="replace")
        except Exception:
            return ""
    else:
        line = input()
        return line.strip().lower() if line else ""


def prompt_input(prompt_text, default=""):
    """带提示的输入"""
    if default:
        val = input(f"  {prompt_text} [{default}]: ").strip()
        return val if val else default
    return input(f"  {prompt_text}: ").strip()


def validate_ip_str(ip_str):
    """验证 IP 或 CIDR"""
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False


def auto_output_path(prefix, ext):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}.{ext}"


# ─── 颜色辅助 ────────────────────────────────────────────

def _green(text):
    """绿色文字"""
    return f"{Fore.GREEN}{text}{Style.RESET_ALL}"


def _red(text):
    """红色文字"""
    return f"{Fore.RED}{text}{Style.RESET_ALL}"


def _display_width(s):
    """计算字符串显示宽度（ANSI 转义不计，中文/emoji 算 2）"""
    clean = re.sub(r'\x1b\[[0-9;]*m', '', s)
    w = 0
    for ch in clean:
        cp = ord(ch)
        if (0x4E00 <= cp <= 0x9FFF or 0x3000 <= cp <= 0x30FF or
            0xFF00 <= cp <= 0xFFEF or 0x2600 <= cp <= 0x27BF or
            0xFE30 <= cp <= 0xFE4F or 0x20000 <= cp <= 0x2FA1F or
            cp == 0x2705 or cp == 0x274C):
            w += 2
        else:
            w += 1
    return w


def _menu_line(label, value, color_func=None, total_width=100):
    """构造对齐的菜单行，返回格式化字符串"""
    label_w = _display_width(label)
    val_str = color_func(value) if color_func else value
    val_w = _display_width(value)
    pad = total_width - 4 - label_w - val_w
    if pad < 1:
        pad = 1
    return f"  │  {label}{' ' * pad}{val_str}"


def _box_border(total_width=100):
    return "  │" + " " * (total_width - 4) + "│"


def _box_top(total_width=100):
    return "  ┌" + "─" * (total_width - 4) + "┐"


def _box_bottom(total_width=100):
    return "  └" + "─" * (total_width - 4) + "┘"


# ═══════════════════════════════════════════════════════════
#  菜单模式函数
# ═══════════════════════════════════════════════════════════

def make_default_config():
    """创建默认配置"""
    return {
        "interface": None,
        "duration": None,
        "bpf_filter": None,
        "src_ip": None,
        "dst_ip": None,
        "port": None,
        "protocol": None,
        "content": None,
        "http_method": None,
        "http_uri": None,
        "ua_pattern": None,
        "detect_enabled": True,
        "detect_categories": None,      # None = 全部
        "rules_file": None,
        "ioc_enabled": False,
        "ioc_whitelist": None,
        "ioc_export": False,
        "suspicion_enabled": True,
        "suspicion_export": False,
        "suspicion_rules": None,
        "log_file": False,
        "quiet": False,
        "no_color": False,
        "summary_interval": 300,
    }


def cfg_status(cfg, key, active_val=True):
    """返回 ✅ 或 ❌ 状态"""
    val = cfg.get(key)
    if active_val is True:
        return "✅ 开启" if val else "❌ 关闭"
    if active_val is False:
        return "❌ 关闭" if val else "✅ 开启"
    if val is None:
        return "❌ 无"
    return f"✅ {val}"


def show_main_menu(cfg):
    """显示主菜单（带颜色 + 对齐）"""
    # ── [1] 网卡
    if cfg["interface"]:
        iface = cfg["interface"]
        if len(iface) > 30:
            iface = iface[:30] + "..."
        card_active = True
        card_val = f"已选择: {iface}"
    else:
        card_active = False
        card_val = "未选择"

    # ── [2] 过滤设置
    filters_active = any([
        cfg["bpf_filter"], cfg["src_ip"], cfg["dst_ip"],
        cfg["port"], cfg["protocol"], cfg["content"],
        cfg["http_method"], cfg["http_uri"], cfg["ua_pattern"]
    ])
    if filters_active:
        parts = []
        if cfg["bpf_filter"]:
            parts.append(f"BPF={cfg['bpf_filter'][:15]}")
        if cfg["src_ip"]:
            parts.append(f"src={cfg['src_ip']}")
        if cfg["dst_ip"]:
            parts.append(f"dst={cfg['dst_ip']}")
        if cfg["port"]:
            parts.append(f"port={cfg['port']}")
        if cfg["protocol"]:
            parts.append(f"proto={cfg['protocol']}")
        if cfg["http_method"]:
            parts.append(f"method={cfg['http_method']}")
        filter_val = " | ".join(parts)
        if _display_width(filter_val) > 34:
            filter_val = filter_val[:34] + "..."
        filter_active = True
    else:
        filter_active = False
        filter_val = "未配置"

    # ── [3] 检测设置
    if cfg["detect_enabled"]:
        if cfg["detect_categories"]:
            cats = ", ".join(cfg["detect_categories"][:2])
            if len(cfg["detect_categories"]) > 2:
                cats += f" ...共{len(cfg['detect_categories'])}类"
        else:
            cats = "全部启用"
        rules_txt = os.path.basename(cfg["rules_file"]) if cfg["rules_file"] else "默认"
        detect_val = f"{cats} | 规则: {rules_txt}"
        detect_active = True
    else:
        detect_active = False
        detect_val = "已禁用"

    # ── [4] IOC 设置
    if cfg["ioc_enabled"]:
        wl = os.path.basename(cfg["ioc_whitelist"]) if cfg["ioc_whitelist"] else "无"
        exp = "开启" if cfg["ioc_export"] else "关闭"
        ioc_val = f"开启 | 白名单: {wl} | 导出: {exp}"
        ioc_active = True
    else:
        ioc_active = False
        ioc_val = "未启用"

    # ── [5] 可疑流量
    if cfg["suspicion_enabled"]:
        exp = "开启" if cfg["suspicion_export"] else "关闭"
        sr = os.path.basename(cfg["suspicion_rules"]) if cfg["suspicion_rules"] else "默认"
        sus_val = f"检测: 开启 | 导出: {exp} | 规则: {sr}"
        sus_active = True
    else:
        sus_active = False
        sus_val = "检测: 关闭"

    # ── [6] 输出设置
    clr = "关闭" if cfg["no_color"] else "开启"
    qt = "开启" if cfg["quiet"] else "关闭"
    lg = "开启" if cfg["log_file"] else "关闭"
    dur = f"{cfg['duration']}秒" if cfg["duration"] else "持续运行"
    out_val = f"彩色: {clr} | 静默: {qt} | 日志: {lg} | 时长: {dur}"
    out_active = True

    # ── 渲染（左列 18 字符宽，状态值着色）
    def _line(num, label, value, active):
        tag = "✅" if active else "❌"
        colored = _green(f"{tag} {value}") if active else _red(f"{tag} {value}")
        left = f"  [{num}] {label}"
        pad = 20 - _display_width(left)
        if pad < 1:
            pad = 1
        print(f"{left}{' ' * pad}{colored}")

    print()
    _line("1", "网卡选择", card_val, card_active)
    _line("2", "过滤设置", filter_val, filter_active)
    _line("3", "检测设置", detect_val, detect_active)
    _line("4", "IOC 设置", ioc_val, ioc_active)
    _line("5", "可疑流量设置", sus_val, sus_active)
    _line("6", "输出设置", out_val, out_active)
    print()
    print(f"  {'─' * 90}")
    print("  [S] 开始监控" + " " * 62 + "[0] 退出")
    print()
    print("  > 请输入选项: ", end="", flush=True)


def menu_select_interface():
    """网卡选择菜单（上下键 + Enter）"""
    print("  正在扫描可用网卡...\n")
    try:
        interfaces = TsharkCapture.list_interfaces()
    except Exception as e:
        print(f"  [ERROR] {e}")
        print("\n  按 Enter 返回...", end="", flush=True)
        input()
        return None

    if not interfaces:
        print("  [ERROR] 未找到可用网卡。请确认 Wireshark/tshark 已安装。")
        print("\n  按 Enter 返回...", end="", flush=True)
        input()
        return None

    selected = 0

    def render():
        print("  ┌─ 网卡选择 ──────────────────────────────────────┐")
        print("  │                                                  │")
        for i, iface in enumerate(interfaces):
            desc = iface.get("desc", "") or iface.get("name", "")
            if len(desc) > 44:
                desc = desc[:41] + "..."
            pointer = " >" if i == selected else "  "
            line = f"{pointer} {i + 1}. {desc}"
            padding = 52 - len(line.encode("utf-8", errors="replace"))
            print(f"  │ {line}{' ' * max(padding, 1)}│")
        print("  │                                                  │")
        print("  │  ↑↓ 选择   Enter 确认   Esc 返回                │")
        print("  └──────────────────────────────────────────────────┘")

    render()

    while True:
        key = readkey()
        if key == "up":
            selected = (selected - 1) % len(interfaces)
        elif key == "down":
            selected = (selected + 1) % len(interfaces)
        elif key == "enter":
            return interfaces[selected]
        elif key == "esc":
            return None
        else:
            continue
        clear_screen()
        print_banner()
        print()
        render()


def menu_filter(cfg):
    """过滤设置子菜单"""
    def _val(key, limit=None):
        """返回 (value_text, is_active) 元组"""
        v = cfg.get(key)
        if not v:
            return "无", False
        s = str(v)
        if limit and _display_width(s) > limit:
            s = s[:limit]
        return s, True

    while True:
        clear_screen()
        print_banner()
        print()
        W = 100
        print(_box_top(W))
        print(_box_border(W))
        for num, label, key, limit in [
            ("1", "BPF 过滤表达式", "bpf_filter", 24),
            ("2", "源 IP 过滤",     "src_ip",     None),
            ("3", "目的 IP 过滤",   "dst_ip",     None),
            ("4", "端口过滤",       "port",       None),
            ("5", "协议过滤",       "protocol",   None),
            ("6", "内容正则匹配",   "content",    24),
            ("7", "HTTP 方法过滤",  "http_method",None),
            ("8", "HTTP URI 匹配",  "http_uri",   24),
            ("9", "User-Agent 匹配","ua_pattern", 24),
        ]:
            txt, active = _val(key, limit)
            tag = "✅" if active else "❌"
            val_str = _green(f"{tag} {txt}") if active else _red(f"{tag} {txt}")
            left = f"  [{num}] {label}"
            pad = W - 2 - _display_width(left) - _display_width(f"{tag} {txt}")
            if pad < 1:
                pad = 1
            print(f"  │{left}{' ' * pad}{val_str} │")
        print(_box_border(W))
        print(f"  │  [C] 清除全部过滤{' ' * 78}│")
        print(f"  │  [0] 返回主菜单{' ' * 79}│")
        print(_box_border(W))
        print(_box_bottom(W))
        print()
        print("  > 请输入选项: ", end="", flush=True)
        print()
        print("  > 请输入选项: ", end="", flush=True)
        choice = input().strip().lower()

        if choice == "0":
            return
        elif choice == "c":
            for k in ["bpf_filter", "src_ip", "dst_ip", "port", "protocol",
                       "content", "http_method", "http_uri", "ua_pattern"]:
                cfg[k] = None
        elif choice == "1":
            val = prompt_input("BPF 过滤表达式（如 'port 80 or port 53'）", cfg["bpf_filter"] or "")
            cfg["bpf_filter"] = val if val else None
        elif choice == "2":
            val = prompt_input("源 IP（支持 CIDR，如 192.168.0.0/16）", cfg["src_ip"] or "")
            if val and not validate_ip_str(val):
                print(f"  [ERROR] IP 格式无效: {val}")
                time.sleep(1)
            else:
                cfg["src_ip"] = val if val else None
        elif choice == "3":
            val = prompt_input("目的 IP（支持 CIDR）", cfg["dst_ip"] or "")
            if val and not validate_ip_str(val):
                print(f"  [ERROR] IP 格式无效: {val}")
                time.sleep(1)
            else:
                cfg["dst_ip"] = val if val else None
        elif choice == "4":
            val = prompt_input("端口号 (1-65535)", str(cfg["port"]) if cfg["port"] else "")
            if val:
                try:
                    p = int(val)
                    if 1 <= p <= 65535:
                        cfg["port"] = p
                    else:
                        print("  [ERROR] 端口范围: 1-65535")
                        time.sleep(1)
                except ValueError:
                    print("  [ERROR] 请输入数字")
                    time.sleep(1)
            else:
                cfg["port"] = None
        elif choice == "5":
            val = prompt_input("协议（http/dns/tls/smb/rdp/ssh）", cfg["protocol"] or "")
            cfg["protocol"] = val if val else None
        elif choice == "6":
            val = prompt_input("Payload 内容正则", cfg["content"] or "")
            if val:
                try:
                    re.compile(val)
                    cfg["content"] = val
                except re.error as e:
                    print(f"  [ERROR] 正则语法错误: {e}")
                    time.sleep(1)
            else:
                cfg["content"] = None
        elif choice == "7":
            val = prompt_input("HTTP 方法（GET/POST/PUT/DELETE...）", cfg["http_method"] or "")
            cfg["http_method"] = val.upper() if val else None
        elif choice == "8":
            val = prompt_input("HTTP URI 正则", cfg["http_uri"] or "")
            if val:
                try:
                    re.compile(val)
                    cfg["http_uri"] = val
                except re.error as e:
                    print(f"  [ERROR] 正则语法错误: {e}")
                    time.sleep(1)
            else:
                cfg["http_uri"] = None
        elif choice == "9":
            val = prompt_input("User-Agent 正则", cfg["ua_pattern"] or "")
            if val:
                try:
                    re.compile(val)
                    cfg["ua_pattern"] = val
                except re.error as e:
                    print(f"  [ERROR] 正则语法错误: {e}")
                    time.sleep(1)
            else:
                cfg["ua_pattern"] = None


def menu_detect(cfg):
    """检测设置子菜单"""
    while True:
        clear_screen()
        print_banner()
        print()
        W = 100

        def _status(val, on_text="开启", off_text="关闭"):
            return _green(f"✅ {on_text}") if val else _red(f"❌ {off_text}")

        if cfg["detect_categories"]:
            cats_str = ", ".join(cfg["detect_categories"])
            if _display_width(cats_str) > 30:
                cats_str = cats_str[:30] + "..."
        else:
            cats_str = "全部启用"
        rules_str = os.path.basename(cfg["rules_file"]) if cfg["rules_file"] else "默认 (signatures.yaml)"

        print(_box_top(W))
        print(_box_border(W))
        # [1] 开关
        left1 = "  [1] 攻击检测开关"
        det_s = _status(cfg["detect_enabled"])
        det_t = "开启" if cfg["detect_enabled"] else "关闭"
        pad1 = W - 2 - _display_width(left1) - _display_width(f"✅ {det_t}")
        print(f"  │{left1}{' ' * max(pad1,1)}{det_s} │")
        # [2] 类别
        left2 = "  [2] 选择检测类别"
        cats_s = _green(f"✅ {cats_str}")
        pad2 = W - 2 - _display_width(left2) - _display_width(f"✅ {cats_str}")
        print(f"  │{left2}{' ' * max(pad2,1)}{cats_s} │")
        # [3] 规则文件
        left3 = "  [3] 自定义规则文件"
        rules_s = _green(f"✅ {rules_str}")
        pad3 = W - 2 - _display_width(left3) - _display_width(f"✅ {rules_str}")
        print(f"  │{left3}{' ' * max(pad3,1)}{rules_s} │")
        print(_box_border(W))
        print(f"  │  [0] 返回主菜单{' ' * 79}│")
        print(_box_border(W))
        print(_box_bottom(W))
        print()
        print("  > 请输入选项: ", end="", flush=True)
        print()
        print("  > 请输入选项: ", end="", flush=True)
        choice = input().strip().lower()

        if choice == "0":
            return
        elif choice == "1":
            cfg["detect_enabled"] = not cfg["detect_enabled"]
        elif choice == "2":
            cfg["detect_categories"] = menu_select_categories(cfg["detect_categories"])
        elif choice == "3":
            val = prompt_input("规则文件路径（留空恢复默认）", cfg["rules_file"] or "")
            if val and not os.path.exists(val):
                print(f"  [ERROR] 文件不存在: {val}")
                time.sleep(1)
            else:
                cfg["rules_file"] = val if val else None


def menu_select_categories(current):
    """检测类别多选菜单（上下键 + 空格切换 + Enter 确认）"""
    all_cats = list(VALID_DETECT_CATEGORIES)
    selected = set(current) if current else set(all_cats)
    cursor = 0

    def render():
        print("  ┌─ 检测类别（空格切换，Enter 确认）──────────────┐")
        print("  │                                                  │")
        for i, cat in enumerate(all_cats):
            check = "✅" if cat in selected else "❌"
            pointer = " >" if i == cursor else "  "
            label = CATEGORY_LABELS.get(cat, cat)
            print(f"  │ {pointer} [{check}] {cat:<20s} {label:<14s}│")
        print("  │                                                  │")
        print("  │  ↑↓ 移动   空格 切换   A 全选   N 全不选        │")
        print("  │  Enter 确认   Esc 取消                           │")
        print("  └──────────────────────────────────────────────────┘")

    render()

    while True:
        key = readkey()
        if key == "up":
            cursor = (cursor - 1) % len(all_cats)
        elif key == "down":
            cursor = (cursor + 1) % len(all_cats)
        elif key == "space":
            cat = all_cats[cursor]
            if cat in selected:
                selected.discard(cat)
            else:
                selected.add(cat)
        elif key in ("a", "A"):
            selected = set(all_cats)
        elif key in ("n", "N"):
            selected = set()
        elif key == "enter":
            result = [c for c in all_cats if c in selected]
            return result if len(result) < len(all_cats) else None  # None = 全部
        elif key == "esc":
            return current
        else:
            continue
        clear_screen()
        print_banner()
        print()
        render()


def menu_ioc(cfg):
    """IOC 设置子菜单"""
    while True:
        clear_screen()
        print_banner()
        print()
        W = 100

        def _s(val, on="开启", off="关闭"):
            return _green(f"✅ {on}") if val else _red(f"❌ {off}")

        wl_str = os.path.basename(cfg["ioc_whitelist"]) if cfg["ioc_whitelist"] else "无"
        wl_active = bool(cfg["ioc_whitelist"])

        print(_box_top(W))
        print(_box_border(W))
        for num, label, val_text, active in [
            ("1", "IOC 提取开关",   "开启" if cfg["ioc_enabled"] else "关闭", cfg["ioc_enabled"]),
            ("2", "IOC 白名单文件", wl_str, wl_active),
            ("3", "IOC 导出开关",   "开启" if cfg["ioc_export"] else "关闭", cfg["ioc_export"]),
        ]:
            tag = "✅" if active else "❌"
            colored = _green(f"{tag} {val_text}") if active else _red(f"{tag} {val_text}")
            left = f"  [{num}] {label}"
            pad = W - 2 - _display_width(left) - _display_width(f"{tag} {val_text}")
            print(f"  │{left}{' ' * max(pad,1)}{colored} │")
        print(_box_border(W))
        print(f"  │  [0] 返回主菜单{' ' * 79}│")
        print(_box_border(W))
        print(_box_bottom(W))
        print()
        print("  > 请输入选项: ", end="", flush=True)
        print()
        print("  > 请输入选项: ", end="", flush=True)
        choice = input().strip().lower()

        if choice == "0":
            return
        elif choice == "1":
            cfg["ioc_enabled"] = not cfg["ioc_enabled"]
        elif choice == "2":
            val = prompt_input("白名单文件路径（留空清除）", cfg["ioc_whitelist"] or "")
            if val and not os.path.exists(val):
                print(f"  [ERROR] 文件不存在: {val}")
                time.sleep(1)
            else:
                cfg["ioc_whitelist"] = val if val else None
        elif choice == "3":
            cfg["ioc_export"] = not cfg["ioc_export"]


def menu_suspicion(cfg):
    """可疑流量设置子菜单"""
    while True:
        clear_screen()
        print_banner()
        print()
        W = 100
        rules_str = os.path.basename(cfg["suspicion_rules"]) if cfg["suspicion_rules"] else "默认 (suspicion.yaml)"

        print(_box_top(W))
        print(_box_border(W))
        for num, label, val_text, active in [
            ("1", "可疑流量检测开关", "开启" if cfg["suspicion_enabled"] else "关闭", cfg["suspicion_enabled"]),
            ("2", "可疑流量导出开关", "开启" if cfg["suspicion_export"] else "关闭", cfg["suspicion_export"]),
            ("3", "自定义可疑规则",   rules_str, True),
        ]:
            tag = "✅" if active else "❌"
            colored = _green(f"{tag} {val_text}") if active else _red(f"{tag} {val_text}")
            left = f"  [{num}] {label}"
            pad = W - 2 - _display_width(left) - _display_width(f"{tag} {val_text}")
            print(f"  │{left}{' ' * max(pad,1)}{colored} │")
        print(_box_border(W))
        print(f"  │  [0] 返回主菜单{' ' * 79}│")
        print(_box_border(W))
        print(_box_bottom(W))
        print()
        print("  > 请输入选项: ", end="", flush=True)
        print()
        print("  > 请输入选项: ", end="", flush=True)
        choice = input().strip().lower()

        if choice == "0":
            return
        elif choice == "1":
            cfg["suspicion_enabled"] = not cfg["suspicion_enabled"]
        elif choice == "2":
            cfg["suspicion_export"] = not cfg["suspicion_export"]
        elif choice == "3":
            val = prompt_input("可疑规则文件路径（留空恢复默认）", cfg["suspicion_rules"] or "")
            if val and not os.path.exists(val):
                print(f"  [ERROR] 文件不存在: {val}")
                time.sleep(1)
            else:
                cfg["suspicion_rules"] = val if val else None


def menu_output(cfg):
    """输出设置子菜单"""
    while True:
        clear_screen()
        print_banner()
        print()
        W = 100
        dur_str = f"{cfg['duration']}秒" if cfg["duration"] else "持续运行"
        interval_str = f"{cfg['summary_interval']}秒"

        print(_box_top(W))
        print(_box_border(W))
        for num, label, val_text, active in [
            ("1", "输出日志开关", "开启" if cfg["log_file"] else "关闭", cfg["log_file"]),
            ("2", "静默模式",     "开启" if cfg["quiet"] else "关闭", cfg["quiet"]),
            ("3", "彩色输出",     "关闭" if cfg["no_color"] else "开启", not cfg["no_color"]),
            ("4", "统计摘要间隔", interval_str, True),
            ("5", "抓包时长",     dur_str, True),
        ]:
            tag = "✅" if active else "❌"
            colored = _green(f"{tag} {val_text}") if active else _red(f"{tag} {val_text}")
            left = f"  [{num}] {label}"
            pad = W - 2 - _display_width(left) - _display_width(f"{tag} {val_text}")
            print(f"  │{left}{' ' * max(pad,1)}{colored} │")
        print(_box_border(W))
        print(f"  │  [0] 返回主菜单{' ' * 79}│")
        print(_box_border(W))
        print(_box_bottom(W))
        print()
        print("  > 请输入选项: ", end="", flush=True)
        print()
        print("  > 请输入选项: ", end="", flush=True)
        choice = input().strip().lower()

        if choice == "0":
            return
        elif choice == "1":
            cfg["log_file"] = not cfg["log_file"]
        elif choice == "2":
            cfg["quiet"] = not cfg["quiet"]
        elif choice == "3":
            cfg["no_color"] = not cfg["no_color"]
        elif choice == "4":
            val = prompt_input("摘要间隔（秒）", str(cfg["summary_interval"]))
            try:
                v = int(val)
                if v > 0:
                    cfg["summary_interval"] = v
                else:
                    print("  [ERROR] 必须大于 0")
                    time.sleep(1)
            except ValueError:
                print("  [ERROR] 请输入数字")
                time.sleep(1)
        elif choice == "5":
            val = prompt_input("抓包时长（秒，留空为持续运行）", str(cfg["duration"]) if cfg["duration"] else "")
            if val:
                try:
                    v = int(val)
                    if v > 0:
                        cfg["duration"] = v
                    else:
                        print("  [ERROR] 必须大于 0")
                        time.sleep(1)
                except ValueError:
                    print("  [ERROR] 请输入数字")
                    time.sleep(1)
            else:
                cfg["duration"] = None


# ═══════════════════════════════════════════════════════════
#  监控启动（菜单模式 & CLI 模式共用）
# ═══════════════════════════════════════════════════════════

def build_filter_from_config(cfg):
    """从配置字典构建 TrafficFilter"""
    tf = TrafficFilter()
    has_filter = any([
        cfg.get("src_ip"), cfg.get("dst_ip"), cfg.get("port"),
        cfg.get("protocol"), cfg.get("content"), cfg.get("http_method"),
        cfg.get("http_uri"), cfg.get("ua_pattern")
    ])
    if not has_filter:
        return tf

    rule = FilterRule(name="cli_filter")
    if cfg.get("src_ip"):
        rule.src_ips = [cfg["src_ip"]]
    if cfg.get("dst_ip"):
        rule.dst_ips = [cfg["dst_ip"]]
    if cfg.get("port"):
        rule.dst_ports = [cfg["port"]]
        rule.src_ports = [cfg["port"]]
    if cfg.get("protocol"):
        rule.protocols = [cfg["protocol"]]
    if cfg.get("content"):
        rule.content_patterns = [cfg["content"]]
    if cfg.get("http_method"):
        rule.http_methods = [cfg["http_method"].split(",")]
    if cfg.get("http_uri"):
        rule.http_uri_pattern = cfg["http_uri"]
    if cfg.get("ua_pattern"):
        rule.http_ua_pattern = cfg["ua_pattern"]

    tf.add_rule(rule)
    return tf


def start_monitoring(cfg):
    """启动流量监控（核心逻辑）"""
    clear_screen()

    # 显示监控横幅（不再显示菜单抬头）
    categories_list = cfg.get("detect_categories")
    print_banner_capture(
        cfg["interface"],
        categories_list,
        cfg.get("bpf_filter")
    )

    # 初始化模块
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out_mgr = OutputManager(
        no_color=cfg.get("no_color", False),
        quiet=cfg.get("quiet", False),
        log_file=auto_output_path("capture", "log") if cfg.get("log_file") else None,
    )
    stats = StatsCollector()
    traffic_filter = build_filter_from_config(cfg)

    # 检测引擎
    detector = None
    if cfg.get("detect_enabled", True):
        rules_path = cfg.get("rules_file") or os.path.join(base_dir, "rules", "signatures.yaml")
        detector = AttackDetector(rules_path)
        if cfg.get("detect_categories"):
            detector.enable_categories(cfg["detect_categories"])

    # IOC 提取器
    extractor = None
    ioc_export_path = None
    if cfg.get("ioc_enabled"):
        patterns_path = os.path.join(base_dir, "rules", "ioc_patterns.yaml")
        extractor = IOCExtractor(
            whitelist_path=cfg.get("ioc_whitelist"),
            patterns_path=patterns_path,
        )
        if cfg.get("ioc_export"):
            ioc_export_path = auto_output_path("ioc", "json")

    # 可疑流量引擎
    suspicion_engine = None
    suspicious_exporter = None
    sus_export_path = None
    if cfg.get("suspicion_enabled", True):
        sus_rules_path = cfg.get("suspicion_rules") or os.path.join(base_dir, "rules", "suspicion.yaml")
        suspicion_engine = SuspicionEngine(sus_rules_path)
        if cfg.get("suspicion_export"):
            sus_export_path = auto_output_path("suspicious_traffic", "txt")
            suspicious_exporter = SuspiciousExporter(sus_export_path)
            suspicious_exporter.open()

    # 抓包
    capture = TsharkCapture(
        interface=cfg["interface"],
        bpf_filter=cfg.get("bpf_filter"),
        duration=cfg.get("duration"),
    )

    stop_event = threading.Event()

    def signal_handler(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, signal_handler)

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
    if cfg.get("log_file"):
        features.append("日志文件")
    if features:
        print(f"  [INFO] 已启用: {' | '.join(features)}")

    try:
        capture.start()
    except Exception as e:
        print(f"  [ERROR] 启动 tshark 失败: {e}")
        print("  请确认: 1) Wireshark/tshark 已安装  2) 以管理员权限运行")
        print("\n  按 Enter 返回...", end="", flush=True)
        input()
        return

    stats.start()
    last_summary_time = time.time()

    try:
        for raw in capture.packets():
            if stop_event.is_set():
                break

            packet = parse_packet(raw)
            stats.record_packet(packet)

            if traffic_filter.rules:
                matched_rules = traffic_filter.match(packet)
                if not matched_rules:
                    continue

            is_confirmed_attack = False
            if detector:
                alerts = detector.detect(packet)
                for alert in alerts:
                    stats.record_alert(alert)
                    out_mgr.alert(alert)
                    is_confirmed_attack = True

            if suspicion_engine and not is_confirmed_attack:
                suspicious_items = suspicion_engine.detect(packet)
                for item in suspicious_items:
                    stats.record_suspicious(item)
                    out_mgr.suspicious(item)
                    if suspicious_exporter:
                        suspicious_exporter.write(item)

            if extractor:
                iocs = extractor.extract(packet)
                if iocs:
                    stats.record_iocs(iocs)
                    suspicious = [i for i in iocs if i.suspicious]
                    if suspicious:
                        out_mgr.ioc_found("ioc", suspicious)

            now = time.time()
            if now - last_summary_time >= cfg.get("summary_interval", 300):
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
        print("\n  [INFO] 正在停止抓包...")
        print()

    # 最终报告
    ioc_data = extractor.summary() if extractor else None
    report = stats.generate_report(ioc_data)
    out_mgr.print_report(report)

    if suspicious_exporter:
        print(f"  [INFO] 可疑流量已导出: {suspicious_exporter.output_path} ({suspicious_exporter.count} 条)")
    if ioc_export_path and extractor:
        extractor.export_iocs(ioc_export_path, ioc_data)
        print(f"  [INFO] IOC 已导出: {ioc_export_path}")
    if cfg.get("log_file"):
        log_path = out_mgr._log_file.name if out_mgr._log_file else None
        if log_path:
            json_path = log_path.rsplit(".", 1)[0] + "_report.json"
            stats.export_json(json_path, ioc_data)
            print(f"  [INFO] 详细报告已导出: {json_path}")

    out_mgr.close()

    print()
    print("═" * 100)
    print("  流量监控结束，欢迎下次使用")
    print("═" * 100)
    print("\n  按 Enter 返回菜单...", end="", flush=True)
    input()


# ═══════════════════════════════════════════════════════════
#  菜单模式主入口
# ═══════════════════════════════════════════════════════════

def show_disclaimer():
    """显示免责声明，按任意键继续，Ctrl+C 退出"""
    clear_screen()
    blue = Fore.CYAN + Style.BRIGHT
    yellow = Fore.YELLOW + Style.BRIGHT
    red = Fore.RED + Style.BRIGHT
    line = "═" * 100

    print(f"{blue}{line}")
    print(f"{blue}              HVV Traffic Analyzer - 护网行动流量分析工具     {VERSION}   开发者：{DEVELOPER}")
    print(f"{blue}                下载链接：{REPO_URL}")
    print(f"{blue}{line}{Style.RESET_ALL}")
    print()
    print(f"  {yellow}[免责声明]{Style.RESET_ALL}")
    print()
    print(f"  {red}1.{Style.RESET_ALL} 此项目无任何发包能力，无反向构造能力，无数据操作能力，只能识别攻击，不能生成或执行攻击")
    print(f"  {red}2.{Style.RESET_ALL} 此项目只做流量分析研究，不确保流量过滤完全正确")
    print(f"  {red}3.{Style.RESET_ALL} 使用者应自行承担所有因使用本工具而产生的法律责任")
    print(f"  {red}4.{Style.RESET_ALL} 开发者不承担任何因使用本工具导致的直接或间接损失")
    print()
    print(f"  {blue}{'─' * 100}{Style.RESET_ALL}")
    print()
    print(f"  按任意键确认并开始，{red}Ctrl+C{Style.RESET_ALL} 退出")
    print()
    try:
        readkey()
    except KeyboardInterrupt:
        clear_screen()
        print(f"\n{blue}{'═' * 100}")
        print("  流量监控结束，欢迎下次使用")
        print(f"{'═' * 100}{Style.RESET_ALL}")
        sys.exit(0)


def menu_main():
    """交互式菜单模式"""
    # 免责声明
    show_disclaimer()

    cfg = make_default_config()

    # 启动时自动扫描网卡，让用户先选
    clear_screen()
    print_banner()
    print()
    iface = menu_select_interface()
    if iface:
        cfg["interface"] = iface.get("desc") or iface.get("name")

    # 主菜单循环
    while True:
        clear_screen()
        print_banner()
        show_main_menu(cfg)
        choice = input().strip().lower()

        if choice == "0":
            clear_screen()
            print_banner()
            print()
            print("═" * 100)
            print("  流量监控结束，欢迎下次使用")
            print("═" * 100)
            break
        elif choice == "1":
            clear_screen()
            print_banner()
            print()
            iface = menu_select_interface()
            if iface:
                cfg["interface"] = iface.get("desc") or iface.get("name")
        elif choice == "2":
            menu_filter(cfg)
        elif choice == "3":
            menu_detect(cfg)
        elif choice == "4":
            menu_ioc(cfg)
        elif choice == "5":
            menu_suspicion(cfg)
        elif choice == "6":
            menu_output(cfg)
        elif choice == "s":
            if not cfg["interface"]:
                clear_screen()
                print_banner()
                print()
                print("  [ERROR] 请先选择网卡！")
                print("\n  按 Enter 返回...", end="", flush=True)
                input()
                continue
            start_monitoring(cfg)


# ═══════════════════════════════════════════════════════════
#  CLI 模式（带参数直接运行，向后兼容）
# ═══════════════════════════════════════════════════════════

def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description="护网行动实时流量分析工具 - HVV Traffic Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py                                  # 交互式菜单模式
  python main.py -i "以太网"                       # 全量监控
  python main.py -i "以太网" -f "port 80 or port 53"
  python main.py -i "以太网" --src-ip 10.0.0.50
  python main.py -i "以太网" --detect webshell,c2
  python main.py -i "以太网" --suspicious-export
  python main.py --list-interfaces
        """
    )

    parser.add_argument("-i", "--interface", help="网卡名或索引")
    parser.add_argument("--list-interfaces", action="store_true", help="列出所有可用网卡")
    parser.add_argument("--duration", type=int, help="抓包时长（秒）")

    filt = parser.add_argument_group("过滤选项")
    filt.add_argument("-f", "--bpf-filter", help='BPF 过滤表达式')
    filt.add_argument("--src-ip", help="源 IP 过滤（支持 CIDR）")
    filt.add_argument("--dst-ip", help="目的 IP 过滤（支持 CIDR）")
    filt.add_argument("--port", type=int, help="端口过滤")
    filt.add_argument("--protocol", help="协议过滤")
    filt.add_argument("--content", help="Payload 内容正则匹配")
    filt.add_argument("--http-method", help="HTTP 方法过滤")
    filt.add_argument("--http-uri", help="HTTP URI 正则匹配")
    filt.add_argument("--ua-pattern", help="User-Agent 正则匹配")

    det = parser.add_argument_group("检测选项")
    det.add_argument("--detect", help="启用的检测类别（逗号分隔）")
    det.add_argument("--rules", help="自定义规则文件路径")
    det.add_argument("--no-detect", action="store_true", help="禁用攻击检测")

    ioc = parser.add_argument_group("IOC 选项")
    ioc.add_argument("--extract-ioc", action="store_true", help="启用 IOC 提取")
    ioc.add_argument("--ioc-whitelist", help="IOC 白名单文件")
    ioc.add_argument("--ioc-export", nargs="?", const="auto", help="导出 IOC")

    sus = parser.add_argument_group("可疑流量选项")
    sus.add_argument("--suspicious-export", nargs="?", const="auto", help="导出可疑流量")
    sus.add_argument("--no-suspicious", action="store_true", help="禁用可疑检测")
    sus.add_argument("--suspicious-rules", help="自定义可疑规则")

    out = parser.add_argument_group("输出选项")
    out.add_argument("-o", "--output", nargs="?", const="auto", help="保存日志")
    out.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    out.add_argument("--quiet", action="store_true", help="静默模式")
    out.add_argument("--summary-interval", type=int, default=300, help="统计摘要间隔")

    return parser.parse_args()


def cli_main():
    """CLI 参数模式（向后兼容）"""
    args = parse_args()

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
        except Exception as e:
            print(f"错误: {e}")
            sys.exit(1)
        sys.exit(0)

    if not args.interface:
        print("错误: 请指定网卡")
        print("  使用 -i <网卡名> 指定，或不带参数进入菜单模式")
        sys.exit(1)

    # 构建配置并启动
    cfg = {
        "interface": args.interface,
        "duration": args.duration,
        "bpf_filter": args.bpf_filter,
        "src_ip": args.src_ip,
        "dst_ip": args.dst_ip,
        "port": args.port,
        "protocol": args.protocol,
        "content": args.content,
        "http_method": args.http_method,
        "http_uri": args.http_uri,
        "ua_pattern": args.ua_pattern,
        "detect_enabled": not args.no_detect,
        "detect_categories": None,
        "rules_file": args.rules,
        "ioc_enabled": args.extract_ioc,
        "ioc_whitelist": args.ioc_whitelist,
        "ioc_export": args.ioc_export is not None,
        "suspicion_enabled": not args.no_suspicious,
        "suspicion_export": args.suspicious_export is not None,
        "suspicion_rules": args.suspicious_rules,
        "log_file": args.output is not None,
        "quiet": args.quiet,
        "no_color": args.no_color,
        "summary_interval": args.summary_interval,
    }

    if args.detect:
        cats = [c.strip() for c in args.detect.split(",")]
        invalid = [c for c in cats if c not in VALID_DETECT_CATEGORIES]
        if invalid:
            print(f"错误: 无效的检测类别: {', '.join(invalid)}")
            sys.exit(1)
        cfg["detect_categories"] = cats

    start_monitoring(cfg)


# ═══════════════════════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    # 有参数 → CLI 模式；无参数 → 菜单模式
    if len(sys.argv) > 1:
        cli_main()
    else:
        menu_main()
