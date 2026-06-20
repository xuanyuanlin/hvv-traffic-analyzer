"""数据包解析模块

将 tshark -T ek 输出的 JSON 解析为统一的 Packet 结构体。
支持 HTTP、DNS、TLS 等协议子结构。
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class HTTPInfo:
    """HTTP 协议信息"""
    method: str = ""            # GET/POST/PUT/DELETE/...
    uri: str = ""               # 请求路径（不含 host）
    host: str = ""              # Host 头
    user_agent: str = ""
    content_type: str = ""
    cookie: str = ""
    status_code: int = 0
    request_body: str = ""      # POST body（hex 字符串）
    request_body_raw: bytes = b""
    full_uri: str = ""          # 完整 URI（含 query string）
    referer: str = ""


@dataclass
class DNSInfo:
    """DNS 协议信息"""
    query_name: str = ""
    query_type: str = ""        # A/AAAA/TXT/CNAME/MX/NS/SOA/PTR/...
    response: list[str] = field(default_factory=list)
    response_code: str = ""     # NOERROR/NXDOMAIN/SERVFAIL/...
    is_response: bool = False   # True 表示是 DNS 响应包


@dataclass
class TLSInfo:
    """TLS/SSL 协议信息"""
    version: str = ""           # TLS 1.2 / TLS 1.3
    sni: str = ""               # Server Name Indication
    ja3: str = ""
    ja3s: str = ""
    ja4: str = ""
    ja4s: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cipher_suite: str = ""


@dataclass
class Packet:
    """统一的数据包结构"""
    timestamp: float = 0.0
    timestamp_str: str = ""     # 人类可读时间
    frame_num: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""          # HTTP/DNS/TLS/TCP/UDP/SMB/RDP/SSH/FTP/...
    length: int = 0
    payload_preview: str = ""   # 载荷前 512 字节预览
    payload_raw: bytes = b""
    tcp_flags: str = ""

    # 协议子结构（按需填充）
    http: Optional[HTTPInfo] = None
    dns: Optional[DNSInfo] = None
    tls: Optional[TLSInfo] = None


def _safe_str(val, default: str = "") -> str:
    """安全取字符串值，处理 None 和 list 情况"""
    if val is None:
        return default
    if isinstance(val, list):
        return val[0] if val else default
    return str(val)


def _safe_int(val, default: int = 0) -> int:
    """安全取整数值"""
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _hex_to_bytes(hex_str: str) -> bytes:
    """将十六进制字符串转为 bytes"""
    if not hex_str:
        return b""
    try:
        return bytes.fromhex(hex_str.replace(":", "").replace(" ", ""))
    except ValueError:
        return b""


def _calc_entropy(data: bytes) -> float:
    """计算香农熵值"""
    import math
    if not data:
        return 0.0
    length = len(data)
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def parse_packet(raw: dict) -> Packet:
    """将 tshark EK JSON 解析为 Packet 结构

    tshark -T ek 输出的 JSON 结构:
    {
      "timestamp": 1680000000000000,
      "layers": {
        "frame": {"frame.number": "1", "frame.len": "120",
                  "frame.protocols": "eth:ip:tcp:http", "frame.time": "..."},
        "ip": {"ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"},
        "tcp": {"tcp.srcport": "12345", "tcp.dstport": "80",
                "tcp.flags": "0x0018"},
        "http": {"http.request.method": "POST", "http.host": "example.com", ...},
        "dns": {"dns.qry.name": "evil.com", "dns.qry.type": "16", ...},
        "tls": {...}
      }
    }
    """
    pkt = Packet()

    layers = raw.get("layers", {})

    # --- frame 层 ---
    frame = layers.get("frame", {})
    pkt.frame_num = _safe_int(frame.get("frame.number"))
    pkt.length = _safe_int(frame.get("frame.len"))
    pkt.timestamp_str = _safe_str(frame.get("frame.time", ""))

    # 解析时间戳（EK 中 timestamp 为微秒级 Unix 时间戳）
    ts = raw.get("timestamp")
    if ts:
        pkt.timestamp = float(ts) / 1_000_000  # 微秒转秒
        if not pkt.timestamp_str:
            pkt.timestamp_str = datetime.fromtimestamp(pkt.timestamp).strftime(
                "%Y-%m-%d %H:%M:%S.%f"
            )[:-3]  # 毫秒精度

    # 协议链（取最高层协议作为主协议）
    protocols_str = _safe_str(frame.get("frame.protocols", ""))
    if protocols_str:
        proto_list = protocols_str.split(":")
        # 取最高层协议（列表最后一个）
        pkt.protocol = proto_list[-1].upper() if proto_list else ""

    # --- IP 层 ---
    ip_layer = layers.get("ip", {})
    if ip_layer:
        pkt.src_ip = _safe_str(ip_layer.get("ip.src"))
        pkt.dst_ip = _safe_str(ip_layer.get("ip.dst"))

    # --- TCP 层 ---
    tcp_layer = layers.get("tcp", {})
    if tcp_layer:
        pkt.src_port = _safe_int(tcp_layer.get("tcp.srcport"))
        pkt.dst_port = _safe_int(tcp_layer.get("tcp.dstport"))
        pkt.tcp_flags = _safe_str(tcp_layer.get("tcp.flags", ""))

    # --- UDP 层（如无 TCP） ---
    if not tcp_layer:
        udp_layer = layers.get("udp", {})
        if udp_layer:
            pkt.src_port = _safe_int(udp_layer.get("udp.srcport"))
            pkt.dst_port = _safe_int(udp_layer.get("udp.dstport"))

    # --- 载荷预览 ---
    data_layer = layers.get("data", {})
    if data_layer:
        hex_data = _safe_str(data_layer.get("data.data", ""))
        pkt.payload_raw = _hex_to_bytes(hex_data)
        if pkt.payload_raw:
            # 尝试解码为 UTF-8，失败则用 repr
            try:
                preview = pkt.payload_raw[:512].decode("utf-8", errors="replace")
            except Exception:
                preview = repr(pkt.payload_raw[:512])
            pkt.payload_preview = preview

    # --- HTTP 子结构 ---
    http_layer = layers.get("http", {})
    if http_layer:
        pkt.http = _parse_http(http_layer)

    # --- DNS 子结构 ---
    dns_layer = layers.get("dns", {})
    if dns_layer:
        pkt.dns = _parse_dns(dns_layer)

    # --- TLS 子结构 ---
    tls_layer = layers.get("tls", {})
    if tls_layer:
        pkt.tls = _parse_tls(tls_layer)

    return pkt


def _parse_http(layer: dict) -> HTTPInfo:
    """解析 HTTP 协议层"""
    info = HTTPInfo()
    info.method = _safe_str(layer.get("http.request.method"))
    info.uri = _safe_str(layer.get("http.request.uri"))
    info.full_uri = _safe_str(layer.get("http.request.full_uri"))
    info.host = _safe_str(layer.get("http.host"))
    info.user_agent = _safe_str(layer.get("http.user_agent"))
    info.content_type = _safe_str(layer.get("http.content_type"))
    info.cookie = _safe_str(layer.get("http.cookie"))
    info.referer = _safe_str(layer.get("http.referer"))
    info.status_code = _safe_int(layer.get("http.response.code"))

    # POST body
    body_hex = _safe_str(layer.get("http.file_data", ""))
    if body_hex:
        info.request_body_raw = _hex_to_bytes(body_hex)
        try:
            info.request_body = info.request_body_raw.decode("utf-8", errors="replace")
        except Exception:
            info.request_body = repr(info.request_body_raw[:512])

    return info


def _parse_dns(layer: dict) -> DNSInfo:
    """解析 DNS 协议层"""
    info = DNSInfo()
    info.query_name = _safe_str(layer.get("dns.qry.name"))
    info.query_type = _safe_str(layer.get("dns.qry.type"))
    info.response_code = _safe_str(layer.get("dns.flags.rcode"))

    # DNS 响应记录
    answers = layer.get("dns.a", [])
    if isinstance(answers, str):
        answers = [answers]
    info.response = answers

    # AAAA 记录
    aaaa = layer.get("dns.aaaa", [])
    if aaaa:
        if isinstance(aaaa, str):
            aaaa = [aaaa]
        info.response.extend(aaaa)

    # 判断是请求还是响应
    flags = _safe_str(layer.get("dns.flags.response", "0"))
    info.is_response = flags == "1"

    # 如果 query_name 为空，尝试从 dns.qry.name 获取
    if not info.query_name:
        info.query_name = _safe_str(layer.get("dns.qry.name", ""))

    return info


def _parse_tls(layer: dict) -> TLSInfo:
    """解析 TLS/SSL 协议层"""
    info = TLSInfo()

    # TLS 版本
    info.version = _safe_str(layer.get("tls.handshake.version", ""))
    # 人类可读的版本号
    ver_map = {
        "0x0301": "TLS 1.0",
        "0x0302": "TLS 1.1",
        "0x0303": "TLS 1.2",
        "0x0304": "TLS 1.3",
    }
    if info.version in ver_map:
        info.version = ver_map[info.version]

    # SNI（Server Name Indication）
    info.sni = _safe_str(layer.get("tls.handshake.extensions_server_name", ""))

    # JA3/JA3S（需要 tshark 编译时支持）
    info.ja3 = _safe_str(layer.get("tls.handshake.ja3", ""))
    info.ja3s = _safe_str(layer.get("tls.handshake.ja3s", ""))

    # JA4/JA4S（需要 Suricata 或自定义插件）
    info.ja4 = _safe_str(layer.get("tls.handshake.ja4", ""))
    info.ja4s = _safe_str(layer.get("tls.handshake.ja4s", ""))

    # 证书信息
    info.cert_subject = _safe_str(layer.get("tls.handshake.certificate.subject", ""))
    info.cert_issuer = _safe_str(layer.get("tls.handshake.certificate.issuer", ""))

    # 密码套件
    info.cipher_suite = _safe_str(layer.get("tls.handshake.ciphersuite", ""))

    return info
