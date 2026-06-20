"""tshark 实时抓封装模块

通过 subprocess 启动 tshark，以 -T ek（Elastic JSON）格式流式输出数据包。
支持 BPF 过滤、时长限制、网卡列表查询。
"""

import json
import subprocess
import threading
import re
from typing import Iterator, Optional


class TsharkCapture:
    """封装 tshark 进程，实现流式实时抓包"""

    def __init__(self, interface: str, bpf_filter: Optional[str] = None,
                 duration: Optional[int] = None, snapshot_len: int = 65535):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.duration = duration
        self.snapshot_len = snapshot_len
        self._process: Optional[subprocess.Popen] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        """启动 tshark 子进程"""
        cmd = ["tshark"]
        # -i: 网卡（支持名称或索引）
        cmd.extend(["-i", self.interface])
        # -T ek: Elastic JSON 输出，每行一个 JSON 对象
        cmd.extend(["-T", "ek"])
        # -l: 实时刷新输出（不缓冲）
        cmd.append("-l")
        # -s: 每包最大捕获字节
        cmd.extend(["-s", str(self.snapshot_len)])
        # -f: BPF 过滤表达式
        if self.bpf_filter:
            cmd.extend(["-f", self.bpf_filter])
        # -a duration:N: 抓包时长限制
        if self.duration:
            cmd.extend(["-a", f"duration:{self.duration}"])
        # 不解析主机名，避免 DNS 查询开销
        cmd.append("-n")
        # 不使用默认名称解析
        cmd.append("-N", )

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # 行缓冲
            encoding="utf-8",
            errors="replace"
        )

    def stop(self) -> None:
        """优雅停止 tshark 子进程"""
        self._stop_event.set()
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()

    def packets(self) -> Iterator[dict]:
        """逐包读取 tshark stdout，解析为 dict 并 yield

        tshark -T ek 输出格式：
        - 每个数据包是一个 JSON 对象
        - 包与包之间以换行分隔
        - 第一行为 index 行（可忽略），第二行为实际包数据
        - 每对行为一个完整的事件

        注意：EK 格式每个包输出两行 JSON
        - 第一行：index 元数据（可跳过）
        - 第二行：实际包数据（我们需要的）
        """
        if not self._process:
            raise RuntimeError("tshark 未启动，请先调用 start()")

        pair_buffer = []
        line_count = 0

        while not self._stop_event.is_set():
            line = self._process.stdout.readline()
            if not line:
                # 进程结束
                break
            line = line.strip()
            if not line:
                continue

            # 跳过 tshark 的启动提示行（非 JSON）
            if not line.startswith("{"):
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # EK 格式：每两行为一个包事件
            # 第一行为 index 元数据，第二行为实际包数据
            if "index" in data:
                # 这是 index 行，跳过（下一行是实际数据）
                continue

            # 实际的包数据行包含 "timestamp" 和 "layers"
            if "layers" in data or "timestamp" in data:
                yield data

    @staticmethod
    def list_interfaces() -> list[dict]:
        """调用 tshark -D 列出所有可用网卡

        返回: [{"index": 1, "name": "\\Device\\NPF_{...}", "desc": "以太网"}, ...]
        """
        try:
            result = subprocess.run(
                ["tshark", "-D"],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
        except FileNotFoundError:
            raise RuntimeError("tshark 未找到，请确认 Wireshark 已安装且 tshark 在 PATH 中")
        except subprocess.TimeoutExpired:
            raise RuntimeError("tshark -D 执行超时")

        if result.returncode != 0:
            raise RuntimeError(f"tshark -D 失败: {result.stderr.strip()}")

        interfaces = []
        # 输出格式: "1. \Device\NPF_{xxx} (以太网)"
        # 或: "1. eth0"
        pattern = re.compile(r'^(\d+)\.\s+(.+?)(?:\s+\((.+)\))?\s*$')
        for line in result.stdout.strip().splitlines():
            m = pattern.match(line.strip())
            if m:
                interfaces.append({
                    "index": int(m.group(1)),
                    "name": m.group(2).strip(),
                    "desc": (m.group(3) or "").strip()
                })
        return interfaces
