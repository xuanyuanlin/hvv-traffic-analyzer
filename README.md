# HVV Traffic Analyzer

护网行动（HVV）实时流量分析工具 — 蓝队流量监控与攻击检测

## 功能

- **三分类流量分析**：确认攻击（红色告警）/ 可疑流量（黄色提示 + 导出）/ 普通流量
- **9 类攻击检测**：SQL注入、XSS、命令注入、目录遍历、文件上传、反序列化、Webshell通信、C2通信、Log4Shell
- **16 条可疑行为规则**：非浏览器UA、敏感路径、非标端口、高熵值请求、DNS异常、TLS异常等
- **IOC 自动提取**：IP、域名、URL、可疑UA、TLS指纹
- **Wireshark 检索词导出**：可疑流量导出含 Wireshark 过滤器和 grep 关键字

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 查看可用网卡
python main.py --list-interfaces

# 全量监控
python main.py -i "以太网"

# 全面监控（导出可疑流量 + IOC）
python main.py -i "以太网" --suspicious-export --extract-ioc --ioc-export
```

## 系统依赖

- Python 3.10+
- Wireshark（含 tshark，需在 PATH 中）

## 文档

- [使用手册](USAGE.md) — 怎么用、各选项效果、实战场景、错误提示
- [技术手册](MANUAL.md) — 项目结构、文件详解、规则修改指南

## 许可证

MIT License
