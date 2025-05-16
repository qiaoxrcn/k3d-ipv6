#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import re
import socket
import subprocess
import sys
import time
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple, Dict

# 彩色日志输出
class Colors:
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    CYAN = '\033[36m'
    RESET = '\033[0m'

# 全局配置
class Config:
    # 网络配置
    DOCKER_BRIDGE_NAME = "k3d-ipv6-net"
    SUBNET_PREFIX = "fd00:beaf"  # 私有 IPv6 前缀
    DOCKER_IPV4_SUBNET = "172.28.0.0/16"
    DOCKER_IPV6_SUBNET = f"{SUBNET_PREFIX}::/64"
    DOCKER_IPV4_GATEWAY = "172.28.0.1"
    DOCKER_IPV6_GATEWAY = f"{SUBNET_PREFIX}::1"
    NAT66_SRC_RANGE = f"{SUBNET_PREFIX}::/48"  # NAT66 匹配范围

    # k3d集群相关配置
    DEFAULT_DOMAIN_SUFFIX = "unifra.xyz"
    DEFAULT_AGENT_COUNT = 2

    # Nginx 相关配置
    NGINX_HTTP_CONF_DIR = "/etc/nginx/conf.d"
    NGINX_STREAM_CONF_DIR = "/etc/nginx/stream-conf.d" 
    DEFAULT_HTTP_BACKEND = "127.0.0.1:8080"
    DEFAULT_HTTPS_BACKEND = "127.0.0.1:4443"

    # 应用配置
    VERBOSE = False

    # 集群CIDR
    POD_IPV4_CIDR = "10.42.0.0/16"
    POD_IPV6_CIDR = f"{SUBNET_PREFIX}:42::/56"
    SERVICE_IPV4_CIDR = "10.43.0.0/16" 
    SERVICE_IPV6_CIDR = f"{SUBNET_PREFIX}:43::/108"

# 日志工具
def log(message: str) -> None:
    print(f"{Colors.GREEN}[+]{Colors.RESET} {message}")

def info(message: str) -> None:
    if Config.VERBOSE:
        print(f"{Colors.CYAN}[i]{Colors.RESET} {message}")

def warn(message: str) -> None:
    print(f"{Colors.YELLOW}[!]{Colors.RESET} {message}")

def error(message: str) -> None:
    print(f"{Colors.RED}[×]{Colors.RESET} {message}", file=sys.stderr)

def die(message: str) -> None:
    error(message)
    sys.exit(1)

# 执行命令并返回输出
def run_cmd(cmd: List[str], check: bool = True, capture_output: bool = True, sudo: bool = False) -> subprocess.CompletedProcess:
    if sudo and os.geteuid() != 0:
        cmd = ["sudo"] + cmd
    
    try:
        result = subprocess.run(
            cmd,
            check=check,
            text=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None
        )
        return result
    except subprocess.CalledProcessError as e:
        if check:
            die(f"命令执行失败: {' '.join(cmd)}\n错误: {e.stderr}")
        return e

# 找到两个可用端口
def get_two_free_ports() -> Tuple[int, int]:
    # 获取已使用端口列表
    try:
        result = run_cmd(["ss", "-lnt"])
        used_ports = set()
        for line in result.stdout.splitlines()[1:]:  # 跳过标题行
            parts = line.split()
            if len(parts) >= 5: # ss output can vary, ensure we have enough parts
                addr = parts[3] # For 'ss -lnt', Local Address:Port is typically the 4th field (0-indexed)
                port_match = re.search(r':(\\d+)$', addr)
                if port_match:
                    used_ports.add(int(port_match.group(1)))
    except Exception as e:
        warn(f"获取已使用端口时出错: {e}")
        used_ports = set()
    
    # 尝试 xx 从 0 到 99
    for xx in range(100): # Generates xx from 0 to 99
        http_port = 8000 + xx
        https_port = 44300 + xx

        if http_port in used_ports:
            info(f"端口 {http_port} (80{xx:02d}) 在 ss 输出中被标记为已使用，跳过 xx={xx:02d}")
            continue
        if https_port in used_ports:
            info(f"端口 {https_port} (443{xx:02d}) 在 ss 输出中被标记为已使用，跳过 xx={xx:02d}")
            continue

        # 双重检查端口是否可用
        http_port_free = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_http:
                s_http.bind(("127.0.0.1", http_port))
            http_port_free = True
        except OSError:
            info(f"端口 {http_port} (80{xx:02d}) 绑定测试失败，尝试下一个 xx={xx:02d}")
            continue # http_port 不可用，尝试下一个 xx

        if http_port_free:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_https:
                    s_https.bind(("127.0.0.1", https_port))
                # 两个端口都可用
                log(f"找到可用端口对: HTTP={http_port} (80{xx:02d}), HTTPS={https_port} (443{xx:02d})")
                return http_port, https_port
            except OSError:
                info(f"端口 {https_port} (443{xx:02d}) 绑定测试失败 (HTTP端口 {http_port} 可用)，尝试下一个 xx={xx:02d}")
                # https_port 不可用，继续下一个 xx
                continue
    
    die("无法在 8000-8099 和 44300-44399 范围内找到符合模式 80xx, 443xx 的可用端口对")

# 等待容器可用
def wait_for_container(container: str, timeout: int = 60) -> bool:
    log(f"等待容器 {container} 就绪...")
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            result = run_cmd(["docker", "inspect", container], check=False)
            if result.returncode == 0:
                info(f"容器 {container} 已就绪")
                return True
        except Exception:
            pass
        time.sleep(1)
    
    warn(f"等待容器 {container} 超时 ({timeout} 秒)")
    return False

# 检查主机环境并确保适当的设置
def check_host_sanity() -> None:
    log("检查主机环境...")
    
    # 1) IPv6 rp_filter 应关闭 (0)
    try:
        result = run_cmd(["sysctl", "-n", "net.ipv6.conf.all.rp_filter"], check=False)
        rpf = result.stdout.strip() if result.returncode == 0 else "0"
        
        if rpf != "0":
            warn(f"net.ipv6.conf.all.rp_filter={rpf}，会导致回包被丢，自动改为 0")
            run_cmd(["sysctl", "-qw", "net.ipv6.conf.all.rp_filter=0"], sudo=True)
            
            # 确保设置持久化
            sysctl_conf = "/etc/sysctl.conf"
            if os.path.exists(sysctl_conf):
                with open(sysctl_conf, 'r') as f:
                    if 'net.ipv6.conf.all.rp_filter=0' not in f.read():
                        run_cmd(["bash", "-c", "echo 'net.ipv6.conf.all.rp_filter=0' | sudo tee -a /etc/sysctl.conf > /dev/null"])
    except Exception as e:
        warn(f"配置 IPv6 rp_filter 时出错: {e}")
    
    # 2) ip6tables INPUT 应允许 ESTABLISHED,RELATED
    try:
        result = run_cmd(["ip6tables", "-C", "INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], 
                        check=False, sudo=True)
        
        if result.returncode != 0:
            warn("在 ip6tables INPUT 链中插入 ESTABLISHED,RELATED 放行规则")
            run_cmd(["ip6tables", "-I", "INPUT", "1", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], 
                   sudo=True)
    except Exception as e:
        warn(f"配置 ip6tables 规则时出错: {e}")
    
    info("主机环境检查完成")

# 启用 IPv6 转发
def enable_ipv6_forwarding() -> None:
    log("启用宿主机 IPv6 转发...")
    run_cmd(["sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"], sudo=True)
    
    # 确保设置持久化
    sysctl_conf = "/etc/sysctl.conf"
    if os.path.exists(sysctl_conf):
        with open(sysctl_conf, 'r') as f:
            content = f.read()
        
        if 'net.ipv6.conf.all.forwarding=1' not in content:
            run_cmd(["bash", "-c", "echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf > /dev/null"])
            info("已将 IPv6 转发设置添加至 /etc/sysctl.conf")

# 创建 Docker 双栈网络
def create_docker_network() -> None:
    # 检查网络是否存在
    result = run_cmd(["docker", "network", "inspect", Config.DOCKER_BRIDGE_NAME], check=False)
    
    if result.returncode != 0:
        log(f"创建 Docker dual-stack 网络: {Config.DOCKER_BRIDGE_NAME}")
        run_cmd([
            "docker", "network", "create", Config.DOCKER_BRIDGE_NAME,
            "--driver", "bridge",
            "--subnet", Config.DOCKER_IPV4_SUBNET,
            "--gateway", Config.DOCKER_IPV4_GATEWAY,
            "--ipv6",
            "--subnet", Config.DOCKER_IPV6_SUBNET,
            "--gateway", Config.DOCKER_IPV6_GATEWAY
        ])
        info("已创建 Docker 网络")
    else:
        log(f"Docker 网络 {Config.DOCKER_BRIDGE_NAME} 已存在，将继续使用")

# 设置 NAT66 规则
def setup_nat66() -> None:
    log(f"配置 NAT66 (源 {Config.NAT66_SRC_RANGE})...")
    
    # 检查 POSTROUTING 链是否存在
    result = run_cmd(["ip6tables", "-t", "nat", "-L", "POSTROUTING"], check=False, sudo=True)
    
    if result.returncode != 0:
        warn("NAT 表中不存在 POSTROUTING 链，将创建")
        run_cmd(["ip6tables", "-t", "nat", "-N", "POSTROUTING"], check=False, sudo=True)
    
    # 清理现有规则并添加新规则
    run_cmd(["ip6tables", "-t", "nat", "-F", "POSTROUTING"], check=False, sudo=True)
    run_cmd([
        "ip6tables", "-t", "nat", "-A", "POSTROUTING",
        "-s", Config.NAT66_SRC_RANGE,
        "!", "-o", Config.DOCKER_BRIDGE_NAME,
        "-j", "MASQUERADE"
    ], sudo=True)
    
    # 尝试保存规则
    try:
        result = run_cmd(["which", "netfilter-persistent"], check=False)
        if result.returncode == 0:
            info("使用 netfilter-persistent 保存 ip6tables 规则")
            run_cmd(["netfilter-persistent", "save"], sudo=True)
        else:
            info("提示: 安装 netfilter-persistent 可持久化保存 ip6tables 规则")
    except Exception as e:
        warn(f"保存 ip6tables 规则时出错: {e}")

# 创建 k3d 集群
def create_k3d_cluster(cluster_name: str, agent_count: int, http_port: int, https_port: int) -> None:
    log(f"创建 k3d 集群: {cluster_name} (agents: {agent_count}, HTTP: {http_port}, HTTPS: {https_port})")
    
    cmd = [
        "k3d", "cluster", "create", cluster_name,
        "--network", Config.DOCKER_BRIDGE_NAME,
        "--agents", str(agent_count),
        "--port", f"127.0.0.1:{http_port}:80@loadbalancer",
        "--port", f"127.0.0.1:{https_port}:443@loadbalancer",
        "--k3s-arg", f"--cluster-cidr={Config.POD_IPV4_CIDR},{Config.POD_IPV6_CIDR}@server:0",
        "--k3s-arg", f"--service-cidr={Config.SERVICE_IPV4_CIDR},{Config.SERVICE_IPV6_CIDR}@server:0",
        "--k3s-arg", "--disable=traefik@server:0",
        "--k3s-arg", "--disable-network-policy@server:0",
        "--k3s-arg", "--flannel-ipv6-masq@server:*",
        "--wait"
    ]
    
    run_cmd(cmd)
    log(f"集群 {cluster_name} 创建成功")

# 生成 Nginx 配置（共享模板方法）
def generate_nginx_configs(cluster_name: str, domain_suffix: str, http_port: int, https_port: int) -> Tuple[str, str]:
    """生成 Nginx HTTP 和 Stream 配置内容"""
    # 替换破折号为下划线，确保map变量名有效
    safe_map_var = cluster_name.replace('-', '_')
    
    # HTTP 配置
    http_conf = f"""map $host $backend_http_{safe_map_var} {{
    ~^.*\\.{cluster_name}\\.{domain_suffix}$  127.0.0.1:{http_port};
    default                                    {Config.DEFAULT_HTTP_BACKEND};
}}

server {{
    listen [::]:80 reuseport;
    location / {{
        proxy_pass http://$backend_http_{safe_map_var};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""

    # Stream 配置
    stream_conf = f"""stream {{
    map $ssl_preread_server_name $backend_https_{safe_map_var} {{
        ~^.*\\.{cluster_name}\\.{domain_suffix}$  127.0.0.1:{https_port};
        default                                    {Config.DEFAULT_HTTPS_BACKEND};
    }}

    server {{
        listen [::]:443 reuseport;   # 仅 IPv6；如要双栈再加一行 listen 443;
        proxy_pass  $backend_https_{safe_map_var};
        ssl_preread on;
    }}
}}
"""
    return http_conf, stream_conf

# 配置 Nginx 集群入口 - 使用单独配置文件方法
def configure_nginx_for_cluster(cluster_name: str, domain_suffix: str, http_port: int, https_port: int) -> None:
    log(f"配置 Nginx 以代理到集群 {cluster_name}")
    
    http_conf, stream_conf = generate_nginx_configs(cluster_name, domain_suffix, http_port, https_port)
    
    # 共享 HTTP 配置文件
    http_conf_file = f"{Config.NGINX_HTTP_CONF_DIR}/k3d-clusters-http.conf"
    stream_conf_file = f"{Config.NGINX_STREAM_CONF_DIR}/k3d-clusters-stream.conf"
    
    # 使用统一的配置文件 - 通过修改现有文件或创建新文件
    # 创建或更新 HTTP 配置
    update_nginx_config_with_patterns(
        http_conf_file, 
        cluster_name, 
        domain_suffix, 
        http_port, 
        is_http=True
    )
    
    # 创建或更新 Stream 配置
    update_nginx_config_with_patterns(
        stream_conf_file, 
        cluster_name, 
        domain_suffix, 
        https_port, 
        is_http=False
    )
    
    # 删除旧的独立配置文件（如果存在）
    old_http_conf = f"{Config.NGINX_HTTP_CONF_DIR}/k3d-http-{cluster_name}.conf"
    old_stream_conf = f"{Config.NGINX_STREAM_CONF_DIR}/k3d-stream-{cluster_name}.conf"
    
    if os.path.exists(old_http_conf):
        run_cmd(["rm", "-f", old_http_conf], sudo=True)
    
    if os.path.exists(old_stream_conf):
        run_cmd(["rm", "-f", old_stream_conf], sudo=True)
    
    reload_nginx()

# 更新 Nginx 配置文件（添加或更新集群配置）
def update_nginx_config_with_patterns(config_file: str, cluster_name: str, domain_suffix: str, port: int, is_http: bool) -> None:
    """添加或更新 Nginx 配置中的集群配置，并处理可能的端口冲突"""
    domain_pattern = fr"~^(?:.*\.)?{cluster_name}\.{domain_suffix}$"
    indent = "    " if is_http else "        "
    backend_line = f"{indent}{domain_pattern}  127.0.0.1:{port};"
    port_pattern = f"127.0.0.1:{port}"
    
    # 检查文件是否存在
    if not os.path.exists(config_file):
        # 文件不存在，创建基本配置结构（与原代码相同）
        if is_http:
            content = f"""# 集群 HTTP 映射 - 由 k3d 脚本自动管理
map $host $k3d_backend {{
    # CLUSTER_MAPPINGS_START
    {domain_pattern}  127.0.0.1:{port};
    # CLUSTER_MAPPINGS_END
    default            {Config.DEFAULT_HTTP_BACKEND};
}}

server {{
    listen [::]:80 reuseport;
    
    location / {{
        proxy_pass http://$k3d_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }}
}}
"""
        else:
            content = f"""stream {{
    # 集群 HTTPS 映射 - 由 k3d 脚本自动管理
    map $ssl_preread_server_name $k3d_stream_backend {{
        # CLUSTER_MAPPINGS_START
        {domain_pattern}  127.0.0.1:{port};
        # CLUSTER_MAPPINGS_END
        default            {Config.DEFAULT_HTTPS_BACKEND};
    }}

    server {{
        listen [::]:443 reuseport;
        proxy_pass $k3d_stream_backend;
        ssl_preread on;
    }}
}}
"""
        # 写入新文件
        with open("/tmp/nginx_config.tmp", "w") as f:
            f.write(content)
        run_cmd(["cp", "/tmp/nginx_config.tmp", config_file], sudo=True)
        run_cmd(["rm", "/tmp/nginx_config.tmp"])
        return
    
    # 文件存在，读取内容
    with open("/tmp/nginx_config.tmp", "w") as tmp_file:
        result = run_cmd(["cat", config_file], sudo=True)
        content = result.stdout
        lines = content.splitlines()
        
        # 处理端口冲突：移除任何使用相同端口但不是当前集群的映射
        filtered_lines = []
        removed_patterns = []
        
        for line in lines:
            # 如果行包含当前处理的端口，但不是当前集群的配置
            if port_pattern in line and domain_pattern not in line:
                # 提取被移除的域名模式，用于日志
                pattern_match = re.search(r'(~\^.*\$)', line)
                if pattern_match:
                    removed_patterns.append(pattern_match.group(1))
                continue  # 跳过此行，不添加到结果中
            filtered_lines.append(line)
        
        # 如果有移除的映射，记录日志
        if removed_patterns:
            warn(f"检测到端口冲突：移除了使用端口 {port} 的以下映射: {', '.join(removed_patterns)}")
        
        # 现在处理当前集群的配置
        # 检查现有行中是否已有当前集群的映射
        current_mapping_exists = False
        for i, line in enumerate(filtered_lines):
            if domain_pattern in line:
                filtered_lines[i] = backend_line  # 更新现有映射
                current_mapping_exists = True
                break
        
        # 如果没有找到当前集群的映射，添加新映射
        if not current_mapping_exists:
            # 尝试在标记之间添加
            if "# CLUSTER_MAPPINGS_START" in content and "# CLUSTER_MAPPINGS_END" in content:
                for i, line in enumerate(filtered_lines):
                    if "# CLUSTER_MAPPINGS_START" in line:
                        filtered_lines.insert(i + 1, backend_line)
                        break
            else:
                # 在 default 前添加
                for i, line in enumerate(filtered_lines):
                    if "default" in line:
                        filtered_lines.insert(i, backend_line)
                        break
        
        tmp_file.write("\n".join(filtered_lines))
    
    # 更新文件
    run_cmd(["cp", "/tmp/nginx_config.tmp", config_file], sudo=True)
    run_cmd(["rm", "/tmp/nginx_config.tmp"])

# 删除特定集群的 Nginx 配置
def remove_nginx_config_for_cluster(cluster_name: str, domain_suffix: str = None) -> None:
    if domain_suffix is None:
        domain_suffix = Config.DEFAULT_DOMAIN_SUFFIX
    
    domain_pattern = fr"~^(?:.*\.)?{cluster_name}\.{domain_suffix}$"
    log(f"从 Nginx 配置中删除集群 {cluster_name} 的映射")
    
    # 处理 HTTP 配置
    http_conf = f"{Config.NGINX_HTTP_CONF_DIR}/k3d-clusters-http.conf"
    if os.path.exists(http_conf):
        # 创建临时文件并处理
        with open("/tmp/nginx_http.tmp", "w") as tmp_file:
            result = run_cmd(["cat", http_conf], sudo=True)
            lines = [line for line in result.stdout.splitlines() if domain_pattern not in line]
            tmp_file.write("\n".join(lines))
        
        run_cmd(["cp", "/tmp/nginx_http.tmp", http_conf], sudo=True)
        run_cmd(["rm", "/tmp/nginx_http.tmp"])
        info("已从 HTTP 配置删除集群映射")
    
    # 处理 Stream 配置
    stream_conf = f"{Config.NGINX_STREAM_CONF_DIR}/k3d-clusters-stream.conf"
    if os.path.exists(stream_conf):
        # 创建临时文件并处理
        with open("/tmp/nginx_stream.tmp", "w") as tmp_file:
            result = run_cmd(["cat", stream_conf], sudo=True)
            lines = [line for line in result.stdout.splitlines() if domain_pattern not in line]
            tmp_file.write("\n".join(lines))
        
        run_cmd(["cp", "/tmp/nginx_stream.tmp", stream_conf], sudo=True)
        run_cmd(["rm", "/tmp/nginx_stream.tmp"])
        info("已从 Stream 配置删除集群映射")
    
    # 删除旧风格的配置文件（如果存在）
    old_http_conf = f"{Config.NGINX_HTTP_CONF_DIR}/k3d-http-{cluster_name}.conf"
    old_stream_conf = f"{Config.NGINX_STREAM_CONF_DIR}/k3d-stream-{cluster_name}.conf"
    
    if os.path.exists(old_http_conf):
        run_cmd(["rm", "-f", old_http_conf], sudo=True)
        info(f"已删除旧的 HTTP 配置: {old_http_conf}")
    
    if os.path.exists(old_stream_conf):
        run_cmd(["rm", "-f", old_stream_conf], sudo=True)
        info(f"已删除旧的 Stream 配置: {old_stream_conf}")
    
    reload_nginx()

# 重新加载 Nginx 配置
def reload_nginx() -> bool:
    log("重新加载 Nginx 配置...")
    
    # 先测试配置有效性
    result = run_cmd(["nginx", "-t"], check=False, sudo=True, capture_output=True)
    if result.returncode != 0:
        warn("Nginx 配置测试失败，详细信息:")
        print(result.stderr)
        return False
    
    # 重新加载配置
    try:
        # 尝试使用 systemctl
        systemctl_result = run_cmd(["systemctl", "is-active", "nginx"], check=False)
        if systemctl_result.returncode == 0 and systemctl_result.stdout.strip() == "active":
            run_cmd(["systemctl", "reload", "nginx"], sudo=True)
        else:
            run_cmd(["nginx", "-s", "reload"], sudo=True)
        
        info("Nginx 配置已重新加载")
        return True
    except Exception as e:
        warn(f"重新加载 Nginx 配置时出错: {e}")
        return False

# 在 k3d 节点上配置网络
def configure_k3d_node_networking(cluster_name: str) -> None:
    log("配置 k3d 节点网络 (动态发现 agent 节点)... ")
    
    pod_cidr = f"{Config.SUBNET_PREFIX}:42::/56" # Pod CIDR
    
    # 1. 配置服务器节点 (通常只有一个，且命名固定)
    server_container_name = f"k3d-{cluster_name}-server-0"
    if wait_for_container(server_container_name, 30):
        info(f"配置服务器节点 NAT: {server_container_name}")
        run_cmd([
            "docker", "exec", server_container_name, "ip6tables", "-t", "nat", "-A", "POSTROUTING",
            "-s", pod_cidr, "-o", "eth0", "-j", "MASQUERADE"
        ])
    else:
        warn(f"服务器容器 {server_container_name} 未就绪，可能影响网络配置。")

    # 2. 动态发现并配置 Agent 节点
    log(f"动态发现集群 '{cluster_name}' 的 agent 节点...")
    try:
        # 使用 docker ps 筛选属于特定集群且角色为 agent 的容器
        # k3d 通常会给容器打上标签，如 k3d.cluster=<cluster_name> 和 k3d.role=agent
        # 我们也检查容器名中是否包含 agent 作为备用方案
        cmd = [
            "docker", "ps",
            "--filter", f"label=k3d.cluster={cluster_name}",
            "--filter", "label=k3d.role=agent",
            "--format", "{{.Names}}"
        ]
        result = run_cmd(cmd, check=True, capture_output=True, sudo=False)
        agent_container_names = [name.strip() for name in result.stdout.splitlines() if name.strip()] 

        if not agent_container_names:
            # 如果基于标签的筛选没有结果，尝试基于名称的模糊匹配 (作为备选方案)
            info(f"未通过标签找到 agent 节点，尝试基于名称匹配 k3d-{cluster_name}-agent-* ...")
            cmd_fallback = [
                "docker", "ps",
                "--filter", f"name=k3d-{cluster_name}-agent",
                "--format", "{{.Names}}"
            ]
            result_fallback = run_cmd(cmd_fallback, check=True, capture_output=True, sudo=False)
            agent_container_names = [name.strip() for name in result_fallback.stdout.splitlines() if name.strip()]

        if not agent_container_names:
            warn(f"未能动态发现集群 '{cluster_name}' 的 agent 节点。将跳过 agent 节点的 NAT 配置。")
            return

        log(f"找到以下 Agent 节点: {', '.join(agent_container_names)}")

        for agent_container_name in agent_container_names:
            if wait_for_container(agent_container_name, 30): # 确保容器实际存在且可操作
                info(f"配置 Agent 节点 NAT: {agent_container_name}")
                run_cmd([
                    "docker", "exec", agent_container_name, "ip6tables", "-t", "nat", "-A", "POSTROUTING",
                    "-s", pod_cidr, "-o", "eth0", "-j", "MASQUERADE"
                ])
            else:
                warn(f"Agent 容器 {agent_container_name} 未就绪或未找到，跳过其 NAT 配置。")
                
    except Exception as e:
        warn(f"动态发现或配置 agent 节点时出错: {e}。请检查 Docker 是否正在运行以及是否有权限执行 docker ps。")

# 删除集群及相关资源
def delete_cluster_resources(cluster_name: str, domain_suffix: str) -> None:
    log(f"删除 k3d 集群: {cluster_name}")
    
    # 检查集群是否存在
    result = run_cmd(["k3d", "cluster", "list"], check=False)
    cluster_exists = False
    
    if result.returncode == 0:
        cluster_pattern = re.compile(rf"^{re.escape(cluster_name)}\s")
        for line in result.stdout.splitlines()[1:]:  # 跳过标题行
            if cluster_pattern.match(line):
                cluster_exists = True
                break
    
    # 删除 k3d 集群（如果存在）
    if cluster_exists:
        run_cmd(["k3d", "cluster", "delete", cluster_name])
        info(f"已删除集群: {cluster_name}")
    else:
        info(f"集群 {cluster_name} 不存在，无需删除")
    
    # 删除集群的 Nginx 配置
    remove_nginx_config_for_cluster(cluster_name, domain_suffix)
    
    log(f"✅ 已成功删除集群 {cluster_name} 及相关资源")

# 主函数
def main() -> None:
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="管理 k3d 集群和 IPv6 网络")
    parser.add_argument("cluster_name", help="集群名称")
    parser.add_argument("-d", "--delete", action="store_true", help="删除指定的集群及相关资源")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    parser.add_argument("--domain-suffix", default=Config.DEFAULT_DOMAIN_SUFFIX, 
                        help=f"设置域名后缀 (默认: {Config.DEFAULT_DOMAIN_SUFFIX})")
    parser.add_argument("--agents", type=int, default=Config.DEFAULT_AGENT_COUNT,
                       help=f"设置 agent 节点数量 (默认: {Config.DEFAULT_AGENT_COUNT})")
    parser.add_argument("--install-suite", action="store_true", 
                        help="安装一套标准的 Kubernetes 组件 (如 nginx, cert-manager, external-secrets, vault) 到新创建的集群中。")
    parser.add_argument("--if-exists", choices=["skip", "recreate"], default="skip",
                        help="当同名集群已存在时的操作：'skip' (跳过创建及k3d网络/Nginx配置)，'recreate' (删除并重新创建，默认)")
    
    args = parser.parse_args()
    
    # 设置详细日志级别
    Config.VERBOSE = args.verbose
    warn("warn 提示")
    # 检查权限
    if os.geteuid() != 0 and not check_sudo_available():
        die("此脚本需要 sudo 权限执行网络配置操作")
    
    # 构造完整域名
    domain = f"{args.cluster_name}.{args.domain_suffix}"
    log(f"开始处理集群: {args.cluster_name} (域名: {domain})")
    
    # 基础环境检查和设置
    check_host_sanity()
    enable_ipv6_forwarding()
    create_docker_network()
    setup_nat66()
    
    # 如果是删除操作
    if args.delete:
        delete_cluster_resources(args.cluster_name, args.domain_suffix)
        return
    
    # 检查集群是否存在
    cluster_exists_check_result = run_cmd(["k3d", "cluster", "list"], check=False)
    cluster_is_present = False
    if cluster_exists_check_result.returncode == 0:
        cluster_pattern = re.compile(rf"^{re.escape(args.cluster_name)}\s")
        if any(cluster_pattern.match(line) for line in cluster_exists_check_result.stdout.splitlines()[1:]):
            cluster_is_present = True

    if cluster_is_present:
        log(f"集群 '{args.cluster_name}' 已存在。")
        if args.if_exists == "recreate":
            log("操作设置为 'recreate'：将删除并重新创建集群。")
            run_cmd(["k3d", "cluster", "delete", args.cluster_name])
            # 让流程继续到下面的创建部分
        elif args.if_exists == "skip":
            log("操作设置为 'skip'：将跳过集群创建、k3d 网络配置和主机 Nginx 配置。")
            if args.install_suite:
                log(f"将尝试在现有集群 '{args.cluster_name}' 上安装套件。")
                log(f"重要提示：请确保 kubectl 上下文已正确设置为目标集群 '{args.cluster_name}'。")
                try:
                    install_cluster_suite()
                except Exception as e:
                    error(f"为现有集群 '{args.cluster_name}' 安装套件时出错: {e}")
                    warn("套件安装可能未完成。")
            log(f"✅ 操作完成：集群 '{args.cluster_name}' 已存在并跳过创建。")
            return # 结束脚本执行
    # 如果集群不存在，或者存在但设置为 recreate (已被删除)，则继续创建流程

    log(f"准备为集群 '{args.cluster_name}' 进行创建或重新创建操作。")
    
    # 获取可用端口 (仅在创建/重新创建时需要)
    try:
        http_port, https_port = get_two_free_ports()
        info(f"为新集群/重新创建的集群选定端口: HTTP={http_port}, HTTPS={https_port}")
    except Exception as e:
        die(f"无法获取可用端口: {e}")
    
    # 创建新集群并配置
    create_k3d_cluster(args.cluster_name, args.agents, http_port, https_port)
    configure_nginx_for_cluster(args.cluster_name, args.domain_suffix, http_port, https_port)
    configure_k3d_node_networking(args.cluster_name)
    
    # 如果指定，安装集群套件
    if args.install_suite:
        log(f"为新创建/重新创建的集群 '{args.cluster_name}' 安装套件。")
        try:
            install_cluster_suite() # k3d create 通常会设置 kubectl 上下文
        except Exception as e:
            error(f"为新集群 '{args.cluster_name}' 安装套件时出错: {e}")
            warn("套件安装可能未完成。")

    log(f"✅ 完成：集群 '{args.cluster_name}' 已成功创建/重新创建并配置。")
    info(f"  - HTTP 端口 (宿主机): {http_port}")
    info(f"  - HTTPS 端口 (宿主机): {https_port}")
    info(f"  - 应用域名(例如 *.{{domain}})应指向 k3d ingress (通常是 127.0.0.1 或者宿主机的 IP)。")

# 检查 sudo 是否可用
def check_sudo_available() -> bool:
    try:
        result = run_cmd(["which", "sudo"], check=False)
        return result.returncode == 0
    except Exception:
        return False

# Helper to apply Kubernetes YAML content from a string
def _apply_kube_yaml_from_string(yaml_content: str, description: str) -> None:
    try:
        # Create a temporary file to store the YAML content
        # The tempfile module is used for secure creation of temporary files
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".yaml") as tmp_yaml:
            tmp_yaml.write(yaml_content)
            tmp_yaml_path = tmp_yaml.name
       
        log(f"正在应用 Kubernetes YAML: {description}")
        # run_cmd is used to execute kubectl. sudo=False as kubectl typically doesn't require it.
        # check=True will raise an exception if kubectl apply fails.
        run_cmd(["kubectl", "apply", "-f", tmp_yaml_path], sudo=False, check=True)
        info(f"成功应用 YAML: {description}")
       
    except Exception as e:
        # Log the error. Depending on requirements, this might need to be more critical (e.g., sys.exit)
        error(f"应用 YAML 时出错 ({description}): {e}")
    finally:
        # Ensure the temporary file is deleted after use
        if 'tmp_yaml_path' in locals() and os.path.exists(tmp_yaml_path):
            os.remove(tmp_yaml_path)

# Helper to wait for a pod to be ready based on label selector and namespace
def _wait_for_pod_ready(namespace: str, label_selector: str, pod_name_hint: str, timeout: int = 300, check_interval: int = 10) -> bool:
    log(f"等待命名空间 '{namespace}' 中标签为 '{label_selector}' 的 {pod_name_hint} Pod 就绪...")
    start_time = time.time()
    # This JSONPath query attempts to mimic the behavior of the original shell script.
    # It checks the 'ready' status of the first container of the first pod found.
    jsonpath_query = '{.items[0].status.containerStatuses[0].ready}'
   
    while time.time() - start_time < timeout:
        cmd = [
            "kubectl", "get", "pods",
            "-n", namespace,
            "-l", label_selector,
            "-o", f"jsonpath={jsonpath_query}"
        ]
        # Execute kubectl command. check=False because the pod/path might not exist initially, leading to non-zero exit codes.
        # capture_output=True to get stdout/stderr for checking readiness.
        result = run_cmd(cmd, check=False, capture_output=True, sudo=False)
       
        # Check if command was successful and stdout is 'true'
        if result.returncode == 0 and result.stdout.strip() == "true":
            log(f"{pod_name_hint} Pod 已就绪。")
            return True
        else:
            # Log current status for debugging if verbose logging is on or if there's an error
            info(f"仍在等待 {pod_name_hint} Pod... 状态: stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}', code={result.returncode}")
            time.sleep(check_interval)
           
    warn(f"等待 {pod_name_hint} Pod 超时 ({timeout} 秒)。")
    return False

# Helper to wait for a CustomResourceDefinition (CRD) to be established
def _wait_for_crd_ready(crd_name: str, timeout: int = 120, check_interval: int = 5) -> bool:
    log(f"等待 CRD '{crd_name}' 建立...")
    start_time = time.time()
    # JSONPath query to check the 'Established' condition status of the CRD
    # A CRD is established when its Established condition is True
    jsonpath_query = '{.status.conditions[?(@.type=="Established")].status}'

    while time.time() - start_time < timeout:
        cmd = [
            "kubectl", "get", "crd", crd_name,
            "-o", f"jsonpath={jsonpath_query}"
        ]
        result = run_cmd(cmd, check=False, capture_output=True, sudo=False)

        if result.returncode == 0 and result.stdout.strip().lower() == "true":
            log(f"CRD '{crd_name}' 已建立。")
            return True
        else:
            info(f"仍在等待 CRD '{crd_name}' 建立... 状态: stdout='{result.stdout.strip()}', stderr='{result.stderr.strip()}', code={result.returncode}")
            time.sleep(check_interval)
    
    warn(f"等待 CRD '{crd_name}' 建立超时 ({timeout} 秒)。")
    return False

def install_cluster_suite() -> None:
    log("开始安装集群套件 (nginx-ingress, cert-manager, external-secrets, vault)...")

    # 1. Nginx-ingress installation
    log("阶段 1: 安装 nginx-ingress")
    run_cmd(["helm", "repo", "add", "nginx-stable", "https://kubernetes.github.io/ingress-nginx"], sudo=False, check=True)
    run_cmd(["helm", "repo", "update"], sudo=False, check=True)
    run_cmd(["helm", "upgrade", "--install", "nginx-ingress", "nginx-stable/ingress-nginx", 
             "--namespace", "kube-system", 
             "--set", "controller.config.ssl-redirect=false",
             "--wait"], sudo=False, check=True)
    log("已使用 --wait 标志启动 nginx-ingress Helm chart 安装。")
    # Fallback or more specific check if needed, Helm --wait can sometimes be insufficient for deep checks.
    if not _wait_for_pod_ready("kube-system", "app.kubernetes.io/name=ingress-nginx", "nginx-ingress-controller"):
        warn("Nginx Ingress 控制器未能通过自定义检查报告就绪。Helm 的 --wait 可能已先生效。谨慎操作。")

    # 2. Cert-manager installation
    log("阶段 2: 安装 cert-manager")
    cert_manager_yaml_url = "https://github.com/cert-manager/cert-manager/releases/download/v1.16.0/cert-manager.yaml"
    # Ensure cert-manager namespace exists if not created by the YAML, though standard YAMLs usually do.
    # run_cmd(["kubectl", "create", "namespace", "cert-manager"], check=False, sudo=False) # If needed
    run_cmd(["kubectl", "apply", "-f", cert_manager_yaml_url], sudo=False, check=True)
    log("已发出 cert-manager YAML 应用命令。")
    if not _wait_for_pod_ready("cert-manager", "app.kubernetes.io/instance=cert-manager", "cert-manager controller/webhook"): # Common labels for cert-manager v1.16
         warn("Cert-manager 未报告就绪。谨慎操作。")

    log("显示 kube-system 命名空间中的服务 (信息性)")
    run_cmd(["kubectl", "get", "services", "-n", "kube-system"], sudo=False, capture_output=False, check=False) 

    # 3. External-secrets installation
    log("阶段 3: 安装 external-secrets")
    run_cmd(["helm", "repo", "add", "external-secrets", "https://charts.external-secrets.io"], sudo=False, check=True)
    run_cmd(["helm", "repo", "update"], sudo=False, check=True)
    run_cmd(["helm", "upgrade", "--install", "external-secrets", "external-secrets/external-secrets", 
             "-n", "external-secrets", "--create-namespace",
             "--wait"], sudo=False, check=True)
    log("已使用 --wait 标志启动 external-secrets Helm chart 安装。")
    if not _wait_for_pod_ready("external-secrets", "app.kubernetes.io/name=external-secrets", "external-secrets controller"):
        warn("External-secrets 未能通过自定义检查报告就绪。谨慎操作。")

    # Ensure SecretStore CRD is established before trying to create SecretStore resources
    if not _wait_for_crd_ready("secretstores.external-secrets.io"):
        die("SecretStore CRD 未能及时建立，无法继续配置 Vault SecretStore。")

    log("显示 external-secrets 命名空间中的服务 (信息性)")
    run_cmd(["kubectl", "get", "services", "-n", "external-secrets"], sudo=False, capture_output=False, check=False)

    # 4. HashiCorp Vault (in dev mode) installation
    log("阶段 4: 安装 HashiCorp Vault (开发模式)")
    run_cmd(["helm", "repo", "add", "hashicorp", "https://helm.releases.hashicorp.com"], sudo=False, check=True)
    run_cmd(["helm", "repo", "update"], sudo=False, check=True)
    run_cmd(["helm", "upgrade", "--install", "vault", "hashicorp/vault", 
             "--set", "server.dev.enabled=true", 
             "--wait"], sudo=False, check=True)
    log("已使用 --wait 标志启动 Vault Helm chart 安装。")
    if not _wait_for_pod_ready("default", "app.kubernetes.io/name=vault", "vault server"):
        warn("Vault 未能通过自定义检查报告就绪。谨慎操作。")

    # 5. Configure Vault SecretStore for External Secrets
    log("阶段 5: 配置 Vault SecretStore 和令牌 Secret")
    # Note: Ensure the SecretStore and its referenced token are in namespaces accessible by external-secrets controller
    # And that Vault is accessible from external-secrets pods.
    vault_secret_store_yaml = """
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "http://vault.default.svc.cluster.local:8200"
      path: "scroll"
      version: "v2"
      auth:
        tokenSecretRef:
          name: vault-token
          key: token
---
apiVersion: v1
kind: Secret
metadata:
  name: vault-token
type: Opaque
stringData:
  token: "root"  # This is the default token in dev mode. Don't use in production!
"""
    _apply_kube_yaml_from_string(vault_secret_store_yaml, "Vault SecretStore 和令牌 Secret")

    # 6. Configure LetsEncrypt ClusterIssuer for Cert-Manager
    log("阶段 6: 配置 LetsEncrypt ClusterIssuer")
    letsencrypt_issuer_yaml = """
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: shu@unifra.io # IMPORTANT: Replace with a valid email address for Let's Encrypt registration
    privateKeySecretRef:
      # Secret resource that will be used to store the ACME account private key
      name: letsencrypt-prod-private-key
    solvers:
      - http01:
          ingress:
            class: nginx # Matches the ingress controller class installed earlier
"""
    _apply_kube_yaml_from_string(letsencrypt_issuer_yaml, "LetsEncrypt ClusterIssuer")

    log("✅ 集群套件安装过程完成。")

if __name__ == "__main__":
    main()
