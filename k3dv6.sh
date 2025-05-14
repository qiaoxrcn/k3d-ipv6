#!/usr/bin/env bash

set -eu -o pipefail

################################
# —— 脚本初始检查 ——
################################
command -v sudo >/dev/null || {
    echo "sudo 命令不可用，请确保已安装" >&2
    exit 1
}

################################
# —— 可配置的全局常量 ——
################################
# 网络配置
readonly DOCKER_BRIDGE_NAME="k3d-ipv6-net"
readonly SUBNET_PREFIX="fd00:beaf"  # 私有 IPv6 前缀
readonly DOCKER_IPV4_SUBNET="172.28.0.0/16"
readonly DOCKER_IPV6_SUBNET="${SUBNET_PREFIX}::/64"
readonly DOCKER_IPV4_GATEWAY="172.28.0.1"
readonly DOCKER_IPV6_GATEWAY="${SUBNET_PREFIX}::1"
readonly NAT66_SRC_RANGE="${SUBNET_PREFIX}::/48"  # NAT66 匹配范围 — /48 同时涵盖节点容器 /64 与 Pod /56

# k3d集群相关配置
readonly DEFAULT_DOMAIN_SUFFIX="unifra.xyz"
readonly DEFAULT_AGENT_COUNT=1

# Nginx 相关配置
readonly NGINX_HTTP_CONF_DIR="/etc/nginx/conf.d"
readonly NGINX_STREAM_CONF_DIR="/etc/nginx/stream-conf.d"
readonly DEFAULT_HTTP_BACKEND="127.0.0.1:8080"
readonly DEFAULT_HTTPS_BACKEND="127.0.0.1:4443"

################################
# —— 日志工具函数 ——
################################
# 设置默认日志级别
VERBOSE=0

log() { printf '\e[32m[+]\e[0m %s\n' "$*"; }
info() { [[ $VERBOSE -eq 1 ]] && printf '\e[36m[i]\e[0m %s\n' "$*" || true; }
warn() { printf '\e[33m[!]\e[0m %s\n' "$*"; }
error() { printf '\e[31m[×]\e[0m %s\n' "$*" >&2; }
die() { error "$*"; exit 1; }

################################
# —— 工具函数 ——
################################
# 获取两个可用端口
get_two_free_ports() {
    local start_port=20000
    local end_port=60000
    local found_ports=()

    for ((port = start_port; port <= end_port; port++)); do
        # 检查 TCP 端口是否已被监听（支持 IPv4 和 IPv6）
        if ! ss -lnt | awk '{print $4}' | grep -qE "[:.]$port\$"; then
            found_ports+=("$port")
        fi

        if [ "${#found_ports[@]}" -ge 2 ]; then
            echo "${found_ports[0]} ${found_ports[1]}"
            return 0
        fi
    done

    error "无法在 $start_port-$end_port 范围内找到 2 个可用端口"
    return 1
}

# 等待容器可用
wait_for_container() {
    local container="$1"
    local timeout="${2:-60}"
    local start=$(date +%s)
    
    log "等待容器 $container 就绪..."
    until docker inspect "$container" &>/dev/null; do
        (($(date +%s) - start > timeout)) && {
            warn "等待容器 $container 超时 ($timeout 秒)"
            return 1
        }
        sleep 1
    done
    info "容器 $container 已就绪"
    return 0
}

# 显示帮助信息
show_help() {
    cat <<EOF
用法: $0 <cluster-name> [选项]

选项:
  -d, --delete           删除指定的集群及相关资源
  -h, --help             显示此帮助信息
  -v, --verbose          显示详细输出
  --domain-suffix=SUFFIX 设置域名后缀 (默认: ${DEFAULT_DOMAIN_SUFFIX})
  --agents=COUNT         设置 agent 节点数量 (默认: ${DEFAULT_AGENT_COUNT})

示例:
  $0 test               # 创建名为 'test' 的集群
  $0 test --delete      # 删除名为 'test' 的集群
  $0 dev --domain-suffix=local.dev  # 使用自定义域名后缀
EOF
}

################################
# —— 核心功能函数 ——
################################
# 检查主机环境并确保适当的设置
check_host_sanity() {
    log "检查主机环境..."
    
    # 1) IPv6 rp_filter 应关闭 (0)
    local rpf=$(sysctl -n net.ipv6.conf.all.rp_filter 2>/dev/null || echo 0)
    if [[ "$rpf" != 0 ]]; then
        warn "net.ipv6.conf.all.rp_filter=$rpf，会导致回包被丢，自动改为 0"
        sudo sysctl -qw net.ipv6.conf.all.rp_filter=0
        echo 'net.ipv6.conf.all.rp_filter=0' | sudo tee -a /etc/sysctl.conf >/dev/null || true
    fi

    # 2) ip6tables INPUT 应允许 ESTABLISHED,RELATED
    if ! sudo ip6tables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
        warn "在 ip6tables INPUT 链中插入 ESTABLISHED,RELATED 放行规则"
        sudo ip6tables -I INPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi
    
    info "主机环境检查完成"
}

# 启用 IPv6 转发
enable_ipv6_forwarding() {
    log "启用宿主机 IPv6 转发..."
    sudo sysctl -qw net.ipv6.conf.all.forwarding=1
    
    # 确保设置持久化
    if ! grep -q '^net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf; then
        echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf >/dev/null
        info "已将 IPv6 转发设置添加至 /etc/sysctl.conf"
    fi
}

# 创建 Docker 双栈网络
create_docker_network() {
    if ! docker network inspect "$DOCKER_BRIDGE_NAME" >/dev/null 2>&1; then
        log "创建 Docker dual-stack 网络: $DOCKER_BRIDGE_NAME"
        docker network create "$DOCKER_BRIDGE_NAME" --driver bridge \
            --subnet "$DOCKER_IPV4_SUBNET" --gateway "$DOCKER_IPV4_GATEWAY" \
            --ipv6 --subnet "$DOCKER_IPV6_SUBNET" --gateway "$DOCKER_IPV6_GATEWAY"
        info "已创建 Docker 网络"
    else
        log "Docker 网络 $DOCKER_BRIDGE_NAME 已存在，将继续使用"
    fi
}

# 设置 NAT66 规则
setup_nat66() {
    log "配置 NAT66 (源 ${NAT66_SRC_RANGE})..."
    
    # 检查 POSTROUTING 链是否存在
    if ! sudo ip6tables -t nat -L POSTROUTING &>/dev/null; then
        warn "NAT 表中不存在 POSTROUTING 链，将创建"
        sudo ip6tables -t nat -N POSTROUTING 2>/dev/null || true
    fi
    
    # 清理现有规则并添加新规则
    sudo ip6tables -t nat -F POSTROUTING || true
    sudo ip6tables -t nat -A POSTROUTING -s "$NAT66_SRC_RANGE" ! -o "$DOCKER_BRIDGE_NAME" -j MASQUERADE
    
    # 尝试保存规则 (如果 netfilter-persistent 可用)
    if command -v netfilter-persistent &>/dev/null; then
        info "使用 netfilter-persistent 保存 ip6tables 规则"
        sudo netfilter-persistent save
    else
        info "提示: 安装 netfilter-persistent 可持久化保存 ip6tables 规则"
    fi
}

# 创建 k3d 集群
create_k3d_cluster() {
    local cluster_name="$1"
    local agent_count="$2"
    local http_port="$3"
    local https_port="$4"
    
    log "创建 k3d 集群: $cluster_name (agents: $agent_count, HTTP: $http_port, HTTPS: $https_port)"
    
    k3d cluster create "$cluster_name" \
        --network "$DOCKER_BRIDGE_NAME" \
        --agents "$agent_count" \
        --port "127.0.0.1:${http_port}:80@loadbalancer" \
        --port "127.0.0.1:${https_port}:443@loadbalancer" \
        --k3s-arg "--cluster-cidr=10.42.0.0/16,${SUBNET_PREFIX}:42::/56@server:0" \
        --k3s-arg "--service-cidr=10.43.0.0/16,${SUBNET_PREFIX}:43::/108@server:0" \
        --k3s-arg "--disable=traefik@server:0" \
        --k3s-arg "--disable-network-policy@server:0" \
        --k3s-arg "--flannel-ipv6-masq@server:*" \
        --wait
    
    log "集群 $cluster_name 创建成功"
}

# 配置 Nginx 集群入口
configure_nginx_for_cluster() {
    local cluster_name="$1"
    local domain_suffix="$2"
    local http_port="$3"
    local https_port="$4"
    local full_domain="*.${cluster_name}.${domain_suffix}"
    local safe_map_var="${cluster_name//-/_}"  # 替换破折号为下划线，确保map变量名有效
    
    log "配置 Nginx 以代理到集群 $cluster_name"
    
    # 配置 HTTP 后端
    local http_conf_file="${NGINX_HTTP_CONF_DIR}/k3d-http-${cluster_name}.conf"
    sudo tee "$http_conf_file" >/dev/null <<EOF
map \$host \$backend_http_${safe_map_var} {
    ~^.*\.${cluster_name}\.${domain_suffix}\$  127.0.0.1:${http_port};
    default                                    ${DEFAULT_HTTP_BACKEND};
}

server {
    listen [::]:80 reuseport;
    location / {
        proxy_pass http://\$backend_http_${safe_map_var};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

    # 配置 HTTPS (SSL) 后端
    local stream_conf_file="${NGINX_STREAM_CONF_DIR}/k3d-stream-${cluster_name}.conf"
    sudo tee "$stream_conf_file" >/dev/null <<EOF
stream {
    map \$ssl_preread_server_name \$backend_https_${safe_map_var} {
        ~^.*\.${cluster_name}\.${domain_suffix}\$  127.0.0.1:${https_port};
        default                                    ${DEFAULT_HTTPS_BACKEND};
    }

    server {
        listen [::]:443 reuseport;   # 仅 IPv6；如要双栈再加一行 listen 443;
        proxy_pass  \$backend_https_${safe_map_var};
        ssl_preread on;
    }
}
EOF

    if [[ $VERBOSE -eq 1 ]]; then
        info "HTTP 配置文件 ($http_conf_file):"
        cat "$http_conf_file"
        
        info "Stream 配置文件 ($stream_conf_file):"
        cat "$stream_conf_file"
    fi
    
    reload_nginx
}

# 删除特定集群的 Nginx 配置
remove_nginx_config_for_cluster() {
    local cluster_name="$1"
    local http_conf="${NGINX_HTTP_CONF_DIR}/k3d-http-${cluster_name}.conf"
    local stream_conf="${NGINX_STREAM_CONF_DIR}/k3d-stream-${cluster_name}.conf"
    
    log "删除 Nginx 配置文件"
    
    # 删除 HTTP 配置文件
    if [[ -f "$http_conf" ]]; then
        sudo rm -f "$http_conf"
        info "已删除 HTTP 配置: $http_conf"
    fi
    
    # 删除 Stream 配置文件
    if [[ -f "$stream_conf" ]]; then
        sudo rm -f "$stream_conf"
        info "已删除 Stream 配置: $stream_conf"
    fi
    
    # 重新加载 Nginx 配置
    reload_nginx
}

# 重新加载 Nginx 配置
reload_nginx() {
    log "重新加载 Nginx 配置..."
    
    # 先测试配置有效性
    if ! sudo nginx -t &>/dev/null; then
        warn "Nginx 配置测试失败，详细信息:"
        sudo nginx -t
        return 1
    fi
    
    # 重新加载配置
    if command -v systemctl &>/dev/null && systemctl is-active --quiet nginx; then
        sudo systemctl reload nginx
    else
        sudo nginx -s reload
    fi
    
    info "Nginx 配置已重新加载"
    return 0
}

# 在 k3d 节点上配置网络
configure_k3d_node_networking() {
    local cluster_name="$1"
    local agent_count="$2"
    
    log "配置 k3d 节点网络..."
    
    # 配置服务器节点
    local server_container="k3d-${cluster_name}-server-0"
    wait_for_container "$server_container" 30 || warn "容器 $server_container 未就绪，可能影响网络配置"
    
    info "配置服务器节点 NAT: $server_container"
    docker exec "$server_container" ip6tables -t nat -A POSTROUTING \
        -s fd00:beaf:42::/56 -o eth0 -j MASQUERADE
    
    # 配置代理节点
    for ((i=0; i<agent_count; i++)); do
        local agent_container="k3d-${cluster_name}-agent-$i"
        wait_for_container "$agent_container" 30 || {
            warn "容器 $agent_container 未就绪，跳过网络配置"
            continue
        }
        
        info "配置代理节点 NAT: $agent_container"
        docker exec "$agent_container" ip6tables -t nat -A POSTROUTING \
            -s fd00:beaf:42::/56 -o eth0 -j MASQUERADE
    done
}

# 删除集群及相关资源
delete_cluster_resources() {
    local cluster_name="$1"
    
    log "删除 k3d 集群: $cluster_name"
    
    # 删除 k3d 集群（如果存在）
    if k3d cluster list 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$cluster_name"; then
        k3d cluster delete "$cluster_name"
        info "已删除集群: $cluster_name"
    else
        info "集群 $cluster_name 不存在，无需删除"
    fi
    
    # 删除集群的 Nginx 配置
    remove_nginx_config_for_cluster "$cluster_name"
    
    log "✅ 已成功删除集群 $cluster_name 及相关资源"
}

################################
# —— 参数解析 ——
################################
# 默认值
DELETE=0
DOMAIN_SUFFIX="$DEFAULT_DOMAIN_SUFFIX"
AGENT_COUNT="$DEFAULT_AGENT_COUNT"

# 确保至少有一个参数
[[ $# -lt 1 ]] && { show_help; die "错误: 未指定集群名称"; }

# 第一个参数必须是集群名称，不能以 - 开头
CLUSTER="$1"
[[ "$CLUSTER" == -* ]] && { show_help; die "错误: 集群名称不能以 '-' 开头"; }
[[ -z "$CLUSTER" ]] && { show_help; die "错误: 集群名称不能为空"; }
shift

# 解析其他选项
while [[ $# -gt 0 ]]; do
    case "$1" in
        --delete|-d)
            DELETE=1
            shift
            ;;
        --help|-h)
            show_help
            exit 0
            ;;
        --verbose|-v)
            VERBOSE=1
            shift
            ;;
        --domain-suffix=*)
            DOMAIN_SUFFIX="${1#*=}"
            shift
            ;;
        --agents=*)
            AGENT_COUNT="${1#*=}"
            shift
            ;;
        *)
            die "未知参数: $1 (使用 --help 获取帮助)"
            ;;
    esac
done

# 生成完整域名
DOMAIN="${CLUSTER}.${DOMAIN_SUFFIX}"

################################
# —— 主流程 ——
################################
log "开始处理集群: $CLUSTER (域名: $DOMAIN)"

# 基础环境检查和设置
check_host_sanity
enable_ipv6_forwarding
create_docker_network
setup_nat66

# 如果是删除操作
if [[ $DELETE -eq 1 ]]; then
    delete_cluster_resources "$CLUSTER"
    exit 0
fi

# 获取可用端口
if ! read HTTP_PORT HTTPS_PORT < <(get_two_free_ports); then
    die "无法获取可用端口，脚本终止"
fi
info "使用端口: HTTP=$HTTP_PORT, HTTPS=$HTTPS_PORT"

# 如果同名集群已存在，先删除
if k3d cluster list 2>/dev/null | awk 'NR>1 {print $1}' | grep -qx "$CLUSTER"; then
    log "集群 $CLUSTER 已存在，先删除"
    k3d cluster delete "$CLUSTER"
fi

# 创建新集群并配置
create_k3d_cluster "$CLUSTER" "$AGENT_COUNT" "$HTTP_PORT" "$HTTPS_PORT"
configure_nginx_for_cluster "$CLUSTER" "$DOMAIN_SUFFIX" "$HTTP_PORT" "$HTTPS_PORT"
configure_k3d_node_networking "$CLUSTER" "$AGENT_COUNT"

log "✅ 完成：集群 $CLUSTER 就绪，*.${DOMAIN} → k3d ingress"
info "  - HTTP 端口: $HTTP_PORT"
info "  - HTTPS 端口: $HTTPS_PORT"
