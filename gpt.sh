#!/usr/bin/env bash
# k3d‑ipv6-bootstrap.sh — 自动化创建 / 删除 dual‑stack k3d 集群 + 宿主机 Nginx 反向代理（IPv6 Only 外网）
# 依赖：docker, k3d, nginx, ip6tables, sudo, (可选) netfilter-persistent, nc
#
# 用法示例：
#   ./k3d-ipv6-bootstrap.sh dogeos          # 创建集群 dogeos → *.dogeos.unifra.xyz
#   ./k3d-ipv6-bootstrap.sh dogeos --delete # 删除并清理

set -eu -o pipefail

command -v sudo >/dev/null || {
    echo "sudo is required" >&2
    exit 1
}

############################
# —— 可按需修改的全局常量 ——
############################
readonly DOCKER_BRIDGE_NAME="k3d-ipv6-net"
LOCAL_80=8000
LOCAL_443=44300
readonly SUBNET_PREFIX="fd00:beaf" # 私有 IPv6 前缀
readonly DOCKER_IPV4_SUBNET="172.28.0.0/16"
readonly DOCKER_IPV6_SUBNET="${SUBNET_PREFIX}::/64"
readonly DOCKER_IPV4_GATEWAY="172.28.0.1"
readonly DOCKER_IPV6_GATEWAY="${SUBNET_PREFIX}::1"

# NAT66 匹配范围 — /48 同时涵盖节点容器 /64 与 Pod /56
readonly NAT66_SRC_RANGE="${SUBNET_PREFIX}::/48"

############################
# —— 日志工具 ——
############################
log() { printf '\e[32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[33m[!]\e[0m %s\n' "$*"; }
die() {
    printf '\e[31m[×]\e[0m %s\n' "$*" >&2
    exit 1
}

[[ $# -lt 1 ]] && die "用法: $0 <cluster-name> [--delete|-d]"
CLUSTER="$1"
shift
DELETE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
    --delete | -d)
        DELETE=1
        shift
        ;;
    *) die "未知参数 $1" ;;
    esac
done
DOMAIN="${CLUSTER}.unifra.xyz" # 自动推导域名

############################
# —— 等待工具 ——
############################
wait_for_container() {
    local container="$1"
    local timeout="${2:-60}"
    local start=$(date +%s)
    until docker inspect "$container" &>/dev/null; do
        (($(date +%s) - start > timeout)) && return 1
        sleep 1
    done
    return 0
}

############################
# —— 预检查 & 防坑 ——
############################
check_host_sanity() {
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
}

############################
# —— 核心函数 ——
############################
enable_ipv6_forwarding() {
    log "启用宿主机 IPv6 转发..."
    sudo sysctl -qw net.ipv6.conf.all.forwarding=1
    sudo grep -q '^net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf ||
        echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf >/dev/null
}

create_docker_network() {
    if ! docker network inspect "$DOCKER_BRIDGE_NAME" >/dev/null 2>&1; then
        log "创建 Docker dual‑stack 网络 $DOCKER_BRIDGE_NAME..."
        docker network create "$DOCKER_BRIDGE_NAME" --driver bridge \
            --subnet "$DOCKER_IPV4_SUBNET" --gateway "$DOCKER_IPV4_GATEWAY" \
            --ipv6 --subnet "$DOCKER_IPV6_SUBNET" --gateway "$DOCKER_IPV6_GATEWAY"
    else
        log "Docker 网络 $DOCKER_BRIDGE_NAME 已存在"
    fi
}

setup_nat66() {
    log "配置 NAT66 (源 ${NAT66_SRC_RANGE})..."
    sudo ip6tables -t nat -F POSTROUTING || true
    sudo ip6tables -t nat -A POSTROUTING -s "$NAT66_SRC_RANGE" ! -o "$DOCKER_BRIDGE_NAME" -j MASQUERADE
    command -v netfilter-persistent &>/dev/null && sudo netfilter-persistent save || true
}

create_k3d_cluster() {
    log "创建 k3d 集群 $CLUSTER..."
    k3d cluster create "$CLUSTER" \
        --network "$DOCKER_BRIDGE_NAME" \
        --agents 1 \
        --port "127.0.0.1:${LOCAL_80}:80@loadbalancer" \
        --port "127.0.0.1:${LOCAL_443}:443@loadbalancer" \
        --k3s-arg "--cluster-cidr=10.42.0.0/16,${SUBNET_PREFIX}:42::/56@server:0" \
        --k3s-arg "--service-cidr=10.43.0.0/16,${SUBNET_PREFIX}:43::/108@server:0" \
        --k3s-arg "--disable=traefik@server:0" \
        --k3s-arg "--disable-network-policy@server:0" \
        --k3s-arg "--flannel-ipv6-masq@server:*" \
        --wait
}

append_conf() {
    local file="$1"
    shift
    sudo bash -c "cat >> '$file' <<'EOF'
$*
EOF"
}

add_nginx_blocks() {
    sudo tee /etc/nginx/conf.d/k3d-http-${CLUSTER}.conf >/dev/null <<EOF
map \$host \$backend_http {
    ~^.*\.${CLUSTER}\.unifra\.xyz\$  127.0.0.1:${LOCAL_80};
    default                          127.0.0.1:8080;
}

server {
    listen 80 reuseport;
    location / {
        proxy_pass http://\$backend_http;
        proxy_set_header Host \$host;
    }
}
EOF

    # 写 STREAM 片段
    sudo tee /etc/nginx/stream-conf.d/k3d-stream-${CLUSTER}.conf >/dev/null <<EOF
stream {
    map \$ssl_preread_server_name \$backend_https {
        ~^.*\.${CLUSTER}\.unifra\.xyz\$  127.0.0.1:${LOCAL_443};
        default                          127.0.0.1:4443;
    }

    server {
        listen [::]:443 reuseport;   # 仅 IPv6；如要双栈再加一行 listen 443;
        proxy_pass  \$backend_https;
        ssl_preread on;
    }
}
EOF

    reload_nginx
}

reload_nginx() {
    sudo nginx -t && { sudo systemctl reload nginx 2>/dev/null || sudo nginx -s reload; }
}

############################
# —— 主流程 ——
############################
check_host_sanity
enable_ipv6_forwarding
create_docker_network
setup_nat66

if [[ $DELETE -eq 1 ]]; then
    log "删除 k3d 集群 $CLUSTER (如存在)..."
    k3d cluster delete "$CLUSTER" || true

    sudo docker network rm k3d-ipv6-net
    log "✅ 已删除集群并清理 Nginx 段"
    exit 0
fi

if k3d cluster list | awk 'NR>1 {print $1}' | grep -qx "$CLUSTER"; then
    log "集群 $CLUSTER 已存在，删除"
    k3d cluster delete $CLUSTER
fi
create_k3d_cluster
add_nginx_blocks

docker exec k3d-${CLUSTER}-server-0 ip6tables -t nat -A POSTROUTING \
    -s fd00:beaf:42::/56 -o eth0 -j MASQUERADE
docker exec k3d-${CLUSTER}-agent-0 ip6tables -t nat -A POSTROUTING \
    -s fd00:beaf:42::/56 -o eth0 -j MASQUERADE

log "✅ 完成：集群 $CLUSTER 就绪，*.${DOMAIN} → k3d ingress"
