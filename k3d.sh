#!/usr/bin/env bash
# k3d‑ipv6‑bootstrap.sh — 自动化创建 dual‑stack k3d 集群 + 宿主机 Nginx 反向代理（IPv6 Only 外网）
# 依赖：docker, k3d, nginx, ip6tables, (可选) netfilter-persistent
#
# 用法示例：
#   sudo ./k3d-ipv6-bootstrap.sh --cluster dogeos   # → dogeos.unifra.xyz
#   sudo ./k3d-ipv6-bootstrap.sh --cluster scroll   # → scroll.unifra.xyz

set -eu -o pipefail

# Global variable for the temporary kubeconfig file
CLUSTER_KUBECONFIG_FILE=""
# Cleanup trap for the temporary kubeconfig file
trap 'rm -f "$CLUSTER_KUBECONFIG_FILE"' EXIT HUP INT QUIT TERM

############################
# —— 解析参数 ——
############################
CLUSTER=$1

############################
# —— 可按需修改的全局常量 ——
############################
readonly DOCKER_BRIDGE_NAME="k3d-ipv6-net"

readonly SUBNET_PREFIX="fd00:beaf"                # 私有 IPv6 前缀，可统一调整
readonly DOCKER_IPV4_SUBNET="172.28.0.0/16"
readonly DOCKER_IPV6_SUBNET="${SUBNET_PREFIX}::/64"
readonly DOCKER_IPV4_GATEWAY="172.28.0.1"
readonly DOCKER_IPV6_GATEWAY="${SUBNET_PREFIX}::1"

readonly NGINX_STREAM_CONF="/etc/nginx/conf.d/k3d-stream.conf"
readonly NGINX_HTTP_CONF="/etc/nginx/conf.d/k3d-http.conf"

############################
# —— 日志工具 ——
############################
log()  { printf '\e[32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[33m[!N!M]\e[0m %s\n' "$*"; } # Escaped !
die()  { printf '\e[31m[×]\e[0m %s\n' "$*" >&2; exit 1; }

############################
# —— 等待工具 ——
############################
wait_for_resource() {
  local resource_description="$1" # Changed from context to a description
  local resource_type="$2"
  local namespace="$3"
  local selector="$4"
  local timeout="${5:-120s}"
  
  log "等待资源就绪: $resource_description ($resource_type $selector in $namespace)"
  if [[ -z "$CLUSTER_KUBECONFIG_FILE" ]]; then
    die "CLUSTER_KUBECONFIG_FILE is not set. Cannot run kubectl."
  fi
  kubectl --kubeconfig="$CLUSTER_KUBECONFIG_FILE" wait --namespace "$namespace" \
    --for=condition=Ready "$resource_type" \
    --selector="$selector" \
    --timeout="$timeout" || warn "等待资源 $resource_description 超时，继续执行"
}

wait_for_container() {
  local container="$1"
  local timeout="${2:-60}"
  
  log "等待容器就绪: $container"
  local start_time=$(date +%s)
  
  while ! sudo docker inspect "$container" &>/dev/null; do
    local current_time=$(date +%s)
    local elapsed=$((current_time - start_time))
    
    if [[ $elapsed -gt $timeout ]]; then
      warn "等待容器 $container 超时($elapsed秒)"
      return 1
    fi
    
    log "等待容器 $container 就绪中...(${elapsed}/${timeout}秒)"
    sleep 1
  done
  
  # 再等待2秒让容器内服务启动
  sleep 2
  log "容器 $container 已就绪"
  return 0
}

wait_until() {
  local description="$1"
  local command_to_eval="$2" # Renamed for clarity as it's passed to eval
  local timeout="${3:-60}"
  
  log "等待$description..."
  local start_time=$(date +%s)
  # Ensure CLUSTER_KUBECONFIG_FILE is available if command_to_eval uses kubectl
  # This is a general check; specific commands will need to incorporate it.
  if [[ "$command_to_eval" == *"kubectl"* && -z "$CLUSTER_KUBECONFIG_FILE" ]]; then
      warn "CLUSTER_KUBECONFIG_FILE is not set for kubectl command in wait_until. Command: $command_to_eval"
      # Depending on strictness, could 'die' here. For now, warning.
  fi

  until eval "$command_to_eval"; do # command_to_eval should now correctly use $CLUSTER_KUBECONFIG_FILE if needed
    local current_time=$(date +%s)
    local elapsed=$((current_time - start_time))
    
    if [[ $elapsed -gt $timeout ]]; then
      warn "等待$description超时($elapsed秒)"
      return 1
    fi
    
    log "等待$description中...(${elapsed}/${timeout}秒)"
    sleep 2
  done
  log "$description已就绪"
  return 0
}

# ✨ 自动推导域名
DOMAIN="${CLUSTER}.unifra.xyz"

############################
# —— 0. 检查依赖和权限 ——
############################
check_dependencies_and_permissions() {
  # 检查核心命令
  local core_cmds=("docker" "ip6tables" "nginx" "sysctl" "kubectl")
  for cmd in "${core_cmds[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || die "依赖命令 '$cmd' 未找到，请安装。"
  done

}

############################
# —— 1. 启用 IPv6 转发 ——
############################
enable_ipv6_forwarding() {
  log "启用宿主机 IPv6 转发..."
  sudo sysctl -qw net.ipv6.conf.all.forwarding=1
  grep -q '^net.ipv6.conf.all.forwarding=1' /etc/sysctl.conf || \
    echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf > /dev/null
}

############################
# —— 2. 创建共享 Docker 网络 ——
############################
create_docker_network() {
  if ! sudo docker network inspect "$DOCKER_BRIDGE_NAME" >/dev/null 2>&1; then
    log "创建 Docker dual‑stack 网络 $DOCKER_BRIDGE_NAME..."
    sudo docker network create "$DOCKER_BRIDGE_NAME" \
      --driver bridge \
      --subnet "$DOCKER_IPV4_SUBNET" --gateway "$DOCKER_IPV4_GATEWAY" \
      --ipv6 --subnet "$DOCKER_IPV6_SUBNET" --gateway "$DOCKER_IPV6_GATEWAY"
  else
    log "Docker 网络 $DOCKER_BRIDGE_NAME 已存在，跳过"
  fi
}

############################
# —— 3. 设置 / 刷新 NAT66 ——
############################
setup_nat66() {
  log "配置 NAT66..."
  sudo ip6tables -t nat -F POSTROUTING || true
  sudo ip6tables -t nat -A POSTROUTING -s "$DOCKER_IPV6_SUBNET" ! -o "$DOCKER_BRIDGE_NAME" -j MASQUERADE
  if command -v netfilter-persistent >/dev/null; then
    sudo netfilter-persistent save
  else
    warn "未检测到 netfilter‑persistent，重启后 NAT66 规则可能丢失"
  fi
}

############################
# —— 4. 创建或检查 k3d 集群 ——
############################
create_k3d_cluster() {
  log "创建 k3d 集群 $CLUSTER..."
  k3d cluster create "$CLUSTER" \
    --network "$DOCKER_BRIDGE_NAME" \
    --agents 1 \
    --k3s-arg "--cluster-cidr=10.42.0.0/16,${SUBNET_PREFIX}:42::/56@server:0" \
    --k3s-arg "--service-cidr=10.43.0.0/16,${SUBNET_PREFIX}:43::/108@server:0" \
    --k3s-arg "--disable=traefik@server:0" \
    --k3s-arg "--disable-network-policy@server:0" \
    --wait
    
  log "获取集群 $CLUSTER 的 kubeconfig..."
  CLUSTER_KUBECONFIG_FILE=$(mktemp)
  if ! k3d kubeconfig get "$CLUSTER" > "$CLUSTER_KUBECONFIG_FILE"; then
    die "无法获取集群 $CLUSTER 的 kubeconfig."
  fi
  log "Kubeconfig 已保存到 $CLUSTER_KUBECONFIG_FILE"

  # 等待k3d服务器节点就绪
  local server_container="k3d-${CLUSTER}-server-0"
  wait_for_container "$server_container" 30
  
  # 等待节点Ready状态
  log "等待Kubernetes节点就绪..."
  local k8s_node_ready_command="kubectl --kubeconfig="$CLUSTER_KUBECONFIG_FILE" get nodes -o jsonpath='{.items[0].status.conditions[?(@.type==\"Ready\")].status}' | grep -q True"
  wait_until "k3d节点就绪" "$k8s_node_ready_command" 60
  
  # 验证IPv6功能
  log "验证集群IPv6支持..."
  if kubectl --kubeconfig="$CLUSTER_KUBECONFIG_FILE" get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}' | grep -q ":"; then
    log "集群节点具有IPv6地址"
  else
    warn "集群节点没有IPv6地址，可能影响双栈功能"
  fi
  
  # 显示集群信息
  kubectl --kubeconfig="$CLUSTER_KUBECONFIG_FILE" get nodes -o wide
}

############################
# —— 5. 生成 / 更新 Nginx 配置 ——
############################
write_nginx_config() {
  log "等待 k3d 集群 $CLUSTER 服务就绪..."
  
  local lb_container="k3d-${CLUSTER}-serverlb"
  
  # 等待DNS服务就绪，确保k8s集群基本功能可用
  # The first argument to wait_for_resource is now a description.
  wait_for_resource "kube-dns" pod kube-system "k8s-app=kube-dns" "180s" # Increased timeout for DNS
  
  # 等待负载均衡器容器就绪
  wait_for_container "$lb_container" 30
  
  # 获取IP地址
  local ip4 ip6
  ip4=$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$lb_container")
  ip6=$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}' "$lb_container")

  [[ -z $ip4 && -z $ip6 ]] && die "无法获取 $lb_container 的 IP"
  
  # 确保IPv6地址可连接
  if [[ -n "$ip6" ]]; then
    if ! wait_until "负载均衡器IPv6($ip6)可访问" "ping -c1 -W1 $ip6 >/dev/null 2>&1" 10; then
      warn "IPv6 $ip6 不可访问，但仍尝试配置"
    fi
  fi

  log "写入 Nginx 配置..."

  # 确保 conf 文件存在
  sudo touch "$NGINX_STREAM_CONF" "$NGINX_HTTP_CONF"

  # STREAM 443 (SNI 透传)
  if ! grep -q "### $CLUSTER ###" "$NGINX_STREAM_CONF"; then
    local stream_config_content=""
    stream_config_content=$(cat <<EOF
### $CLUSTER ###
map \$ssl_preread_server_name \$backend_$CLUSTER {
    ~^.*\\.${DOMAIN}\$   [\$ip6]:443;
    ~^${DOMAIN}\$        [\$ip6]:443;
}
server {
    listen [::]:443 reuseport;
    proxy_pass \$backend_$CLUSTER;
    ssl_preread on;
}
EOF
)
    echo "$stream_config_content" | sudo tee -a "$NGINX_STREAM_CONF" > /dev/null
  fi

  # HTTP 80 (Host 头转发)
  if ! grep -q "### $CLUSTER ###" "$NGINX_HTTP_CONF"; then
    local http_config_content=""
    http_config_content=$(cat <<EOF
### $CLUSTER ###
upstream http_$CLUSTER { server [\$ip6]:80; }

server {
    listen [::]:80 reuseport;
    server_name *.${DOMAIN} ${DOMAIN};
    location / {
        proxy_set_header Host \$host;
        proxy_pass http://http_$CLUSTER;
    }
}
EOF
)
    echo "$http_config_content" | sudo tee -a "$NGINX_HTTP_CONF" > /dev/null
  fi

  log "测试并重载Nginx配置..."
  sudo nginx -t && sudo systemctl reload nginx
  log "Nginx配置已更新"
}

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
# —— 主流程 ——
############################
check_dependencies_and_permissions
enable_ipv6_forwarding

# Attempt to remove cluster and network, warn on failure but continue
log "尝试删除旧的 k3d 集群 $CLUSTER..."
k3d cluster rm "$CLUSTER" || warn "删除集群 $CLUSTER 失败，可能不存在或删除时出错。"

log "尝试删除旧的 docker 网络 $DOCKER_BRIDGE_NAME..."
sudo docker network rm "$DOCKER_BRIDGE_NAME" || warn "删除网络 $DOCKER_BRIDGE_NAME 失败，可能不存在或仍在使用。"

check_host_sanity
create_docker_network
setup_nat66
create_k3d_cluster # This function now sets CLUSTER_KUBECONFIG_FILE
write_nginx_config

log "✅ 完成：集群 $CLUSTER 已就绪，外部域名 *.${DOMAIN} → k3d ingress。"
log "集群 kubeconfig 临时存储在: $CLUSTER_KUBECONFIG_FILE (脚本退出时会自动删除)"
log "您可以通过以下命令（或类似命令，替换 kubectl 为使用此 kubeconfig）访问集群:"
log "  kubectl --kubeconfig="$CLUSTER_KUBECONFIG_FILE" get nodes"
log "  kubectl --kubeconfig="$CLUSTER_KUBECONFIG_FILE" ..."

# Note: CLUSTER_KUBECONFIG_FILE will be cleaned up by the trap
