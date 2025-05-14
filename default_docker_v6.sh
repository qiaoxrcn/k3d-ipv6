#!/bin/bash
# 自动配置 Docker 的 IPv6 支持
# 依赖：docker, k3d, nginx, ip6tables, sudo, (可选) netfilter-persistent, nc
#
# 用法示例：
#   ./default_docker_v6.sh
#
# 1. 修改 /etc/docker/daemon.json 启用 IPv6

config_docker_v6() {
    cat <<EOF | sudo tee /etc/docker/daemon.json
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00:beaf:1::/64"
}
EOF

    sudo systemctl restart docker
}

# config_docker_v6

# 2. 给 docker0 加 IPv6 地址
sudo ip -6 addr add fd00:beaf:1::1/64 dev docker0

# 3. 启用 IPv6 转发
sudo sysctl -w net.ipv6.conf.all.forwarding=1
echo 'net.ipv6.conf.all.forwarding=1' | sudo tee -a /etc/sysctl.conf

# 4. 添加 NAT66
sudo ip6tables -t nat -A POSTROUTING \
    -s fd00:beaf:1::/64 ! -o docker0 -j MASQUERADE

# 5. 持久化 NAT 设置
sudo apt install -y netfilter-persistent
sudo netfilter-persistent save
# 6. 测试 容器能访问外网

echo "正在测试容器的IPv6外网连接..."

# 创建一个临时容器，测试IPv6连接
docker run --rm alpine sh -c "apk add --no-cache curl && \
echo '测试IPv6连接到ipv6.google.com:' && \
curl -6 -s -m 5 -o /dev/null -w '状态码: %{http_code}\n' https://ipv6.google.com || \
echo '无法连接到ipv6.google.com' && \
echo '测试IPv6连接到ipv6.baidu.com:' && \
curl -6 -s -m 5 -o /dev/null -w '状态码: %{http_code}\n' https://ipv6.baidu.com || \
echo '无法连接到ipv6.baidu.com'"

echo "IPv6连接测试完成。"

# 7. 测试容器访问宿主机公网IPv6

echo "测试容器访问宿主机公网IPv6..."

# 获取宿主机公网IPv6地址
HOST_IPV6=$(ip -6 addr show scope global | grep -v fe80 | grep -oP '(?<=inet6\s)[0-9a-f:]+')

if [ -z "$HOST_IPV6" ]; then
    echo "未检测到宿主机公网IPv6地址，测试失败"
    exit 1
fi

echo "宿主机公网IPv6地址: $HOST_IPV6"

# 在宿主机上临时启动一个HTTP服务
PORT=80
echo "在宿主机IPv6地址上启动临时HTTP服务，端口: $PORT"

# 从容器内测试连接宿主机
echo "从容器内测试连接宿主机IPv6地址..."
docker run --rm alpine sh -c "apk add --no-cache curl && \
echo '测试连接宿主机IPv6地址:' && \
curl -6 -s -m 10 http://[$HOST_IPV6]:$PORT || \
echo '无法连接到宿主机IPv6地址'"

# 清理

echo "IPv6宿主机连接测试完成。"
