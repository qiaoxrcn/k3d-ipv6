# 1. 确保桥接口上有 ULA 地址
sudo ip addr add fd00:beaf::1/64 dev k3d-ipv6-net  # 如果 inspect 里本来就有可省略
sudo sysctl -w net.ipv6.conf.k3d-ipv6-net.accept_ra=2   # 让内核为该口响应 NDP

# 2. 允许 Pod↔Host 直接通信 & 转发
sudo ip6tables -I INPUT   -i k3d-ipv6-net -p icmpv6 -j ACCEPT
sudo ip6tables -I INPUT   -i k3d-ipv6-net -p tcp -m state --state NEW -j ACCEPT
sudo ip6tables -I FORWARD -i k3d-ipv6-net               -j ACCEPT

# 3. NAT66（Pod 出去访问公网时才需要）
sudo ip6tables -t nat -F POSTROUTING
sudo ip6tables -t nat -A POSTROUTING \
  -s fd00:beaf::/48 -o wlo1 -j MASQUERADE

# 4. 持久化
sudo netfilter-persistent save
