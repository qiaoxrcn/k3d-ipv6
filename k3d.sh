#!/bin/bash

# ==============================================================================
# K3d 集群基础设施自动化设置脚本 (增强版)
#
# 功能:
# 1. 创建一个暴露 80/443 端口的 K3d 集群。
# 2. 安装 Nginx Ingress Controller。
# 3. 安装 Cert-Manager 用于自动化 TLS 证书。
# 4. 配置 LetsEncrypt ClusterIssuer。
# 5. 安装 External Secrets Operator。
# 6. 安装 HashiCorp Vault (开发模式)。
# ==============================================================================

# --- 可配置变量 (请根据您的实际情况修改) ---
CLUSTER_NAME="c1"
K3D_VOLUME_DIR="$HOME/k3d-storage/${CLUSTER_NAME}"
DOGECOIN_DATA_DIR="$K3D_VOLUME_DIR/dogecoin-data"

LETSENCRYPT_EMAIL="shu@unifra.io"
# --- END 可配置变量 ---


# --- 脚本辅助功能 ---
COL_GREEN="\033[32m"
COL_YELLOW="\033[33m"
COL_RED="\033[31m"
COL_BLUE="\033[34m"
COL_RESET="\033[0m"

info() {
    echo -e "${COL_BLUE}[INFO]${COL_RESET} $1"
}

success() {
    echo -e "${COL_GREEN}[SUCCESS]${COL_RESET} $1"
}

warn() {
    echo -e "${COL_YELLOW}[WARNING]${COL_RESET} $1"
}

error() {
    echo -e "${COL_RED}[ERROR]${COL_RESET} $1"
}

check_deps() {
    info "正在检查依赖工具: k3d, kubectl, helm..."
    for cmd in k3d kubectl helm; do
        if ! command -v "$cmd" &> /dev/null; then
            error "命令 '$cmd' 未找到。请先安装它再运行此脚本。"
            exit 1
        fi
    done
    success "所有依赖工具都已安装。"
}

# --- 核心功能 ---

# 步骤 1: 创建 K3d 集群
step1_create_cluster() {
    info "--- 步骤 1: 创建 K3d 集群 ---"
    if k3d cluster get "$CLUSTER_NAME" &> /dev/null; then
        warn "集群 '$CLUSTER_NAME' 已存在，跳过创建步骤。"
    else
        info "正在创建名为 '$CLUSTER_NAME' 的 K3d 集群..."
        mkdir -p "$DOGECOIN_DATA_DIR" 
        k3d cluster create "$CLUSTER_NAME" \
            --agents 0 \
            --port '80:80@loadbalancer' \
            --port '443:443@loadbalancer' \
            --k3s-arg "--disable=traefik@server:*" \
            --volume "${DOGECOIN_DATA_DIR}:/data/dogecoin"

        if [ $? -eq 0 ]; then
            success "集群 '$CLUSTER_NAME' 创建成功。"
        else
            error "集群 '$CLUSTER_NAME' 创建失败。"
            exit 1
        fi
    fi
}

# 步骤 2: 安装 Nginx Ingress Controller
step2_install_nginx_ingress() {
    info "--- 步骤 2: 安装 Nginx Ingress Controller ---"
    helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx &>/dev/null
    helm repo update &>/dev/null
    
    if helm status ingress-nginx -n ingress-nginx &> /dev/null; then
        warn "Nginx Ingress Controller 已安装，跳过。"
    else
        info "正在通过 Helm 安装 Nginx Ingress Controller..."
        helm install ingress-nginx ingress-nginx/ingress-nginx \
          --namespace ingress-nginx \
          --create-namespace \
          --wait

        if [ $? -eq 0 ]; then
            success "Nginx Ingress Controller 安装成功。"
        else
            error "Nginx Ingress Controller 安装失败。"
            exit 1
        fi
    fi
}

# 步骤 3: 安装 Cert-Manager
step3_install_cert_manager() {
    info "--- 步骤 3: 安装 Cert-Manager ---"
    helm repo add jetstack https://charts.jetstack.io &>/dev/null
    helm repo update &>/dev/null

    if helm status cert-manager -n cert-manager &> /dev/null; then
        warn "Cert-Manager 已安装，跳过。"
    else
        info "正在通过 Helm 安装 Cert-Manager..."
        helm install cert-manager jetstack/cert-manager \
          --namespace cert-manager \
          --create-namespace \
          --version v1.15.1 \
          --set installCRDs=true \
          --wait
        
        if [ $? -eq 0 ]; then
            success "Cert-Manager 安装成功。"
        else
            error "Cert-Manager 安装失败。"
            exit 1
        fi
    fi
}

# 步骤 4: 配置 LetsEncrypt ClusterIssuer
step4_configure_letsencrypt_issuer() {
    info "--- 步骤 4: 配置 LetsEncrypt 证书签发者 (ClusterIssuer) ---"
    info "等待 Cert-Manager Webhook 可用..."
    kubectl wait --for=condition=Available deployment/cert-manager-webhook -n cert-manager --timeout=300s

    info "正在创建 LetsEncrypt Production ClusterIssuer..."
    kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: ${LETSENCRYPT_EMAIL}
    privateKeySecretRef:
      name: letsencrypt-prod-private-key
    solvers:
      - http01:
          ingress:
            class: nginx
EOF

    if [ $? -eq 0 ]; then
        success "LetsEncrypt Production ClusterIssuer 创建成功。"
    else
        error "LetsEncrypt Production ClusterIssuer 创建失败。"
        exit 1
    fi
}

# 步骤 5: 安装 External Secrets Operator
step5_install_external_secrets() {
    info "--- 步骤 5: 安装 External Secrets Operator ---"
    helm repo add external-secrets https://charts.external-secrets.io
    helm repo update
    helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace
}

# 步骤 6: 安装 HashiCorp Vault
step6_install_vault() {
    info "--- 步骤 6: 安装 HashiCorp Vault ---"
    helm repo add hashicorp https://helm.releases.hashicorp.com
    helm repo update
    helm install vault hashicorp/vault --set "server.dev.enabled=true"
}

step7_install_pv() {
    info "--- 步骤 7: 安装 PV ---"
    kubectl apply -f - <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: dogecoin-manual-pv
spec:
  capacity:
    storage: 100Gi # 给一个比PVC请求大的容量
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  # 使用一个专门的名字，确保只有对应的PVC能绑定
  storageClassName: manual-dogecoin 
  hostPath:
    path: /data/dogecoin
EOF

    kubectl apply -f - <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: celestia-manual-pv
spec:
  capacity:
    storage: 300Gi # 给一个比PVC请求大的容量
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: manual-celestia
  hostPath:
    path: /data/celestia
EOF
}

step8_install_secret_store() {
    info "--- 步骤 8: 安装 Secret Store ---"
    kubectl apply -f ./vault-secret-store.yaml
}
# --- 主函数 ---
main() {
    check_deps
    step1_create_cluster
    step2_install_nginx_ingress
    step3_install_cert_manager
    step4_configure_letsencrypt_issuer
    step5_install_external_secrets
    step6_install_vault
    step7_install_pv
    step8_install_secret_store

    echo
    echo -e "${COL_GREEN}================================================================${COL_RESET}"
    echo -e "${COL_GREEN} ✅ 基础设施设置完成！(包括 Nginx, Cert-Manager, External Secrets, Vault) ${COL_RESET}"
    echo -e "${COL_GREEN}================================================================${COL_RESET}"
    echo
    info "接下来，你需要手动完成 Cloudflare 的 DNS 配置。"
    echo
    info "Vault (开发模式) 的默认 Root Token 是 'root'。你可以通过以下命令进入 Vault Pod 进行操作:"
    echo -e "${COL_YELLOW}kubectl exec -it vault-0 -n default -- vault status${COL_RESET}"
    echo -e "${COL_YELLOW}kubectl exec -it vault-0 -n default -- /bin/sh${COL_RESET}"

}

# --- 脚本入口 ---
main