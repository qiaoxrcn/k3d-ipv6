#!/usr/bin/env bash
echo "Starting nginx-ingress installation"
helm repo add nginx-stable https://kubernetes.github.io/ingress-nginx
helm repo update
helm install nginx-ingress nginx-stable/ingress-nginx --namespace kube-system --set controller.config.ssl-redirect=false
echo "nginx-ingress installation completed"

# Wait for nginx-ingress controller pod to be ready
while true; do
  READY=$(kubectl get pods -n kube-system -l app.kubernetes.io/name=ingress-nginx -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null)
  if [ "$READY" = "true" ]; then
    echo "nginx-ingress pod is ready"
    break
  else
    echo "Waiting for nginx-ingress pod to be ready..."
    sleep 3
  fi
done

echo "Starting cert-manager installation"
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.16.0/cert-manager.yaml
echo "cert-manager installation completed"

# Wait for cert-manager pod to be ready
while true; do
  READY=$(kubectl get pods -n cert-manager -l app=cert-manager -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null)
  if [ "$READY" = "true" ]; then
    echo "cert-manager pod is ready"
    break
  else
    echo "Waiting for cert-manager pod to be ready..."
    sleep 3
  fi
done

echo "Checking load balancer"
kubectl get services -n kube-system

echo "Starting external-secrets installation"
helm repo add external-secrets https://charts.external-secrets.io
helm repo update
helm install external-secrets external-secrets/external-secrets -n external-secrets --create-namespace
echo "external-secrets installation completed"

# Wait for external-secrets pod to be ready
while true; do
  READY=$(kubectl get pods -n external-secrets -l app.kubernetes.io/name=external-secrets -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null)
  if [ "$READY" = "true" ]; then
    echo "external-secrets pod is ready"
    break
  else
    echo "Waiting for external-secrets pod to be ready..."
    sleep 3
  fi
done

kubectl get services -n external-secrets


helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update
helm install vault hashicorp/vault --set "server.dev.enabled=true"
# Wait for vault pod to be ready
while true; do
  READY=$(kubectl get pods -n default -l app.kubernetes.io/name=vault -o jsonpath='{.items[0].status.containerStatuses[0].ready}' 2>/dev/null)
  if [ "$READY" = "true" ]; then
    echo "vault pod is ready"
    break
  else
    echo "Waiting for vault pod to be ready..."
    sleep 3
  fi
done

cat <<EOF | kubectl apply -f -
apiVersion: external-secrets.io/v1beta1
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
EOF


cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: shu@unifra.io
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
EOF
