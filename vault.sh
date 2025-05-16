helm install vault hashicorp/vault --set "server.dev.enabled=true" --namespace default
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