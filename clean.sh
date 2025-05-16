ns=default
helm list -n $ns | tail -n +2 | awk '{print $1}' | grep -v "vault" | xargs -I{} helm delete -n $ns {}
kubectl delete pvc -n $ns --all
bash /home/qxr/github/dogeos/tools/resetblockscoutdb.sh
