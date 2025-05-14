minikube start --driver=docker --network-plugin=cni --cni=calico

minikube addons enable ingress

minikube addons enable metrics-server

minikube addons enable dashboard