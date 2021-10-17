## install cert-manager

kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.4/cert-manager.yaml

kubectl create ns demo

## self-signed CA
kubectl apply -f samples/issuer-selfsigned.yaml



