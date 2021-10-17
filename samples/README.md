## install cert-manager

kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.4/cert-manager.yaml

kubectl create ns demo

## self-signed CA

kubectl apply -f samples/self-signed/issuer-selfsigned.yaml
kubectl apply -f samples/self-signed/cert-selfsigned.yaml

## Configure NGINX SSL

- https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-nginx-on-centos-7
- https://smallstep.com/hello-mtls/doc/server/nginx
- https://nginx.org/en/docs/http/configuring_https_servers.html#chains
- https://www.cyberciti.biz/faq/configure-nginx-to-use-only-tls-1-2-and-1-3/
- https://www.techrepublic.com/article/how-to-enable-ssl-on-nginx/
