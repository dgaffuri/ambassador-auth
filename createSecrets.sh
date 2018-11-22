kubectl delete secret oidc-config
kubectl create secret generic oidc-config --from-file=oidc-config.json 
