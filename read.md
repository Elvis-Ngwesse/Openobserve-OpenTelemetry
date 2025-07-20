# Jaeger-OpenTelemetry

# 📦 Project Setup
✅ Create Virtual Environment

python3 -m venv venv
source venv/bin/activate
deactivate


# ▶️ Build and Start the Stack
docker-compose build --no-cache
docker-compose up -d

# 🖥️ Access Services in Browser
Jaeger UI: http://localhost:16686/
CyberPulse UI: http://localhost:8090/
Username: admin
Password: adminpass


# 🌍 Build Multi platform Image

docker buildx create --use

COMMIT_SHA=$(git rev-parse --short HEAD) && \
docker buildx build --platform linux/amd64,linux/arm64 \
-t dockerelvis/CyberPulse-app:latest \
-t dockerelvis/CyberPulse-app:$COMMIT_SHA \
-f Dockerfile \
--push .
echo $COMMIT_SHA

# 🧪 Start Minikube (3 Nodes)
minikube start --nodes 3 --cpus=2 --memory=4g
kubectl get nodes

# ⚙️ Access Nodes
minikube ssh --node=minikube
minikube ssh --node=minikube-m02
minikube ssh --node=minikube-m03

# ⛔ Taint and Label Nodes
kubectl taint nodes minikube node-role.kubernetes.io/master=:NoSchedule
kubectl label node minikube-m02 node-role.kubernetes.io/worker=""
kubectl label node minikube-m03 node-role.kubernetes.io/worker=""

# 🧹 Clean Minikube (if needed)
minikube stop minikube delete --all
minikube delete --all --purge


# CyberPulse-App
CyberPulse is a web app that collects, stores, and shows up-to-date cybersecurity threat information from an external source called AlienVault OTX. It also tracks how the app behaves using OpenTelemetry and Jaeger.

The app regularly talks to AlienVault OTX’s API to get new threat alerts. It downloads and saves this data in a database (MongoDB). This is called data ingestion.

MongoDB is a NoSQL database used to store the threat alerts

# Observability with OpenTelemetry and Jaeger
The app tracks how it’s performing and reports tracing data to Jaeger




🚀 1. Deploy (Bootstrap & Add Resources)

Go to GitHub token settings and create a token with the necessary scopes:

"https://github.com/settings/tokens" export GITHUB_TOKEN=ghp_xxx # your personal GitHub token flux bootstrap github
--owner=Elvis-Ngwesse
--repository=Jaeger-OpenTelemetry
--branch=main
--path=./k8s
--personal

⬇️⬆️ 📥 git pull

Do a git pull since flux-system folder is created in remote

🔄 Force a manual reconciliation

flux reconcile kustomization couchdb --with-source flux get all flux get sources git flux get kustomizations kubectl get pods -n flux-system flux check kubectl -n flux-system delete pods --all kubectl -n flux-system logs deployment/kustomize-controller -f kubectl -n flux-system get kustomizations.kustomize.toolkit.fluxcd.io -o wide

🗑️ Clean Up Kubernetes Resources

kubectl delete namespace car-app kubectl delete namespace car-logs



http://localhost:5080
root@gmail.com
admin


python3 -c "import requests; print(requests.post('http://localhost:5514'))"
docker ps | grep openobserve
docker inspect --format='{{json .State.Health}}' openobserve | jq


📬 Send failed pulse insertions to Redis DLQ?



curl -v http://openobserve:5080/v1/traces

curl -v http://localhost:5080/api/default
curl -v http://openobserve:5080/api/default
curl -v http://openobserve:5080/api/default



https://openobserve.ai/docs/ingestion/traces/python/
