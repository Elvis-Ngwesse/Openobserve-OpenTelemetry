⚙️ Project Overview
# 🛡️ Threat Intelligence Platform
 A Python-based multi-service application designed to collect, store, visualize, and trace cyber threat intelligence. 
 It leverages OpenTelemetry for distributed tracing and observability, MongoDB for data persistence, and OpenObserve 
 for logs, metrics, and traces.

---

## ⚙️ Architecture Overview

### 🌐 `app-ui` (Frontend)
- **Tech Stack:** Flask + HTMX + TailwindCSS + OpenTelemetry
- **Function:** Interactive web UI for visualizing threat intelligence.
- **Features:**
    - View recent threats
    - Filter by:
        - IOC Type (IP, domain, file hash, etc.)
        - Severity
        - Tags
        - Date range
    - Tracing propagation to backend
    - Metrics (CPU, memory, request counters)
    - Logs

---

### 🛰️ `threat-fetcher` (Background Worker)
- **Tech Stack:** Python + Schedule + Requests + MongoDB
- **Function:** Periodically fetches latest threat data from public CTI sources like:
    - AlienVault OTX
    - MISP (Optional)
- **Features:**
    - Runs every minute in the background
    - Avoids duplicate entries
    - Supports multiple indicator types (IP, domains, URLs, hashes)
    - Logs CPU and memory stats per fetch cycle
    - Tracing enabled to monitor pipeline behavior

---

### 📦 MongoDB (Database)
- **Function:** Stores structured threat indicators
- **Collections:**
    - `threats`: Contains enriched IOC data with timestamps, tags, type, and source

---

### 📊 OpenObserve (Telemetry Backend)
- **Function:** Aggregates:
    - Traces from all services (via OTLP/HTTP)
    - Application logs
    - System and app metrics
- **Stream Name:** `openobserve_stream`
- **Benefits:**
    - End-to-end tracing visibility
    - Unified observability stack (logs, metrics, traces)
    - Searchable, filterable telemetry dashboard

---

## 🚀 Features at a Glance
- 🔄 Automatic CTI ingestion every minute
- 🔍 Filterable threat dashboards
- 📊 Distributed tracing with OpenTelemetry
- 🧠 Prometheus-style metrics
- 🧾 Logs with CPU and memory stats
- ☁️ Ready for deployment with Docker Compose or Kubernetes (via flux)

---

****************************
# Openobserve-OpenTelemetry
****************************

# 📦 Project Setup
✅ Create Virtual Environment

python3 -m venv venv
source venv/bin/activate
deactivate


# ▶️ Build and Start the Stack
docker-compose build --no-cache
docker-compose up -d

# 🖥️ Access Services in Browser
App UI: http://localhost:5020/
Openobserve UI: http://localhost:5080/
Username: root@gmail.com
Password: admin


# 🌍 Build Multi platform Image app
docker buildx create --use

COMMIT_SHA=$(git rev-parse --short HEAD) && \
docker buildx build --platform linux/amd64,linux/arm64 \
-t dockerelvis/threat-app:latest \
-t dockerelvis/threat-app:$COMMIT_SHA \
-f ./app/Dockerfile \
--push ./app
echo $COMMIT_SHA

# 🌍 Build Multi platform Image fetcher
docker buildx create --use

COMMIT_SHA=$(git rev-parse --short HEAD) && \
docker buildx build --platform linux/amd64,linux/arm64 \
-t dockerelvis/fetcher-app:latest \
-t dockerelvis/fetcher-app:$COMMIT_SHA \
-f ./fetcher/Dockerfile \
--push ./fetcher
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


🚀 1. Deploy (Bootstrap & Add Resources)
Go to GitHub token settings and create a token with the necessary scopes:
---
"https://github.com/settings/tokens" export GITHUB_TOKEN=ghp_xxx # your personal GitHub token flux bootstrap github
---
flux bootstrap github \
--owner=Elvis-Ngwesse \
--repository=Openobserve-OpenTelemetry \
--branch=main \
--path=./k8s \
--personal

---

⬇️⬆️ 📥 git pull
Do a git pull since flux-system folder is created in remote
---

🔄 Force a manual reconciliation

🗑️ Clean Up Kubernetes Resources

kubectl delete namespace car-app kubectl delete namespace car-logs


🧪 Verify
kubectl get pods,svc
kubectl logs deploy/threats-app
kubectl logs deploy/fetcher-app
