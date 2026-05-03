# Secubernetes Security Layers

This folder contains the security demos and configuration files for the Secubernetes project.

Secubernetes is built as a multi-layer Kubernetes security system:

```text
1. Supply Chain Security
   Docker image signing and verification with Cosign

2. Admission Control / Policy Enforcement
   Kubernetes policy enforcement with Kyverno

3. Runtime Security
   eBPF runtime monitoring, anomaly detection, LOF, Adaptive Threshold, risk scoring, MongoDB and frontend
```

---

## 1. Supply Chain Security - Cosign

The supply chain layer demonstrates that container images can be signed and verified before being trusted.

This helps protect the Kubernetes environment from running images that were not produced or approved by the project owner.

### Implemented Flow

```text
Dockerfile
-> docker build
-> docker push to GHCR
-> cosign sign
-> cosign verify
```

### Important Files

```text
security/supply-chain/demo-app/Dockerfile
security/supply-chain/cosign/secubernetes-demo.pub
docs/demo-evidence/supply-chain/
```

The private key is intentionally ignored by Git and must not be committed:

```text
security/supply-chain/cosign/secubernetes-demo.key
```

### Build Demo Image

```bash
docker build -t ghcr.io/yuvalpinto/secubernetes-demo:latest security/supply-chain/demo-app
```

### Push Demo Image to GHCR

```bash
docker push ghcr.io/yuvalpinto/secubernetes-demo:latest
```

### Sign Image with Cosign

```bash
cosign sign \
  --key security/supply-chain/cosign/secubernetes-demo.key \
  ghcr.io/yuvalpinto/secubernetes-demo:latest
```

### Verify Signed Image

```bash
cosign verify \
  --key security/supply-chain/cosign/secubernetes-demo.pub \
  ghcr.io/yuvalpinto/secubernetes-demo:latest
```

### Expected Verification Result

The verification should show that:

```text
The cosign claims were validated
Existence of the claims in the transparency log was verified
The signatures were verified against the specified public key
```

This proves that the image was signed and can be verified before use.

### Evidence

Evidence files are saved under:

```text
docs/demo-evidence/supply-chain/
```

Example evidence files:

```text
cosign-version.txt
docker-build.txt
docker-push.txt
cosign-sign.txt
cosign-verify-success.txt
```

---

## 2. Admission Control - Kyverno

The admission control layer blocks dangerous Kubernetes configurations before Pods are allowed to run.

This layer works before runtime. If a Pod violates a security policy, Kubernetes rejects it during the admission phase.

### Implemented Policies

The project includes the following Kyverno ClusterPolicies:

```text
1. Disallow privileged containers
2. Disallow hostPath volumes
3. Require CPU and memory requests/limits
4. Restrict allowed image registries
```

### Important Files

```text
security/kyverno/policies/
security/kyverno/test-pods/
docs/demo-evidence/kyverno/
```

### Apply Policies

```bash
kubectl apply -f security/kyverno/policies/
```

### Check Policies

```bash
kubectl get clusterpolicies
```

Expected policies:

```text
secubernetes-disallow-privileged-containers
secubernetes-disallow-hostpath
secubernetes-require-resource-limits
secubernetes-restrict-image-registries
```

### Policy 1 - Block Privileged Containers

A privileged container is dangerous because it gives the container very high permissions on the node.

```bash
kubectl apply -f security/kyverno/test-pods/bad-privileged-pod.yaml
```

Expected result:

```text
admission webhook "validate.kyverno.svc" denied the request
Privileged containers are not allowed by Secubernetes admission policy
```

### Policy 2 - Block hostPath Volumes

A hostPath volume is dangerous because it allows a Pod to mount files or directories from the Kubernetes node itself.

```bash
kubectl apply -f security/kyverno/test-pods/bad-hostpath-pod.yaml
```

Expected result:

```text
admission webhook "validate.kyverno.svc" denied the request
hostPath volumes are not allowed by Secubernetes admission policy
```

### Policy 3 - Require Resource Limits

Pods without CPU and memory limits can abuse node resources and cause denial-of-service behavior.

```bash
kubectl apply -f security/kyverno/test-pods/bad-no-resources-pod.yaml
```

Expected result:

```text
admission webhook "validate.kyverno.svc" denied the request
CPU and memory requests/limits are required by Secubernetes admission policy
```

### Policy 4 - Restrict Image Registries

This policy allows only approved container image registries.

In this demo, the allowed registry is:

```text
ghcr.io/yuvalpinto/*
```

```bash
kubectl apply -f security/kyverno/test-pods/bad-registry-pod.yaml
```

Expected result:

```text
admission webhook "validate.kyverno.svc" denied the request
Only images from ghcr.io/yuvalpinto/* are allowed
```

### Valid Pod Test

A valid Pod should pass admission control.

```bash
kubectl apply -f security/kyverno/test-pods/good-pod.yaml
kubectl get pods -n policy-demo
```

Expected result:

```text
good-policy-demo-pod   1/1   Running
```

### Evidence

Evidence files are saved under:

```text
docs/demo-evidence/kyverno/
```

Example evidence files:

```text
bad-privileged-rejection.txt
bad-hostpath-rejection.txt
bad-no-resources-rejection.txt
bad-registry-rejection.txt
good-pod-admission.txt
good-pod-describe-running.txt
```

---

## 3. Runtime Security

The runtime security layer monitors actual behavior inside containers after they are already running.

This layer uses eBPF programs to collect runtime events from the Linux kernel.

The monitored event types are:

```text
execve  - process execution
openat  - file access
connect - network connection attempts
```

The runtime pipeline is:

```text
eBPF userspace binaries
-> runtime_runner
-> stream_reader
-> event_builder
-> event_enricher
-> dispatcher
-> storage_worker
-> online_worker
-> feature_worker
-> Adaptive Threshold
-> LOF
-> combined risk score
-> MongoDB
-> FastAPI
-> React frontend
```

### Run Runtime Detector

```bash
sudo ./backend/.venv/bin/python -m backend.collector.runtime_runner
```

### Create Runtime Test Pod

```bash
kubectl run test-pod --image=busybox --restart=Never -- sleep 3600
kubectl get pod test-pod
```

Expected:

```text
test-pod   1/1   Running
```

### Generate Runtime Events

Enter the Pod:

```bash
kubectl exec -it test-pod -- sh
```

Inside the Pod, run:

```sh
whoami
cat /etc/passwd
cat /etc/shadow
wget http://93.184.216.34
```

If `wget` is not available or fails, use:

```sh
nc -vz 93.184.216.34 80
```

### Expected Runtime Output

The runtime runner should show events with container metadata:

```text
pod_name=test-pod
namespace=default
resolver_status=resolved
```

The system should create:

```text
raw events
online alerts
feature vectors
Adaptive Threshold results
LOF results
combined container risk scores
MongoDB records
frontend visualizations
```

### Runtime Collections

The main MongoDB collections used by the runtime layer are:

```text
events_raw
alerts
feature_vectors
feature_anomalies
container_risk_scores
```

### MongoDB Checks

```bash
mongosh
```

```js
use secubernetes

db.events_raw.find().sort({ts:-1}).limit(5).pretty()
db.alerts.find().sort({ts:-1}).limit(5).pretty()
db.feature_vectors.find().sort({window_end:-1}).limit(5).pretty()
db.container_risk_scores.find().sort({ts:-1}).limit(5).pretty()

db.events_raw.find({pod_name:"test-pod"}).sort({ts:-1}).limit(5).pretty()
db.alerts.find({"source_event.pod_name":"test-pod"}).sort({ts:-1}).limit(5).pretty()
db.feature_vectors.find({pod_name:"test-pod"}).sort({window_end:-1}).limit(5).pretty()
db.container_risk_scores.find({pod_name:"test-pod"}).sort({ts:-1}).limit(5).pretty()
```

---

## 4. Full Security Architecture Summary

Secubernetes demonstrates a multi-layer security architecture:

```text
Before deployment:
Cosign verifies image authenticity
Kyverno blocks dangerous Kubernetes configurations

During runtime:
eBPF collects low-level runtime behavior
Online rules detect known suspicious patterns
Feature vectors summarize behavior per time window
Adaptive Threshold detects statistical anomalies
LOF detects local outliers
Sequence/risk scoring combines context into final risk

After detection:
MongoDB stores evidence
FastAPI exposes data
React frontend displays alerts, risk and runtime state
```

This creates a complete security flow:

```text
Build image
-> Sign image
-> Verify image
-> Enforce Kubernetes admission policies
-> Run approved Pod
-> Monitor runtime behavior
-> Detect suspicious actions
-> Score risk
-> Store evidence
-> Display results in frontend
```

---

## 5. Demo Order for Project Presentation

### Step 1 - Show Supply Chain Security

```bash
cosign verify \
  --key security/supply-chain/cosign/secubernetes-demo.pub \
  ghcr.io/yuvalpinto/secubernetes-demo:latest
```

Explain:

```text
The image is signed and verified before it is trusted.
```

### Step 2 - Show Kyverno Blocking Bad Pods

```bash
kubectl apply -f security/kyverno/test-pods/bad-privileged-pod.yaml
```

Explain:

```text
The Pod is blocked before it can run because it violates admission policy.
```

### Step 3 - Show Good Pod Running

```bash
kubectl apply -f security/kyverno/test-pods/good-pod.yaml
kubectl get pods -n policy-demo
```

Explain:

```text
A valid Pod passes admission control.
```

### Step 4 - Show Runtime Detection

```bash
sudo ./backend/.venv/bin/python -m backend.collector.runtime_runner
```

Then:

```bash
kubectl exec -it test-pod -- sh
```

Inside the Pod:

```sh
cat /etc/passwd
wget http://93.184.216.34
```

Explain:

```text
The runtime layer detects file access, network activity, anomaly scores and risk.
```

### Step 5 - Show Frontend

Open the frontend and show:

```text
alerts
feature vectors
LOF result
Adaptive Threshold result
risk score
container/pod context
```

---

## 6. Notes

The private Cosign key is intentionally not committed to Git.

The public key is committed because it is needed for verification:

```text
security/supply-chain/cosign/secubernetes-demo.pub
```

The evidence files are stored to make the project easier to present and verify:

```text
docs/demo-evidence/
```

The Kyverno demo is scoped to the namespace:

```text
policy-demo
```

This prevents the demo policies from breaking other development or runtime tests.
