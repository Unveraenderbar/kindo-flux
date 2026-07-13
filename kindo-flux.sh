#!/bin/sh

# General kind-related parameters:
k8sVersion="${KIND_K8s_VERSION:-v1.36.1}"
kindImage="kindest/node:$k8sVersion"
clusterName="${1:-k8s-$k8sVersion}"
export KIND_TMP_DIR="${TMPDIR:=/var/tmp}/$clusterName"
kindConfig="${2:-$KIND_TMP_DIR/kind-$k8sVersion.yaml}"
kubeConfig="${3:-$KIND_TMP_DIR/kubeconfig-$clusterName}"
kxDir="${XDG_CONFIG_HOME:-$HOME/.config}/kubectx"
sshKeyScanCmd="${KIND_SSH_KEYSCAN_CMD=ssh-keyscan -t ecdsa -p}"

# kubectl-related parameters:
kubectlBaseUrl="https://dl.k8s.io/release"
kubectlUrl="${KUBECTL_URL:-$kubectlBaseUrl/$(curl -Ls $kubectlBaseUrl/stable.txt)/bin/linux/amd64/kubectl}"

# gitolite+OpenSSH image related parameters:
opensshImg="${GITOSSH_BASE_IMAGE:-docker.io/linuxserver/openssh-server:latest}"
opensshPort="$((${KIND_OPENSSH_PORT:-2222} + ${K8S_KIND_NODEPORT_OFFSET:-0}))"
nodePortPrefix="${KIND_NODEPORT_PREFIX:-3}"
opensshNodePort="$nodePortPrefix$opensshPort" # has to be in standard k8s NodePort range 30000-32767
knownHostsFile="${KIND_SSH_KNOWN_HOSTS_FILE:-$HOME/.ssh/known_hosts}"
gitoliteNamespace="${KIND_GITOLITE_NAMESPACE:-gitolite}"
gitosshName="${GITOSSH_IMAGE_NAME:-${GITOSSH_NAME:-docker.io/library/gitossh}}"
gitosshImg="$gitosshName:${GITOSSH_TAG:-latest}"
gitoliteUser="${GITOLITE_USERNAME:-git}"
gitoliteAdminKeyFile="${GITOSSH_ADMIN_KEY_FILE:-$KIND_TMP_DIR/gitolite.ecdsa}"
gitoliteAdminClone="${GITOLITE_ADMIN_CLONE:-$KIND_TMP_DIR/gitolite-admin}"
gitoliteConfFile="$gitoliteAdminClone/conf/gitolite.conf"
gitoliteLocalBaseUrl="ssh://$gitoliteUser@localhost:$opensshNodePort"
gitoliteSSHCmd='ssh -o IdentityAgent=none -F /dev/null -i'

gitolitePrintCloneCmd() {
    printf "GIT_SSH_COMMAND='$gitoliteSSHCmd %s' git clone $gitoliteLocalBaseUrl/%s\n" "$1" "$2"
}

gitIsRepoUnchanged() {
    [ ! -r "$gitoliteFluxKeyFile" ] || [ ! -r "$gitoliteFluxPubKeyFile" ]
}

# FluxCD related parameters:
fluxNamespace="${KIND_FLUX_NAMESPACE:-flux-system}"
fluxBootNamespace="${KIND_FLUX_BOOT_NAMESPACE:-flux-bootstrap}"
fluxVersion="${FLUX_VERSION:-2.8.8}"
fluxUrl="https://github.com/fluxcd/flux2/releases/download/v$fluxVersion/flux_${fluxVersion}_linux_amd64.tar.gz"
gitoliteFluxKeyFile="${GITOSSH_FLUX_KEY_FILE:-$KIND_TMP_DIR/$fluxNamespace.ecdsa}"
gitoliteFluxPubKeyFile="$gitoliteAdminClone/keydir/$fluxNamespace.pub"
fluxCloneDir="${KIND_FLUX_CLONE_DIR:-$KIND_TMP_DIR/$fluxNamespace}"

# ArgoCD related parameters:
argoCdNamespace="${KIND_FLUX_NAMESPACE:-argocd}"
argoCdVersion="${ARGOCD_VERSION:-stable}"
argoCdUrl="https://raw.githubusercontent.com/argoproj/argo-cd/$argoCdVersion/manifests/install.yaml"
argocdNodePort="$((${ARGOCD_NODE_PORT:-${nodePortPrefix}0333} + ${K8S_KIND_NODEPORT_OFFSET:-0}))"

# k8s cluster API  related parameters:
clusterApiProviderNamespace="${CLUSTER_API_PROVIDER_NAMESPACE:-capi}"
clusterApiTestNamespace="${CLUSTER_API_PROVIDER_NAMESPACE:-capv-test}"
vclusterNodePort="$((${VCLUSTER_NODE_PORT:-${nodePortPrefix}0444} + ${K8S_KIND_NODEPORT_OFFSET:-0}))"
clusterApiHelmValues='service:\n  type: NodePort'
clusterApiEnvPatch="patches:
- target:
    kind: Deployment
    name: .*
  patch: |-
    - op: add
      path: '/spec/template/spec/containers/0/env/-'
      value:
        name: CLUSTER_NAME
        value: '$clusterName'
    - op: add
      path: '/spec/template/spec/containers/0/env/-'
      value:
        name: CLUSTER_NAMESPACE
        value: '$clusterApiProviderNamespace'
    - op: add
      path: '/spec/template/spec/containers/0/env/-'
      value:
        name: KUBERNETES_VERSION
        value: '$k8sVersion'
    - op: add
      path: '/spec/template/spec/containers/0/env/-'
      value:
        name: HELM_VALUES
        value: '$clusterApiHelmValues'
- target:
    kind: VCluster
    name: $clusterApiTestNamespace
  patch: |-
    - op: replace
      path: '/spec/helmRelease/chart/name'
      value: ''
    - op: replace
      path: '/spec/helmRelease/chart/repo'
      value: ''
    - op: replace
      path: '/spec/helmRelease/chart/version'
      value: ''
- target:
    kind: Deployment
    name: cluster-api-provider-vcluster-controller-manager
  patch: |-
    - op: replace
      path: '/spec/template/spec/containers/1/image'
      value: 'docker.io/kubebuilder/kube-rbac-proxy:v0.8.0' # default tries to pull from ghcr.io where the image is not available?"

fluxWaitForKustomization() {
    kubeCtl() { kubectl -n "$fluxNamespace" "$@"; }
    kubeWait() { kubeCtl wait kustomization --timeout="${KIND_KUSTOMIZATION_WAIT_TIMEOUT:-4m}" "$@"; }
    while ! kubeCtl get kustomization "$1" -o 'jsonpath={.status.observedGeneration}'; do sleep "${2:-2}"; done
    kubeWait "$1" --for='jsonpath={.status.observedGeneration}=1' # can be -1 while kustomization is uninitialized
    kubeWait "$1" --for='jsonpath={.status.conditions[0].reason}=ReconciliationSucceeded'
    kubectl get -A gitrepositories,kustomizations
}

fluxAddComponent() {( # run in sub-shell to isolate git SSH command / working directory
    rm -rf "$fluxCloneDir"
    # shellcheck disable=SC2030,SC2031
    export GIT_SSH_COMMAND="$gitoliteSSHCmd $gitoliteFluxKeyFile"
    git clone "$gitoliteLocalBaseUrl/$fluxNamespace" "$fluxCloneDir"
    componentSubDir="clusters/$clusterName/$1"
    mkdir -p "$fluxCloneDir/$componentSubDir"
    cd "$fluxCloneDir/$componentSubDir"
    eval "${7:-wget -O- \"$2\"}" > "$1-components.yaml"
    if ! gitIsRepoUnchanged; then
        git add .; git commit -m "Add $3 for kind manifests"; git push
    fi

    tee "$1-sync.yaml" <<-EOF
	apiVersion: kustomize.toolkit.fluxcd.io/v1
	kind: Kustomization
	metadata:
	  labels:
	    kustomize.toolkit.fluxcd.io/name: $1
	    kustomize.toolkit.fluxcd.io/namespace: $fluxNamespace
	  name: $1
	  namespace: $fluxNamespace
	spec:
	  force: false
	  interval: 1m0s
	  path: ./$componentSubDir
	  prune: true
	  sourceRef:
	    kind: GitRepository
	    name: $fluxNamespace
	EOF

    tee kustomization.yaml <<-EOF
	apiVersion: kustomize.config.k8s.io/v1beta1
	kind: Kustomization
	resources:
	- $1-components.yaml
	- $1-sync.yaml
	$(echo "$6" | sed 's/^	*//')
	EOF

    if ! gitIsRepoUnchanged; then
        git add .; git commit -m "Add $3 for kind sync manifests"; git push
    fi
    kubectl -n "$fluxNamespace" apply -f "$1-sync.yaml"
    fluxWaitForKustomization "$1"
    kubectl -n "$4" wait pod -l "$5" --for=condition=ready --timeout="${K8S_POD_WAIT_TIMEOUT:-6m}"
)}

istioNamespace="${KIND_CONTOUR_NAMESPACE:-istio-system}"
istioIngressGateway='ingress-gateway'

metricsServerUrl="${KIND_METRICS_SERVER_DEPLOYMENT_URL:-https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml}"

export HELM_CACHE_HOME="$KIND_TMP_DIR/.cache/helm" HELM_CONFIG_HOME="$KIND_TMP_DIR/.config/helm"
zotChartUrl="${ZOT_HELM_CHART_URL:-http://zotregistry.dev/helm-charts}"
zotNamespace="${ZOT_NAMESPACE:-zot}"

envTrueCheck() {
   [ "$(echo "$1" | tr '[:upper:]' '[:lower:]')" = 'true' ]
}

finishInfoExit() {
    set +x 2>/dev/null
    kubectl get pod -A
    # shellcheck disable=SC2059
    printf "\nexport KUBECONFIG='%s'\n" "$kubeConfig"
    gitolitePrintCloneCmd "$gitoliteAdminKeyFile" gitolite-admin
    envTrueCheck "$KINDOFLUX_ONLY_K8S" || gitolitePrintCloneCmd "$gitoliteFluxKeyFile"  "$fluxNamespace"
    envTrueCheck "$KINDOFLUX_ARGO" \
        && echo "argocd login localhost:$argocdNodePort --insecure --username admin --password \"\$(kubectl -n $argoCdNamespace get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d)\""
    echo "export KIND_TMP_DIR=$KIND_TMP_DIR"
    exit "$1"
}

## phase 0 prepare:

# see https://github.com/NixOS/nixpkgs/issues/36214 for summary and
# documentation hub:
inotifyMaxInstances="$(cat /proc/sys/fs/inotify/max_user_instances)"
[ "$inotifyMaxInstances" -ge 512 ] || {
    echo "Cannot provision ArgoCD, max. count $inotifyMaxInstances of inotify user instances too low for ArgoCD" 1>&2
    echo "Run sudo sysctl sysctl fs.inotify.max_user_instances=8192 for correction" 1>&2
    exit 1
}
lsmod | awk '$1 == "ip_tables" {exit 0}' || {
    echo "Cannot provision Contour ingress controllers as IP tables kernel module not loaded, aborting" 1>&2
    exit 1
}

set -ex
kindPath="$(command -v kind)"
[ -n "$kindPath" ] || exit 1
kindCmd="KIND_EXPERIMENTAL_PROVIDER=podman $kindPath"

if [ -n "$(mount -lt cgroup)" ]; then
    sudo='sudo'             # WSL messed-up/outdated cgroups, cannot run rootless
else
    unprivilegedPort='true' # running rootless, cannot expose privileged ports
fi

rm -rf "$KIND_TMP_DIR"; (umask 077; mkdir -p "$KIND_TMP_DIR")

gitoliteUid="$(id -u)"
gitoliteGid="$(id -g)"

## phase 1.1 build (if it doesn't exist) image w/ OpenSSH server + gitolite + flux2 CLI:

if [ -z "$(podman images --noheading "$gitosshImg")" ]; then # trigger rebuild of gitolite image by deleting it
    buildah rm "$gitosshName" || true
    buildah rmi "$opensshImg" "$gitosshImg" || true
    buildah from --name "$gitosshName" "$opensshImg"
    ${TZ:+buildah config --env TZ="$TZ" "$gitosshName"}
    # have to make port in sshd configuration runtime-parametrizable in case we install w/ offset!
    buildah run "$gitosshName" sh -exc \
            "apk update; apk upgrade; apk add ${GITOSSH_PKGS:-git perl gitolite openssl}
             sed -i -e 's/ \(2222\)/ \${OPENSSH_PORT:-\1}/' /etc/s6-overlay/s6-rc.d/svc-openssh-server/run
             usermod -u $gitoliteUid -g $gitoliteGid $gitoliteUser
             wget -O- $fluxUrl | tar -oxzf - -C /usr/local/bin flux
             wget -O    /usr/bin/kubectl $kubectlUrl
             chmod 0555 /usr/bin/kubectl"
    buildah commit --rm "$gitosshName" "$gitosshImg"
fi
gitolitePwEntry="$(podman run --rm --entrypoint='' "$gitosshName" grep "^$gitoliteUser" /etc/passwd)"
gitoliteHomeDir="$(echo "$gitolitePwEntry" | cut -d: -f 6)"
gitosshImgArchive="$KIND_TMP_DIR/$(echo "$gitosshImg" | tr /: --)"
podman save "$gitosshImg" > "$gitosshImgArchive"

## phase 1.2 provision k8s / kind cluster w/ port-forwarding for ingress:and SSH based services

export KUBECONFIG="$kubeConfig" # kind tries to lock kubectl configuration
ingressHttpNodePort="${unprivilegedPort:+300}$((80  + ${K8S_KIND_NODEPORT_OFFSET:-0}))"
ingressHttpsNodePort="${unprivilegedPort:+30}$((443 + ${K8S_KIND_NODEPORT_OFFSET:-0}))"
tee "$kindConfig" <<-EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: $clusterName
networking:
  apiServerAddress: "127.0.0.1"
  apiServerPort: 6443 # prevents API server listening on random port
  ipFamily: ipv4 # disables IPV6 networking
nodes:
- role: control-plane
  labels:
    ingress-ready: true
  extraPortMappings:
  - containerPort: $ingressHttpNodePort
    hostPort: $ingressHttpNodePort
    listenAddress: '0.0.0.0'
    protocol: TCP
  - containerPort: $ingressHttpsNodePort
    hostPort: $ingressHttpsNodePort
    listenAddress: '0.0.0.0'
    protocol: TCP
  - containerPort: 15021
    hostPort: 30081
    listenAddress: '0.0.0.0'
    protocol: TCP
  - containerPort: $opensshNodePort
    hostPort: $opensshNodePort
    protocol: TCP
  - containerPort: $argocdNodePort
    hostPort: $argocdNodePort
    protocol: TCP
  - containerPort: $vclusterNodePort
    hostPort: $vclusterNodePort
    protocol: TCP
$(seq 1 "${KIND_NUM_NODES:-2}" | xargs -rn1 sh -c "printf -- \"- role: worker\n\"")
EOF
$sudo sh -exc "kind delete cluster --name $clusterName || true
               podman rm --filter name=$clusterName
               $kindCmd create cluster --image $kindImage --config $kindConfig
               $kindCmd export kubeconfig --kubeconfig=$kubeConfig --name $clusterName
               chown $gitoliteUid:$gitoliteGid $kubeConfig
               $kindCmd load image-archive $gitosshImgArchive --name=$clusterName"
if [ -d "$kxDir" ] && [ -d "$kxDir/clusters" ] && [ -d "$kxDir/users" ] && command -v yq >/dev/null; then
   kubeClusters="$(yq 'with_entries(select(.key == "clusters"))' "$kubeConfig")"
      kubeUsers="$(yq 'with_entries(select(.key == "users"   ))' "$kubeConfig")"
   echo "$kubeClusters" > "$kxDir/clusters/$(echo "$kubeClusters" | yq '.clusters[].name' -)"
   echo "$kubeUsers"    > "$kxDir/users/$(   echo "$kubeUsers"    | yq '.users[].name'    -)"
fi

## phase 2.1 provision git service in k8s:

kubectl create namespace "$gitoliteNamespace"
kubectl -n "$gitoliteNamespace" create service nodeport "$gitoliteNamespace" \
                                               --tcp="$opensshPort" --node-port="$opensshNodePort"
ssh-keygen -qt ed25519 -a 64 -C "$gitoliteNamespace" -P '' -f "$gitoliteAdminKeyFile"
tee "${KIND_GITOLITE_DEPLOY_DEBUG:-/dev/stderr}" <<-EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  labels:
    app: $gitoliteNamespace
  name: $gitoliteNamespace-home
  namespace: $gitoliteNamespace
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 64M
  storageClassName: standard

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  labels:
    app: $gitoliteNamespace
  name: $gitoliteNamespace-openssh
  namespace: $gitoliteNamespace
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 64M
  storageClassName: standard

---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: $gitoliteNamespace
  name: $gitoliteNamespace
  namespace: $gitoliteNamespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: $gitoliteNamespace
  strategy:
    type: Recreate
  template:
    metadata:
      labels:
        app: $gitoliteNamespace
    spec:
      containers:
      - env:
        - name: OPENSSH_PORT
          value: '$opensshPort'
        - name: PUBLIC_KEY
          value: '$(ssh-keygen -y -f "$gitoliteAdminKeyFile")'
        - name: PGID
          value: '$gitoliteGid'
        - name: PUID
          value: '$gitoliteUid'
        image: $gitosshImg
        imagePullPolicy: Never
        name: openssh
        ports:
        - containerPort: $opensshPort
        volumeMounts:
        - mountPath: $gitoliteHomeDir
          name: $gitoliteNamespace-home
        - mountPath: /config
          name: $gitoliteNamespace-openssh
      initContainers:
      - args:
        - |
          chown -R $gitoliteUid:$gitoliteGid $gitoliteHomeDir
          chmod 0700 $gitoliteHomeDir
          [ -d $gitoliteHomeDir/.gitolite ] || \
              exec sudo -u $gitoliteUser sh -exc "   echo \"\$PUBLIC_KEY\" > /tmp/key.pub \
                                                  && gitolite setup -pk /tmp/key.pub"
        command: ['sh', '-exc']
        env:
        - name: PUBLIC_KEY
          value: '$(ssh-keygen -y -f "$gitoliteAdminKeyFile")'
        image: $gitosshImg
        imagePullPolicy: Never
        name: gitolite-setup
        volumeMounts:
        - mountPath: $gitoliteHomeDir
          name: $gitoliteNamespace-home
      restartPolicy: Always
      volumes:
      - name: $gitoliteNamespace-home
        persistentVolumeClaim:
          claimName: $gitoliteNamespace-home
      - name: $gitoliteNamespace-openssh
        persistentVolumeClaim:
          claimName: $gitoliteNamespace-openssh
EOF

## phase 2.2 connect git service to container host:

sleep 2 # give gitolite pod time to show up, so that it can be waited for
kubectl -n "$gitoliteNamespace" wait --for=condition=ready --timeout="${KIND_KUSTOMIZATION_WAIT_TIMEOUT:-4m}" \
        pod -l "app=$gitoliteNamespace"
if [ -r "$knownHostsFile" ] && [ -s "$knownHostsFile" ]; then
    sed -i -e "/^\[localhost\]:$opensshNodePort /d" "$knownHostsFile"
fi
while ! sshServerPubKey="$($sshKeyScanCmd "$opensshNodePort" localhost)"; do sleep 1; done
echo "$sshServerPubKey" >> "$knownHostsFile"
k8sSshSvcName="$gitoliteNamespace.$gitoliteNamespace"
gitolitePod="$(kubectl -n "$gitoliteNamespace" get pod -l app="$gitoliteNamespace" -o name)"
# shellcheck disable=2086
k8sServerPubKey="$(kubectl -n "$gitoliteNamespace" exec -ti -c openssh $gitolitePod -- \
                                                        $sshKeyScanCmd $opensshPort $k8sSshSvcName)"
gitoliteCloneCmd="$(gitolitePrintCloneCmd "$gitoliteAdminKeyFile" gitolite-admin)"
kubectl -n "$gitoliteNamespace" create secret generic "$gitoliteNamespace" \
                                                      "--from-file=id_ecdsa=$gitoliteAdminKeyFile" \
                                                      "--from-literal=known_hosts=$k8sServerPubKey" \
                                                      "--from-literal=clone_command=$gitoliteCloneCmd"

## phase 2.3 provision Istio service mesh (i.e. independant of Flux in case we want to bootstrap the latter via operator)
openSslOpts='-sha256 -days 365'
openSslReqOpts="req -quiet $openSslOpts -x509 -nodes -newkey rsa:2048"
kubeSslCmd="kubectl exec -n gitolite $gitolitePod -c openssh -i --"
kubectl create namespace "$istioNamespace"
$kubeSslCmd \
        sh -c "set -e; cd /tmp \
               && openssl $openSslReqOpts -subj '/CN=localhost/O=localhost CA'                    -keyout ingress-ca.key -out ingress-ca.crt \
               && openssl req -quiet -nodes -newkey rsa:2048 -subj '/CN=ingress.localhost/O=localhost Istio ingress' -keyout ingress.key -out ingress.csr \
               && openssl x509 -req $openSslOpts -CA ingress-ca.crt -CAkey ingress-ca.key -set_serial 0 -in ingress.csr -out ingress.crt -extfile <(printf 'subjectAltName=DNS:localhost')"
(cd "$KIND_TMP_DIR" && mkdir crt key
 $kubeSslCmd cat /tmp/ingress-ca.crt > crt/ingress-ca.crt
 $kubeSslCmd cat /tmp/ingress-ca.key > key/ingress-ca.key
 $kubeSslCmd cat /tmp/ingress.crt    > crt/ingress.crt
 $kubeSslCmd cat /tmp/ingress.key    > key/ingress.key
 kubectl create -n "$istioNamespace" secret tls ingress-tls --cert=crt/ingress.crt --key=key/ingress.key)

tee "${KIND_GITOLITE_DEPLOY_DEBUG:-/dev/stderr}" <<-EOF \
| istioctl install --skip-confirmation --readiness-timeout=15m --set 'profile=demo' -f -
---
apiVersion: install.istio.io/v1alpha1
kind: IstioOperator
metadata:
  namespace: $istioNamespace
  name: istiocontrolplane
spec:
  components:
    base:
      enabled: true
    cni:
      enabled: true
    ingressGateways:
    - enabled: true
      name: istio-ingressgateway
      k8s:
        nodeSelector:
          ingress-ready: 'true'
        service:
          type: NodePort
        overlays:
        - apiVersion: apps/v1
          kind: Deployment
          name: istio-ingressgateway
          patches:
          - path: spec.template.spec.tolerations
            value:
              - key: node-role.kubernetes.io/control-plane
                operator: Exists
                effect: NoSchedule
        - apiVersion: v1
          kind: Service
          name: istio-ingressgateway
          patches:
          - path: spec.ports
            value:
              - name: status-port
                port: 15021
                targetPort: 15021
                nodePort: 30081
                protocol: TCP
              - name: http2
                port: 8080
                targetPort: 8080
                nodePort: $ingressHttpNodePort
                protocol: TCP
              - name: https
                port: 8443
                targetPort: 8443
                nodePort: $ingressHttpsNodePort
                protocol: TCP
  meshConfig:
    accessLogFile: '/dev/stdout'
    accessLogEncoding: 'JSON'
  values:
    cni:
      excludeNamespaces:
        - $istioNamespace
        - kube-system
EOF
# phase 2.3.1 provision Istio central ingress gateway (routing HTTP traffic to Istio ingress service)
tee "${KIND_GITOLITE_DEPLOY_DEBUG:-/dev/stderr}" <<-EOF | kubectl apply -f -
---
apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: $istioIngressGateway-http
  namespace: $istioNamespace
spec:
  selector:
    istio: ingressgateway
  servers:
  - hosts:
    - '*'
    port:
      number: 8080
      name: http2
      protocol: HTTP
---
apiVersion: networking.istio.io/v1
kind: Gateway
metadata:
  name: $istioIngressGateway-https
  namespace: $istioNamespace
spec:
  selector:
    istio: ingressgateway
  servers:
  - hosts:
    - '*'
    port:
      number: 8443
      name: https
      protocol: HTTPS
    tls:
      mode: SIMPLE
      credentialName: ingress-tls
EOF

## phase 2.4 provision OCI registry (independent from Flux, so we can practice gitless GitOps)
kubectl create namespace "$zotNamespace"
kubectl label namespace "$zotNamespace" istio-injection=enabled
helm repo add project-zot "$zotChartUrl"
helm install -n "$zotNamespace" zot project-zot/zot \
             --set 'persistence=true' --set 'pvc.storage=20Gi' --set 'pvc.storageClassName=standard'
sleep 2 # give zot workload time to show up, so that it can be waited for
kubectl -n "$zotNamespace" wait --for=condition=ready --timeout="${KIND_KUSTOMIZATION_WAIT_TIMEOUT:-4m}" \
        pod -l "app.kubernetes.io/name=zot"
tee "${KIND_GITOLITE_DEPLOY_DEBUG:-/dev/stderr}" <<-EOF | kubectl apply -f - # expose zot via Istio CR, rewriting application root to /zot
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: zot
  namespace: $zotNamespace
spec:
  hosts:
  - "*"
  gateways:
  - $istioNamespace/$istioIngressGateway-http
  http:
  - route:
    - destination:
        host: zot.$zotNamespace.svc.cluster.local
        port:
          number: 5000
EOF

status=$?
envTrueCheck "$KINDOFLUX_ONLY_K8S" && finishInfoExit $status

## phase 2.5 instantiate FluxCD base git repository:

rm -rf "$gitoliteAdminClone" "$gitoliteFluxKeyFile" "$gitoliteFluxPubKeyFile"
# shellcheck disable=SC2030,SC2031
(export GIT_SSH_COMMAND="$gitoliteSSHCmd $gitoliteAdminKeyFile"
    git clone "$gitoliteLocalBaseUrl/gitolite-admin" "$gitoliteAdminClone"
    cd "$gitoliteAdminClone"
    if ! grep -q "^repo $fluxNamespace" "$gitoliteConfFile"; then # flux bootstrap expects 'flux-system' repo
        printf "\nrepo %s\n    RW+     =   %s\n" "$fluxNamespace" "$fluxNamespace" >> "$gitoliteConfFile"
    fi
    if gitIsRepoUnchanged; then
        ssh-keygen -qt ed25519 -a 64 -P '' -C "$fluxNamespace" -f "$gitoliteFluxKeyFile"
        mv "$gitoliteFluxKeyFile.pub" "$gitoliteFluxPubKeyFile"
    fi
    if ! gitIsRepoUnchanged; then
        git add "$gitoliteConfFile" "$gitoliteFluxPubKeyFile"
        git commit -m 'added fluxcd'
        git push
    fi)

## phase 2.6 bootstrap FluxCD controllers and initial kustomization:

kubectl create namespace "$fluxBootNamespace"
kubectl -n "$fluxBootNamespace" create secret generic "$fluxNamespace" \
                                                      "--from-file=id_ecdsa=$gitoliteFluxKeyFile" \
                                                      "--from-literal=known_hosts=$k8sServerPubKey"
kubectl -n "$fluxBootNamespace" create serviceaccount "$fluxBootNamespace"
tee "${KIND_FLUXCD_BOOTSTRAP_DEBUG:-/dev/stderr}" <<-EOF | kubectl apply -f -
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: $fluxBootNamespace
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- apiGroup: ""
  kind: ServiceAccount
  name: $fluxBootNamespace
  namespace: $fluxBootNamespace

---
apiVersion: v1
kind: Pod
metadata:
  name: $fluxBootNamespace
  namespace: $fluxBootNamespace
spec:
  containers:
  - args:
    - '--path'
    - 'clusters/$clusterName'
    - '--private-key-file=/root/.ssh/id_ecdsa' # flux tries to start SSH agent if given no private key
    - '--timeout=${FLUX_BOOTSTRAP_TIMEOUT:-12m}'
    - '--url=ssh://git@$k8sSshSvcName:$opensshPort/$fluxNamespace'
    # flux aborts w/o error message if started w/o silent option!
    command: ['flux', 'bootstrap', 'git', '--silent', '--branch', 'master', '--interval', '1m']
    image: $gitosshImg
    imagePullPolicy: Never
    name: $fluxBootNamespace
    volumeMounts:
    - mountPath: /root/.ssh # mounting secret in home directory provides known_hosts file
      name: $fluxNamespace
  serviceAccount: $fluxBootNamespace
  volumes:
  - name: $fluxNamespace
    secret:
      defaultMode: 0400
      secretName: $fluxNamespace
EOF

kubectl -n "$fluxBootNamespace" wait --for=condition=ready pod "$fluxBootNamespace"
kubectl -n "$fluxBootNamespace" logs -f "$fluxBootNamespace"
fluxWaitForKustomization "$fluxNamespace"
kubectl delete namespace "$fluxBootNamespace"
fluxCloneCmd="$(gitolitePrintCloneCmd "$gitoliteFluxKeyFile" "$fluxNamespace" | base64 -w0)"
kubectl -n "$fluxNamespace" patch secret "$fluxNamespace" --type json \
        -p '[{"op": "add", "path": "/data/clone_command", "value": "'"$fluxCloneCmd"'"}]'

## phase 3.1 provision k8s metrics server via FluxCD kustomization:

fluxAddComponent metrics-server "$metricsServerUrl" 'Metrics Server' kube-system k8s-app=metrics-server \
					'patches:
					- target:
					    kind: Deployment
					    name: metrics-server
					  patch: |-
					    - op: add
					      path: "/spec/template/spec/containers/0/args/-"
					      value: "--kubelet-insecure-tls"'

## phase 3.2 optionally, provision ArgoCD GitOps toolkit via FluxCD kustomization:
if envTrueCheck "$KINDOFLUX_ARGO"; then
    kubectl create ns "$argoCdNamespace"
    fluxAddComponent argocd "$argoCdUrl" 'ArgoCD GitOps toolkit' "$argoCdNamespace" 'partOf=ArgoCD' \
					"commonLabels:
					  partOf: ArgoCD
					namespace: $argoCdNamespace # ArgoCD resources are not namespaced...
					patches:
					- target:
					    kind: Kustomization
					    name: argocd
					  patch: |-
					    - op: replace
					      path: '/metadata/namespace'
					      value: $fluxNamespace  # ... but namespace for kustomization must be that of Flux 
					- target:
					    kind: Service
					    name: argocd-server
					  patch: |-
					    - op: replace
					      path: '/spec/type'
					      value: NodePort
					    - op: add
					      path: '/spec/ports/1/nodePort'
					      value: $argocdNodePort"
fi

## phase 3.3 optionally, provision k8s-in-k8s via cluster API with vcluster provider (does not work due to VCluster 0.34.0 inconsistencies with kube-rbac-proxy):
if envTrueCheck "$KINDOFLUX_CLUSTERAPI"; then
    kubectl create ns "$clusterApiProviderNamespace"
    clusterctl init -v 10 --infrastructure vcluster --target-namespace "$clusterApiProviderNamespace" --wait-providers
    kubectl create ns "$clusterApiTestNamespace"
    fluxAddComponent "$clusterApiTestNamespace" '' 'k8s Cluster API' "$clusterApiTestNamespace" "partOf=$clusterApiTestNamespace" \
                     "$clusterApiEnvPatch" \
                     "export CLUSTER_NAME=$clusterName CLUSTER_NAMESPACE=$clusterApiProviderNamespace KUBERNETES_VERSION=$k8sVersion HELM_VALUES='$clusterApiHelmValues';
                      clusterctl generate cluster $clusterApiTestNamespace --target-namespace $clusterApiProviderNamespace --kubernetes-version $k8sVersion --control-plane-machine-count=1 --worker-machine-count=2 "
fi

## phase 4 clean up, show k8s pod status and print some useful commands for
#          interaction w/ cluster / FluxCD via gitolite / argocd CLI, using
#          the current parametrization:

rm -rf "$kindConfig" "$gitosshImgArchive" "$gitoliteAdminKeyFile.pub" "$gitoliteAdminClone" "$fluxCloneDir"

finishInfoExit $?
