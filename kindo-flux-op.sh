#!/bin/bash

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
fluxVersion="${FLUX_VERSION:-2.9.2}"
fluxUrl="${GITHUB_PROXY_URL:-https://github.com}/fluxcd/flux2/releases/download/v$fluxVersion/flux_${fluxVersion}_linux_amd64.tar.gz"
gitoliteFluxKeyFile="${GITOSSH_FLUX_KEY_FILE:-$KIND_TMP_DIR/$fluxNamespace.ecdsa}"
gitoliteFluxPubKeyFile="$gitoliteAdminClone/keydir/$fluxNamespace.pub"

fluxWaitForKustomization() {
    kubeCtl() { kubectl -n "$fluxNamespace" "$@"; }
    kubeWait() { kubeCtl wait kustomization --timeout="${KIND_KUSTOMIZATION_WAIT_TIMEOUT:-4m}" "$@"; }
    while ! kubeCtl get kustomization "$1" -o 'jsonpath={.status.observedGeneration}'; do sleep "${2:-2}"; done
    kubeWait "$1" --for='jsonpath={.status.observedGeneration}=1' # can be -1 while kustomization is uninitialized
    kubeWait "$1" --for='jsonpath={.status.conditions[0].reason}=ReconciliationSucceeded'
    kubectl get -A gitrepositories,kustomizations
}

istioNamespace="${KIND_CONTOUR_NAMESPACE:-istio-system}"
istioIngressGateway='ingress-gateway'

export HELM_CACHE_HOME="$KIND_TMP_DIR/.cache/helm" HELM_CONFIG_HOME="$KIND_TMP_DIR/.config/helm"
zotChartUrl="${ZOT_HELM_CHART_URL:-oci://ghcr.io/project-zot/helm-charts/zot}"
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
    echo "export KIND_TMP_DIR=$KIND_TMP_DIR"
    exit "$1"
}

## phase 0 prepare:

# see https://github.com/NixOS/nixpkgs/issues/36214 for summary and documentation hub:
inotifyMaxInstances="$(cat /proc/sys/fs/inotify/max_user_instances)"
[ "$inotifyMaxInstances" -ge 512 ] || {
    echo "Max. count $inotifyMaxInstances of inotify user instances too low, aborting" 1>&2
    echo "Run \"sudo sysctl fs.inotify.max_user_instances=8192\" for correction" 1>&2
    exit 1
}
lsmod | awk '$1 == "ip_tables" {exit 0}' || {
    echo "Cannot provision ingress controllers as IP tables kernel module not loaded, aborting" 1>&2
    exit 1
}

set -euxo pipefail
kindPath="$(command -v kind)"
[ -n "$kindPath" ] || exit 1
kindCmd="KIND_EXPERIMENTAL_PROVIDER=podman $kindPath"

if [ -n "$(mount -lt cgroup)" ]; then
    sudo='sudo'             # WSL messed-up/outdated cgroups, cannot run rootless
else
    sudo=''
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
    ${https_proxy:+buildah config --env https_proxy="$https_proxy" "$gitosshName"}
    # have to make port in sshd configuration runtime-parametrizable in case we install w/ offset!
    buildah run "$gitosshName" sh -exc \
            "apk update; apk upgrade; apk add ${GITOSSH_PKGS:-git perl gitolite openssl}
             sed -i -e 's/ \(2222\)/ \${OPENSSH_PORT:-\1}/' /etc/s6-overlay/s6-rc.d/svc-openssh-server/run
             usermod -u $gitoliteUid -g $gitoliteGid $gitoliteUser
             curl -sk $fluxUrl | tar -oxzf - -C /usr/local/bin flux
             curl -sk $kubectlUrl >  /usr/bin/kubectl
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
$(seq 1 "${KIND_NUM_NODES:-2}" | xargs -rn1 sh -c "printf -- \"- role: worker\n\"")
EOF
$sudo sh -exc "$kindCmd delete cluster --name $clusterName || true
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
helm install -n "$zotNamespace" zot "$zotChartUrl" --set 'persistence=true' --set 'pvc.storage=20Gi' --set 'pvc.storageClassName=standard'
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
envTrueCheck "${KINDOFLUX_ONLY_K8S:-}" && finishInfoExit $status

## phase 2.4 instantiate Flux D2 reference architecture
## https://fluxcd.control-plane.io/guides/d2-architecture-reference/

set +ex # bash's read builtin returns != 0, pause exit on error for variable initialization

fluxOrg='controlplaneio-fluxcd'
fluxPush='flux push artifact --verbose --debug --insecure-registry'
localDomain="${LOCAL_DOMAIN:-localhost}"
localRegistry="$localDomain:${LOCAL_REGISTRY_PORT:-30080}"
clusterRegistry="${CLUSTER_REGISTRY:-zot.zot:5000}"
fleetRepoDir="${FLEET_REPO_DIR:-d2-fleet}"
fluxNamespace="${FLUX_NAMESPACE:-flux-system}"
fluxStageDir="${FLUX_STAGE:-clusters/staging}"
fluxNamespaceDir="$fleetRepoDir/$fluxStageDir/$fluxNamespace"
fleetTransformersDir="$fleetRepoDir/transformers"
operatorChart="$fluxOrg/charts/flux-operator"
remoteRegistryHost="${REMOTE_REGISTRY_HOST:-ghcr.io}"
remoteRegistry="$remoteRegistryHost/$fluxOrg"
localFleetUrl="$localRegistry/$fluxOrg/$fleetRepoDir"

appsRepoDir="${APPS_REPO_DIR:-d2-apps}"
appsCompDir="$appsRepoDir/components"
localAppsBackendUrl="$localRegistry/$fluxOrg/$appsRepoDir/backend"
localAppsFrontendUrl="$localRegistry/$fluxOrg/$appsRepoDir/frontend"
infraRepoDir="${INFRA_REPO_DIR:-d2-infra}"
infraCompDir="$infraRepoDir/components"
localInfraCertManagerUrl="$localRegistry/$fluxOrg/$infraRepoDir/cert-manager"
localInfraMonitoringUrl="$localRegistry/$fluxOrg/$infraRepoDir/monitoring"

IFS='' read -r -d '' fluxRegistryTranformers <<-EOF
---
apiVersion: kustomize.config.k8s.io/v1alpha1
kind: Component

replacements:
- sourceValue: $clusterRegistry
  targets:
  - select:
      kind: FluxInstance
    fieldPaths:
    - spec.sync.url
    options:
      delimiter: /
      index: 2
  - select:
      kind: ResourceSet
      name: apps|flux-operator|infra
    fieldPaths:
    - spec.resources.[kind=OCIRepository].spec.url
    options:
      delimiter: /
      index: 2
EOF

IFS='' read -r -d '' airGapPatch <<-EOF
transformers:
- |-
  apiVersion: builtin
  kind: ReplacementTransformer
  metadata:
    name: registryProxyReplacement
  replacements:
  - sourceValue: $clusterRegistry
    targets:
    - select:
        kind: OCIRepository
      fieldPaths:
      - spec.url
      options:
        delimiter: /
        index: 2
patches:
- patch: |-
    apiVersion: source.toolkit.fluxcd.io/v1
    kind: OCIRepository
    metadata:
      name: irrelevant-here
    spec:
      insecure: true
  target:
    kind: OCIRepository
EOF

IFS='' read -r -d '' fluxInstancePatch <<-EOF
components:
- ../../../transformers
patches:
- patch: '[  {"op": "remove", "path": "/spec/sync/pullSecret"      }
           , {"op": "remove", "path": "/spec/distribution/artifact"}]'
  target:
    kind: FluxInstance
    name: flux
- patch: |-
    - op: replace
      path: /spec/kustomize/patches/0
      value:
        patch: |
          - op: add
            path: /spec/insecure
            value: true
        target:
          kind: OCIRepository
          name: flux-(operator|system)
  target:
    kind: FluxInstance
    name: flux
- patch: |-
    - op: remove
      path: /spec/resources/0/spec/verify
  target:
    kind: ResourceSet
    name: flux-operator
- patch: |-
    - op: replace
      path: /data/CLUSTER_DOMAIN
      value: $localDomain
  target:
    kind: ConfigMap
    name: flux-runtime-info

replacements:
- source:
    fieldPath: spec.cluster.multitenant
    kind: FluxInstance
    name: flux
  targets:
  - select:
      kind: ResourceSet
      name: flux-(operator|system)
    fieldPaths:
    - spec.resources.[kind=OCIRepository].spec.insecure
    options:
      create: true
EOF

IFS='' read -r -d '' fluxStagingPatch <<-EOF
patches:
- patch: |-
    - op: add
      path: /spec/components
      value: [../transformers]
  target:
    kind: Kustomization
    name: tenants
EOF

IFS='' read -r -d '' fluxTenantsPatch <<-EOF
components:
- ../transformers

patches:
- patch: '[  {"op": "remove", "path": "/spec/resources/3/imagePullSecrets"}
           , {"op": "remove", "path": "/spec/resources/5/spec/verify"     }
           , {"op": "remove", "path": "/spec/resources/2"                 }]'
  target:
    kind: ResourceSet
    name: apps|infra

replacements:
- source:
    fieldPath: spec.dependsOn.0.ready
    kind: ResourceSet
    name: infra
  targets:
  - select:
      kind: ResourceSet
      name: apps|infra
    fieldPaths:
    - spec.resources.[kind=OCIRepository].spec.insecure
    options:
      create: true
- sourceValue: oci://$clusterRegistry/$fluxOrg/${remoteRegistryProxy:-} oci://$clusterRegistry/bitnamicharts/redis oci://$clusterRegistry/stefanprodan/charts/podinfo oci://$clusterRegistry/bitnamicharts/memcached
  targets:
  - select:
      kind: ResourceSet
      name: policies
    fieldPaths:
    - spec.resources.[kind=ConfigMap].data.sources
    options:
      create: true
      delimiter: ' '
      index: 9999
- sourceValue: 18m
  targets:
  - select:
      kind: ResourceSet
      name: infra
    fieldPaths:
    - spec.resources.[kind=Kustomization].spec.timeout
    options:
      create: true
EOF

IFS='' read -r -d '' infraHelmReleasePatch <<-EOF # Grafana deployment lets infra-controllers HelmRelease CR fail reproducibly
replacements:
- sourceValue: 18m
  targets:
  - select:
      kind: HelmRelease
    fieldPaths:
    - spec.install.timeout
    - spec.upgrade.timeout
    options:
      create: true
- sourceValue: RetryOnFailure
  targets:
  - select:
      kind: HelmRelease
    fieldPaths:
    - spec.install.strategy.name
    - spec.upgrade.strategy.name
    options:
      create: true
EOF

_localCopy() {
    local tag="${2:-latest}"
    # shellcheck disable=SC2001 # need non-greedy RE, bash does not have these
    skopeo copy --dest-tls-verify=false "docker://$1:$tag" "docker://$(echo "$1" | sed s#[^/]*#"$localRegistry"#):$tag"
}

_chartCopy() { # extract all OCIRepository CRs from Kustomization directories, and copy them to our local registry:
    local yqExpr='select(.kind == "OCIRepository") | .spec | .url + " " + (.ref.tag // .ref.semver // "latest")'
    for dir in "$@"; do
        kustomize build "$dir" | yq eval-all -N "$yqExpr" | while read -r chart tag; do
            _localCopy "${chart##oci://}" "$tag"
        done
    done
}

_autoKustomizate() {
    (cd "$1"; kustomize create --autodetect --recursive)
    cat >> "$1/kustomization.yaml"
}

set -ex

## phase 2.4.1 prepare Flux ControlPlane OCI images patched for Kind / air-gapped platform:

# emulate pseudo-air-gap for reference architecture OCI artifacts (other artifacts/images are still pulled from GitHub registry):
_localCopy "$remoteRegistryHost/$operatorChart" "${OPERATOR_CHART_VERSION:-0.55.0}"
_localCopy "$remoteRegistry/flux-operator-manifests"

#_localCopy "$remoteRegistry/$fleetRepoDir"              # transformed below...
#_localCopy "$remoteRegistry/$infraRepoDir/cert-manager" # ... to local OCI registry ...
#_localCopy "$remoteRegistry/$infraRepoDir/monitoring"   # ... via git repo instead
#_localCopy "$remoteRegistry/$appsRepoDir/backend"
#_localCopy "$remoteRegistry/$appsRepoDir/frontend"

[ -n "${KIND_TMP_DIR:-}" ] && cd "$KIND_TMP_DIR"

## phase 2.4.1.1 prepare&push Flux ControlPlane D2 reference architecture fleet repo
rm -rf "$fleetRepoDir"; git clone "https://github.com/$fluxOrg/$fleetRepoDir"
mkdir -p "$fleetTransformersDir"
cat >            "$fleetTransformersDir/kustomization.yaml" <<<"$fluxRegistryTranformers"
cat >>           "$fluxNamespaceDir/kustomization.yaml"     <<<"$fluxInstancePatch"
_autoKustomizate "$fleetRepoDir/$fluxStageDir"              <<<"$fluxStagingPatch"
_autoKustomizate "$fleetRepoDir/tenants"                    <<<"$fluxTenantsPatch"
(cd "$fluxNamespaceDir"; git add .; git commit -m 'chore: add patch for localizing fleet OCI registry')

fleetGitRev="$(cd "$fleetRepoDir" && printf '%s-%s' "$(git branch --show-current)" "$(git rev-parse HEAD)")"
$fluxPush "--revision=$fleetGitRev" "oci://$localFleetUrl" \
          --path "$fleetRepoDir" --source "https://$localFleetUrl"

## phase 2.4.1.2 prepare&push Flux ControlPlane D2 reference architecture infra repo
rm -rf "$infraRepoDir"; git clone "https://github.com/$fluxOrg/$infraRepoDir"
_chartCopy "$infraCompDir/cert-manager/controllers/staging" "$infraCompDir/monitoring/controllers/staging"
cat >> "$infraCompDir/cert-manager/controllers/base/kustomization.yaml" <<<"$infraHelmReleasePatch"
cat >> "$infraCompDir/monitoring/controllers/base/kustomization.yaml"   <<<"$infraHelmReleasePatch"
cat >> "$infraCompDir/cert-manager/controllers/base/kustomization.yaml" <<<"$airGapPatch"
cat >> "$infraCompDir/monitoring/controllers/base/kustomization.yaml"   <<<"$airGapPatch"
(cd "$infraRepoDir"; git add .; git commit -m 'chore: add patch for infra HelmRelease and OCIRepository CRs')

infraGitRev="$(cd "$infraRepoDir" && printf '%s-%s' "$(git branch --show-current)" "$(git rev-parse HEAD)")"
$fluxPush "--revision=$infraGitRev" "oci://$localInfraCertManagerUrl" \
          --source "https://$localInfraCertManagerUrl" --path "$infraCompDir/cert-manager"
$fluxPush "--revision=$infraGitRev" "oci://$localInfraMonitoringUrl" \
          --source "https://$localInfraMonitoringUrl" --path "$infraCompDir/monitoring"

## phase 2.4.1.3 prepare&push Flux ControlPlane D2 reference architecture apps repo
rm -rf "$appsRepoDir"; git clone "https://github.com/$fluxOrg/$appsRepoDir"
_chartCopy "$appsCompDir/backend/staging" "$appsCompDir/frontend/staging"
cat >> "$appsCompDir/backend/base/kustomization.yaml"  <<<"$airGapPatch"
cat >> "$appsCompDir/frontend/base/kustomization.yaml" <<<"$airGapPatch"
(cd "$appsRepoDir"; git add .; git commit -m 'chore: add patch for redirecting apps repo OCIRepository CRs to proxy')

appsGitRev="$(cd "$appsRepoDir" && printf '%s-%s' "$(git branch --show-current)" "$(git rev-parse HEAD)")"
$fluxPush "--revision=$appsGitRev" "oci://$localAppsBackendUrl" \
          --source "https://$localAppsBackendUrl" --path "$appsCompDir/backend"
$fluxPush "--revision=$appsGitRev" "oci://$localAppsFrontendUrl" \
          --source "https://$localAppsFrontendUrl" --path "$appsCompDir/frontend"

## phase 2.4.2 bootstrap Flux ControlPlane operator via Helm
kubectl create namespace "$fluxNamespace"
kubectl label namespace "$fluxNamespace" 'istio-injection=enabled'
helm delete  -n "$fluxNamespace" --wait --cascade orphan --ignore-not-found flux-operator # try to act idempotent
helm install -n "$fluxNamespace" --wait --plain-http --create-namespace --replace \
             -f "$fleetRepoDir/$fluxStageDir/$fluxNamespace/flux-operator-values.yaml" \
             flux-operator "oci://$localRegistry/$operatorChart"

## phase 2.4.3 bootstrap Flux ControlPlane FluxInstance CR patched for Kind
kubectl -n "$fluxNamespace" apply -k "$fluxNamespaceDir" -o 'jsonpath={.items[?(@.kind=="FluxInstance")]}' | jq .spec
kubectl -n "$fluxNamespace" wait fluxinstance/flux --for=condition=Ready --timeout=15m

## phase 2.4.4 expose Flux operator web UI via Istio
tee "${KIND_GITOLITE_DEPLOY_DEBUG:-/dev/stderr}" <<-EOF | kubectl -n "$fluxNamespace" apply -f -
apiVersion: networking.istio.io/v1
kind: VirtualService
metadata:
  name: flux-web
spec:
  hosts:
  - '*'
  gateways:
  - $istioNamespace/$istioIngressGateway-https
  http:
  - route:
    - destination:
        host: flux-operator
        port:
          number: 9080
EOF
