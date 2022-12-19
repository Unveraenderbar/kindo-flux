#!/bin/sh

# General kind-related parameters:
k8sVersion="${KIND_K8s_VERSION:-v1.26.0}"
kindImage="kindest/node:$k8sVersion"
clusterName="${1:-k8s-$k8sVersion}"
kindTmpDir="${TMPDIR:=/var/tmp}/$clusterName"
kindConfig="${2:-$kindTmpDir/kind-$k8sVersion.yaml}"
kubeConfig="${3:-$kindTmpDir/kubeconfig-$clusterName}"
kxDir="${XDG_CONFIG_HOME:-$HOME/.config}/kubectx"
sshKeyScanCmd="${KIND_SSH_KEYSCAN_CMD=ssh-keyscan -t ecdsa -p}"

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
gitoliteAdminKeyFile="${GITOSSH_ADMIN_KEY_FILE:-$kindTmpDir/gitolite.ecdsa}"
gitoliteAdminClone="${GITOLITE_ADMIN_CLONE:-$kindTmpDir/gitolite-admin}"
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
fluxVersion="${FLUX_VERSION:-0.37.0}"
fluxUrl="https://github.com/fluxcd/flux2/releases/download/v$fluxVersion/flux_${fluxVersion}_linux_amd64.tar.gz"
gitoliteFluxKeyFile="${GITOSSH_FLUX_KEY_FILE:-$kindTmpDir/$fluxNamespace.ecdsa}"
gitoliteFluxPubKeyFile="$gitoliteAdminClone/keydir/$fluxNamespace.pub"
fluxCloneDir="${KIND_FLUX_CLONE_DIR:-$kindTmpDir/$fluxNamespace}"

# ArgoCD related parameters:
argoCdNamespace="${KIND_FLUX_NAMESPACE:-argocd}"
argoCdVersion="${ARGOCD_VERSION:-stable}"
argoCdUrl="https://raw.githubusercontent.com/argoproj/argo-cd/$argoCdVersion/manifests/install.yaml"
argocdNodePort="$((${ARGOCD_NODE_PORT:-${nodePortPrefix}0333} + ${K8S_KIND_NODEPORT_OFFSET:-0}))"

vclusterNodePort="$((${VCLUSTER_NODE_PORT:-${nodePortPrefix}0444} + ${K8S_KIND_NODEPORT_OFFSET:-0}))"

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
    wget "-O$1-components.yaml" "$2"
    if ! gitIsRepoUnchanged; then
        git add .; git commit -m "Add $3 for kind manifests"; git push
    fi

    tee "$1-sync.yaml" <<-EOF
	apiVersion: kustomize.toolkit.fluxcd.io/v1beta2
	kind: Kustomization
	metadata:
	  labels:
	    kustomize.toolkit.fluxcd.io/name: $1
	    kustomize.toolkit.fluxcd.io/namespace: $fluxNamespace
	  name: $1
	  namespace: $fluxNamespace
	spec:
	  force: false
	  interval: 10m0s
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

ingressNamespace="${KIND_INGRESS_NAMESPACE:-ingress-nginx}"
ingressUrl="${KIND_INGRESS_DEPLOYMENT_URL:-https://raw.githubusercontent.com/kubernetes/ingress-nginx/main/deploy/static/provider/kind/deploy.yaml}"

metricsServerUrl="${KIND_METRICS_SERVER_DEPLOYMENT_URL:-https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml}"

## phase 0 prepare:

# see https://github.com/NixOS/nixpkgs/issues/36214 for summary and
# documentation hub:
inotifyMaxInstances="$(cat /proc/sys/fs/inotify/max_user_instances)"
[ "$inotifyMaxInstances" -ge 512 ] || {
    echo "Cannot provision ArgoCD, max. count $inotifyMaxInstances of inotify user instances too low for ArgoCD"
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

rm -rf "$kindTmpDir"; (umask 077; mkdir -p "$kindTmpDir")

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
            "apk update; apk upgrade; apk add ${GITOSSH_PKGS:-git perl gitolite}
             sed -i -e 's/ \(2222\)/ \${OPENSSH_PORT:-\1}/' /etc/s6-overlay/s6-rc.d/svc-openssh-server/run
             usermod -u $gitoliteUid -g $gitoliteGid $gitoliteUser
             wget -O- $fluxUrl | tar -oxzf - -C /usr/local/bin flux"
    buildah commit --rm "$gitosshName" "$gitosshImg"
fi
gitolitePwEntry="$(podman run --rm --entrypoint='' "$gitosshName" grep "^$gitoliteUser" /etc/passwd)"
gitoliteHomeDir="$(echo "$gitolitePwEntry" | cut -d: -f 6)"
gitosshImgArchive="$kindTmpDir/$(echo "$gitosshImg" | tr /: --)"
podman save "$gitosshImg" > "$gitosshImgArchive"

## phase 1.2 provision k8s / kind cluster w/ port-forwarding for ingress:

export KUBECONFIG="$kubeConfig" # kind tries to lock kubectl configuration
ingressHttpNodePort="${unprivilegedPort:+80}$((80  + ${K8S_KIND_NODEPORT_OFFSET:-0}))"
ingressHttpsNodePort="${unprivilegedPort:+8}$((443 + ${K8S_KIND_NODEPORT_OFFSET:-0}))"
tee "$kindConfig" <<-EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
name: $clusterName
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: InitConfiguration
    nodeRegistration:
      kubeletExtraArgs:
        node-labels: "ingress-ready=true"
  extraPortMappings:
  - containerPort: 80
    hostPort: $ingressHttpNodePort
    protocol: TCP
  - containerPort: 443
    hostPort: $ingressHttpsNodePort
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
               chown $gitoliteUid.$gitoliteGid $kubeConfig
               $kindCmd load image-archive $gitosshImgArchive --name=$clusterName $gitosshImg"
if [ -d "$kxDir" ] && [ -d "$kxDir/clusters" ] && [ -d "$kxDir/users" ] && command -v yq; then
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

## phase 2.3 instantiate FluxCD base git repository:

rm -rf "$gitoliteAdminClone" "$gitoliteFluxKeyFile" "$gitoliteFluxPubKeyFile"
# shellcheck disable=SC2030,SC2031
(export GIT_SSH_COMMAND="$gitoliteSSHCmd $gitoliteAdminKeyFile"
    git clone "$gitoliteLocalBaseUrl/gitolite-admin" "$gitoliteAdminClone"
    cd "$gitoliteAdminClone"
    if ! grep -q "^repo $fluxNamespace" "$gitoliteConfFile"; then # flux bootstrap expects 'flux-system' repo
        printf "\nrepo %s\n    RW+     =   %s\n" "$fluxNamespace" "$fluxNamespace" >> "$gitoliteConfFile"
    fi
    if [ ! -r "$gitoliteFluxKeyFile" ] || [ ! -r "$gitoliteFluxPubKeyFile" ] ; then
        ssh-keygen -qt ed25519 -a 64 -P '' -C "$fluxNamespace" -f "$gitoliteFluxKeyFile"
        mv "$gitoliteFluxKeyFile.pub" "$gitoliteFluxPubKeyFile"
    fi
    if ! gitIsRepoUnchanged; then
        git add "$gitoliteConfFile" "$gitoliteFluxPubKeyFile"
        git commit -m 'added fluxcd'
        git push
    fi)

## phase 2.4 bootstrap FluxCD controllers and initial kustomization:

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
    command: ['flux', 'bootstrap', 'git', '--silent', '--branch', 'master']
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


## phase 3.1 provision NGINX ingress via FluxCD kustomization:

fluxAddComponent "$ingressNamespace" "$ingressUrl" 'NGINX Ingress' "$ingressNamespace" \
                 'app.kubernetes.io/component=controller,app.kubernetes.io/instance=ingress-nginx' \
					'patchesJSON6902:
					- target:
					    kind: ConfigMap
					    name: ingress-nginx-controller
					  patch: |-
					    - op: add
					      path: "/data/worker-processes"
					      value: "2"'

## phase 3.2 provision k8s metrics server via FluxCD kustomization:

fluxAddComponent metrics-server "$metricsServerUrl" 'Metrics Server' kube-system k8s-app=metrics-server \
					'patchesJSON6902:
					- target:
					    kind: Deployment
					    name: metrics-server
					  patch: |-
					    - op: add
					      path: "/spec/template/spec/containers/0/args/-"
					      value: "--kubelet-insecure-tls"'

## phase 3.3 provision ArgoCD GitOps toolkit via FluxCD kustomization:
kubectl create ns "$argoCdNamespace"
fluxAddComponent argocd "$argoCdUrl" 'ArgoCD GitOps toolkit' "$argoCdNamespace" 'partOf=ArgoCD' \
					"commonLabels:
					  partOf: ArgoCD
					namespace: $argoCdNamespace # ArgoCD resources are not namespaced...
					patchesJSON6902:
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

## phase 4 clean up, show k8s pod status and print some useful commands for
#          interaction w/ cluster / FluxCD via gitolite / argocd CLI, using
#          the current parametrization:

kubectl -n "$ingressNamespace" delete job ingress-nginx-admission-create ingress-nginx-admission-patch 
rm -rf "$kindConfig" "$gitosshImgArchive" "$gitoliteAdminKeyFile.pub" "$gitoliteAdminClone" "$fluxCloneDir"
set +x

kubectl get pod -A
# shellcheck disable=SC2059
printf "\nexport KUBECONFIG='%s'\n" "$kubeConfig"
gitolitePrintCloneCmd "$gitoliteAdminKeyFile" gitolite-admin
gitolitePrintCloneCmd "$gitoliteFluxKeyFile"  "$fluxNamespace"
echo "argocd login localhost:$argocdNodePort --insecure --username admin --password \"\$(kubectl -n $argoCdNamespace get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d)\""
