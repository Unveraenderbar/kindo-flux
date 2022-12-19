
# kindo-flux

Just a shell script.  
The objective here is to build a play-ground for experimenting with the
[Flux 2][flux2] and [ArgoCD](ArgoCD) GitOps toolkits on a [kind][kind]
based [k8s][k8s] cluster. 
The resulting setup should
- be fully self-contained, i.e. include its own [git][git] repository service
- be reproducible and disposable infrastructure-as-code
- use [podman][podman] as base layer container runtime (Docker is considered
  deprecated)
- work at least on
    - up to date Fedora Linux (in reality, this means [SilverBlue][SilverBlue]
      due to its native support for podman)
    - and (within the limitations imposed by the outdated kernel of this
      platform) standard [WSL][WSL] installations

kindo-flux consists of:
- the main shell script
- an auxiliary interactive shell setup for managing kubectl
  [contexts][kubectl-contexts] in a read-only fashion
- an auxiliary shell script for adding packages and package repositories
  enabling the installation of podman on Ubuntu Focal based Linux systems
  (as this is the standard distribution for WSL instances)

**NOTE**: kindo-flux is intended to be only a development / proof-of-concept
helper tool – it is [shellcheck](shellcheck)ed, but that's about it with
respect to "production quality" SW.  So don't expect stuff like robust error
handling, modularization, easy extensibility etc..  
The result can be considered to large for implementation as a shell script,
and not very eye-friendly due to excessive parametrization and embedded YAML,
but OTOH it is linear in execution and straight-forward to understand.

**NOTE**: as Flux 2 is capable of bootstrapping and lifecycle-managing its own
installation into a cluster, and has only k8s and a git server as requirements
(while at least the argocd CLI needs an ingress), it is used for managing ArgoCD
as a service.

## Installation and usage
Download the main [script](<./master/kindo-flux.sh> "kindo-flux.sh"), make it
executable
```
chmod 0755 kindo-flux.sh
```
and execute it
```
./kindo-flux.sh
```
to install a cluster, which is named ```kind-k8s-<k8s-version>``` per default.
If you pass a command line argumend to the script, this will be used as the
cluster name.

**NOTE**: don't forget to tune host kernel parameters for serious container
workloads – esp. [inotify](inotify), but also (for ArgoCD) number of standard
open file descriptors per systemd user session / ulimit shell settings are
configured too low for running complex k8s cloud-native applicaions on many
mainstream Linux distributions, including Fedora and Ubuntu.

**NOTE**: when using a WSL instance as host system, kind has to be called with
superuser privileges, as at least the WSL default kernel as distributed by
Microsoft unfortunately does not support podman with rootless containers.  
However, this is not considered a showstopper as it's best practice to spin up
a dedicated WSL instance for the containerized k8s anyway.

<!--links-->
[ArgoCD]: https://argo-cd.readthedocs.io/en/stable/
[flux2]: https://github.com/fluxcd/flux2
[git]: https://github.com/gitolite/gitolite
[inotify]: https://kind.sigs.k8s.io/docs/user/known-issues/#pod-errors-due-to-too-many-open-files
[kind]: https://kind.sigs.k8s.io/docs/user/quick-start/
[k8s]: https://kubernetes.io/
[kubernetes-cluster-api-nested]: https://github.com/kubernetes-sigs/cluster-api-provider-nested/tree/main/docs
[podman]: https://github.com/kubernetes-sigs/kind
[SilverBlue]: https://silverblue.fedoraproject.org/
[shellcheck]: https://github.com/koalaman/shellcheck
[WSL]: https://learn.microsoft.com/en-us/windows/wsl/
