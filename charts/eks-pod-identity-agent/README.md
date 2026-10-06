# EKS Pod Identity Agent

This chart installs the `eks-pod-identity-agent`.
This agent is required for EKS pods to get granular IAM permissions with EKS Pod Identity feature.

## Prerequisites

- Kubernetes v{?} running on AWS
- Helm v3

## Update below Env to your cluster and region in values.yaml

* `EKS_CLUSTER_NAME` 
* `AWS_REGION_NAME`

## Installing the Chart

```shell
git clone https://github.com/aws/eks-pod-identity-agent.git
cd eks-pod-identity-agent/
helm install eks-pod-identity-agent --namespace kube-system ./charts/eks-pod-identity-agent --values ./charts/eks-pod-identity-agent/values.yaml
```

To uninstall:

```shell
helm uninstall eks-pod-identity-agent --namespace kube-system
```

## Configuration

The following table lists the configurable parameters for this chart and their default values.

| Parameter                 | Description                                             | Default                  |
|---------------------------|---------------------------------------------------------|--------------------------|
| `affinity`                | Map of node/pod affinities                              | (see `values.yaml`)      |
| `agent.additionalArgs`    | Additional arguments to pass to the agent-container     | (see `values.yaml`)      |
| `env`                     | List of environment variables.                          | (see `values.yaml`)      |
| `fullnameOverride`        | Override the fullname of the chart                      | `eks-pod-identity-agent` |
| `image.pullPolicy`        | Container pull policy                                   | `Always`                 |
| `imagePullSecrets`        | Docker registry pull secret                             | `[]`                     |
| `init.additionalArgs`     | Additional arguments to pass to the init-container      | (see `values.yaml`)      |
| `init.create`             | Specifies whether init-container should be created      | `true`                   |
| `nameOverride`            | Override the name of the chart                          | `eks-pod-identity-agent` |
| `nodeSelector`            | Node labels for pod assignment                          | `{}`                     |
| `podAnnotations`          | annotations to add to each pod                          | `{}`                     |
| `priorityClassName`       | Name of the priorityClass                               | `system-node-critical`   |
| `resources`               | Resources for containers in pod                         | `{}`                     |
| `tolerations`             | Optional deployment tolerations                         | `all`                    |
| `updateStrategy`          | Optional update strategy                                | `type: RollingUpdate`    |

Specify each parameter using the `--set key=value[,key=value]` argument to `helm install` or provide a YAML file
containing the values for the above parameters.

## Workload identity CSI driver

The chart installs a cluster-scoped `CSIDriver` named `spiffe.csi.eks.amazonaws.com`, served by
the agent's node service. It publishes the workload identity socket into pods the EKS Pod
Identity webhook has enrolled.

There is no values knob for it. This chart is what the EKS managed add-on installs, so it is
always the owner of the object, and a customer should not need a flag to get a working agent. On
a cluster not using workload identity the object is inert: only enrolled pods mount the driver,
so an unused declaration changes no pod. It is not rendered in isolated regions, where workload
identity is not enabled.

The object must exist before the agent can mint a token. Kubernetes 1.33's
`ServiceAccountNodeAudienceRestriction` only lets a node identity mint a ServiceAccount token for
an audience the target pod already references, either through a projected `serviceAccountToken`
volume or through the `tokenRequests` of a CSI driver the pod mounts. Enrolled pods mount this
driver, so this one declaration makes the agent's `TokenRequest` permissible fleet-wide with no
change to any pod spec. As a side effect, kubelet mints a token for that audience on every
publish and passes it in the volume context; the node service ignores it and the agent mints its
own, bound to the pod.

### Node plugin mounts and privilege

The agent container mounts three kubelet directories plus the socket directory, and each
`mountPath` must equal its host path. The endpoint the plugin reports at registration is opened
by the kubelet in the host mount namespace but bound by the agent in its own, so the two views
have to agree on the path.

`/var/lib/kubelet/pods` is mounted with `mountPropagation: Bidirectional`, which is what forces
`privileged: true` on the container. The agent makes its bind mount in its own mount namespace
and the kubelet has to see it in the host's; with any weaker propagation the publish succeeds,
the kubelet finds an empty directory, and the pod starts with no socket. Kubernetes only permits
Bidirectional on a privileged container, and `CAP_SYS_ADMIN` alone is not enough — the
propagation check is not capability-based.

The `hostPath` types differ on purpose. The socket directory and the two CSI plugin directories
are `DirectoryOrCreate`, since on a first boot nothing else creates them. `/var/lib/kubelet/pods`
is a strict `Directory`: the kubelet creates it on any node that runs pods, so its absence means
the kubelet root is somewhere else and publishing there would write into a directory nothing
reads.

The socket directory is a `hostPath` rather than an `emptyDir` so that it outlives the agent pod.
An `emptyDir` is tied to the pod instance, and a restart would invalidate every bind mount
already published into running workloads.

### Updating the object

Re-applying the object on a later add-on update is a no-op. `attachRequired` and
`podInfoOnMount` are immutable after creation, so a future version wanting different values for
those two must delete and recreate the object. `tokenRequests`, `volumeLifecycleModes` and
`fsGroupPolicy` can be changed in place.
