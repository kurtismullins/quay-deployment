# Tear down a cluster which was deployed using setup.sh

# Require a namespace to be specified explicitly
if [ "$#" -ne 1 ]
then
  echo "Usage: setup.sh <namespace>"
  exit 1
fi

NAMESPACE=$1
echo "Removing Quay deployment from namespace: $NAMESPACE"

oc delete --namespace=$NAMESPACE -f quay.yaml
oc delete --namespace=$NAMESPACE -f mysql57.yaml
oc delete --namespace=$NAMESPACE -f redis.yaml
oc delete --namespace=$NAMESPACE -f config.secret.yaml
oc delete --namespace=$NAMESPACE -f redhat-pull-secret.yaml
oc delete --namespace=$NAMESPACE -f quay.route.yaml
oc delete --namespace=$NAMESPACE -f quay.service.yaml
oc delete --namespace=$NAMESPACE -f quay.role.yaml
oc delete --namespace=$NAMESPACE -f quay.rolebinding.yaml