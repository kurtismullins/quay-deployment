#
#                          Deploy a fully functioning Quay registry
#
# TODO: Change certain configuration options such as the namespace into variables and use them
#       in the commands executed.
#
# TODO: The hostname should be dynamically determined (or specified) and used in the following:
#       - The generated certificate
#       - Quay's config.yaml
#       - Quay's Route
#

# Require a namespace to be specified explicitly
if [ "$#" -ne 1 ]
then
  echo "Usage: setup.sh <namespace>"
  exit 1
fi

NAMESPACE=$1
echo "Beginning Quay deployment to namespace $NAMESPACE"
echo

echo "Creating Quay's Route in $NAMESPACE"
oc create --namespace=$NAMESPACE -f quay.route.yaml
echo

echo "Creating Quay's Service in $NAMESPACE"
oc create --namespace=$NAMESPACE -f quay.service.yaml
echo

echo "Deploying MySQL 5.7 to $NAMESPACE"
oc create --namespace=$NAMESPACE -f mysql57.yaml
echo

echo "Deploying Redis to $NAMESPACE"
oc create --namespace=$NAMESPACE -f redis.yaml
echo

echo "Creating Quay's Role"
oc create --namespace=$NAMESPACE -f quay.role.yaml
echo

echo "Creating Quay's Role Binding"
oc create --namespace=$NAMESPACE -f quay.rolebinding.yaml
echo

echo "Fetching Quay's URL"
QUAY_HOST=$(oc get routes --namespace=$NAMESPACE --field-selector metadata.name==quay -o jsonpath="{.items[0].spec.host}")
echo "Quay's hostname is $QUAY_HOST"
echo

echo "Generating certificate for TLS"
echo "Note: Requires openssl >= 1.1.1"
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout ssl.key -out ssl.cert -subj "/CN=$QUAY_HOST" \
  -addext "subjectAltName=DNS:$QUAY_HOST,DNS:$QUAY_HOST"
echo

echo "Verifying certificate"
openssl x509 -noout -text -in ssl.cert
echo

# TODO: modify config.yaml with hostname. update config.secret.yaml with base64 of the following:
# - config.yaml
# - ssl.cert
# - ssl.key

echo "Creating Quay's configuration secret in $NAMESPACE"
oc create --namespace=$NAMESPACE -f config.secret.yaml
echo

echo "Creating the Red Hat Pull Secret in $NAMESPACE"
oc create --namespace=$NAMESPACE -f redhat-pull-secret.yaml
echo

echo "-------------------------------------------"
echo "Giving MySQL and Redis 120 seconds to start"
echo "-------------------------------------------"
sleep 120
echo

echo "Deploying Quay for the purpose of creating the database tables in $NAMESPACE"
echo "NOTE: The pod will fail after this step. A User must be created manually for Quay 3.3."
oc create --namespace=$NAMESPACE -f quay.yaml
echo

echo "-----------------------------------------------------------------"
echo "Waiting 180 seconds for Quay to start and run database migrations"
echo "-----------------------------------------------------------------"
sleep 180
echo

echo "Deleting Quay deployment in $NAMESPACE"
oc delete --namespace=$NAMESPACE -f quay.yaml
echo

echo "Fetching name of MySQL 5.7 Pod in $NAMESPACE"
POD=$(oc get pod --namespace=$NAMESPACE -l app=mysql57 -o jsonpath="{.items[0].metadata.name}")
echo "MySQL Pod: $POD"
echo

echo "Creating the User 'admin' with password 'password'"
oc exec -it --namespace=$NAMESPACE $POD -- /opt/rh/rh-mysql57/root/usr/bin/mysql \
    --user=root quay -e 'INSERT INTO user (username, email, password_hash, verified, uuid, organization, robot, invoice_email, last_invalid_login) VALUES ( "admin", "example@example.com", "$2a$12$VGiU60jGp1JtJXd9SLw6EucbYlAbGbLX2EJTgrSp8KofKTu4jfCNC", 1, "00ccf29c-704a-414e-9c14-54e490f08382", 0, 0, 0, "2020-01-01");'
echo

echo "Setting MySQL max_connections to 4096"
oc exec -it --namespace=$NAMESPACE $POD -- /opt/rh/rh-mysql57/root/usr/bin/mysql \
    --user=root quay -e 'set global max_connections = 4096;'
echo

echo "Deploying Quay to $NAMESPACE"
oc create --namespace=$NAMESPACE -f quay.yaml
echo

echo "Quay should be available at https://$QUAY_HOST after 60 seconds."