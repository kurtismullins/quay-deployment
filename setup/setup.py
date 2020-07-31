"""
Written by Kurtis Mullins on July 7th, 2020.
Last modified: July 9th, 2020.

The purpose of this script is to provision Red Hat Quay on Openshift for the purpose of load and
performance testing. The goal of this work is to easily allow the provisioning and tear-down of
various combinations of Quay, MySQL, and Postgres versions.
"""

import argparse
import base64
import logging
import sys

import yaml

from kubernetes import client, config
from kubernetes.stream import stream
from openshift.dynamic import DynamicClient
from OpenSSL import crypto, SSL


__VERSION__ = "0.0.1"


logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)


class Base:
    """
    Provides methods to deploy to Openshift or Kubernetes.

    This should only encapsulate generic logic. Any logic specific to a particular component should
    be included in that component's class.

    NOTE: Some trivial steps are broken out into their own methods so they can be overridden as
          needed for more complex component deployments.
    """

    # Infrastructure
    image = None
    namespace = None
    container_ports = None
    replicas = 1  # Sane default
    app_label = None
    service_port = None

    # Application
    env_vars = {}

    def __init__(self, image=None, namespace=None, container_ports=None, app_label=None):
        """
        Initialize the class and ensure everything is available that is required for deployment.
        """
        self.image = image or self.image
        self.namespace = namespace or self.namespace
        self.container_ports = container_ports or self.container_ports
        self.app_label = app_label or self.app_label

        if not self.image:
            raise Exception("No image specified")

        if not self.namespace:
            raise Exception("No namespace specified")

        if not self.app_label:
            raise Exception("No app label specified")

        if not self.container_ports:
            raise Exception("No container port(s) specified")

        if not self.service_port and len(self.service_port) != 2:
            raise Exception("No port has been specified for the Service.")

    def deploy(self, apps_v1_api, core_v1_api):
        """
        Deploy every needed resource for this particular component.
        """
        # Deployment
        deployment = self.create_deployment()
        apps_v1_api.create_namespaced_deployment(namespace=self.namespace, body=deployment)
        logger.info("Created Deployment: %s", self.app_label)

        # Service
        service = self.create_service()
        core_v1_api.create_namespaced_service(namespace=self.namespace, body=service)
        logger.info("Created Service: %s", self.app_label)

    def teardown(self, apps_v1_api, core_v1_api):
        """
        Removes every resources created during the deployment of this component.
        """
        # Deployment
        try:
            apps_v1_api.delete_namespaced_deployment(
                name=self.app_label,
                namespace=self.namespace,
                body=client.V1DeleteOptions(
                    propagation_policy='Foreground',
                    grace_period_seconds=30
                )
            )
            logger.info("Deleted Deployment: %s" % self.app_label)
        except client.rest.ApiException:
            logger.exception("Unable to delete Deployment: '%s'. Skipping.", self.app_label)

        # Service
        try:
            core_v1_api.delete_namespaced_service(
                name=self.app_label,
                namespace=self.namespace,
                body=client.V1DeleteOptions(
                    propagation_policy='Foreground',
                    grace_period_seconds=30
                )
            )
            logger.info("Deleted Service: %s" % self.app_label)
        except client.rest.ApiException:
            logger.exception("Unable to delete Service: '%s'. Skipping.", self.app_label)

    def create_role(self):
        """ Create a Role. """
        raise NotImplementedError()

    def create_volume_mounts(self):
        """
        Returns a list of Volumes which should be mounted by the container.
        """
        return []

    def create_container(self):
        """
        Create the Container definition.
        """
        volume_mounts = self.create_volume_mounts()

        # Ports must be a list of client.V1ContainerPort objects
        ports = [client.V1ContainerPort(container_port=port) for port in self.container_ports]

        # Environment Variables must be a list of V1EnvVar objects
        env = [client.V1EnvVar(name=key, value=str(value)) for key, value in self.env_vars.items()]

        container = client.V1Container(
            name="deployment",
            image=self.image,
            image_pull_policy="Always",
            ports=ports,
            env=env,
            volume_mounts=volume_mounts,
        )

        return container

    def create_template_metadata(self):
        metadata = client.V1ObjectMeta(labels={"app": self.app_label})
        return metadata

    def create_pull_secrets(self):
        return []

    def create_template_volumes(self):
        """
        Returns all Volumes used in a Deployment's templates.
        """
        return []

    def create_deployment_template_spec(self):
        volumes = self.create_template_volumes()
        container = self.create_container()
        secret = self.create_pull_secrets()
        spec = client.V1PodSpec(containers=[container], image_pull_secrets=secret, volumes=volumes)
        return spec

    def create_deployment_template(self):
        metadata = self.create_template_metadata()
        spec = self.create_deployment_template_spec()
        template = client.V1PodTemplateSpec(metadata=metadata, spec=spec)
        return template

    def create_deployment(self):
        """
        Create the Deployment.
        """
        template = self.create_deployment_template()

        deployment_spec = client.V1DeploymentSpec(
            replicas=self.replicas,
            template=template,
            selector={'matchLabels': {'app': self.app_label}}
        )
        deployment_metadata = client.V1ObjectMeta(name=self.app_label)
        deployment = client.V1Deployment(
            api_version="apps/v1",
            kind="Deployment",
            metadata=deployment_metadata,
            spec=deployment_spec
        )

        return deployment

    def create_service(self):
        """
        Create the Quay Service.
        """
        # Ports must be a list of client.V1ContainerPort objects
        ports = [client.V1ServicePort(port=self.service_port[1], target_port=self.service_port[0])]

        selector = {"app": self.app_label}
        spec = client.V1ServiceSpec(selector=selector, ports=ports)
        metadata=client.V1ObjectMeta(name=self.app_label)
        service = client.V1Service(api_version="v1", kind="Service", metadata=metadata, spec=spec)

        return service


class MySQL(Base):
    """
    Provisions MySQL on Openshift
    """

    # Infrastructure
    image = "registry.access.redhat.com/rhscl/mysql-57-rhel7"
    app_label = "mysql"
    service_port = (3306, 3306)  # (Target, Exposed)
    container_ports = [3306]

    # Application
    username = 'quay'
    password = 'password'
    db_name = 'quay'
    env_vars = {
        "MYSQL_ROOT_PASSWORD": "password",
        "MYSQL_USER": "quay",
        "MYSQL_PASSWORD": "password",
        "MYSQL_DATABASE": "quay",
    }

    def get_connection_string(self):
        """
        Returns a connection string which Quay can use to connect to the DB within Openshift.
        """
        return "mysql+pymysql://%s:%s@%s/%s" % (
            self.username,
            self.password,
            self.app_label,
            self.db_name
        )

    def set_max_connection_count(self):
        """
        Change MySQL's max connection count.
        """
        raise NotImplementedError("TODO")

    def create_quay_user(self):
        """
        Create a user for Quay. Required by Quay v3.3.0.
        """
        raise NotImplementedError("TODO")


class Postgres(Base):
    """
    Provisions Postgres on Openshift
    """

    # Infrastructure
    image = "registry.access.redhat.com/rhscl/postgresql-10-rhel7:1-35"
    app_label = "postgres"
    service_port = (5432, 5432)  # (Target, Exposed)
    container_ports = [5432]

    # Application
    username = 'quay'
    password = 'password'
    db_name = 'quay'
    env_vars = {
        "POSTGRESQL_MAX_CONNECTIONS": 4096,  # TODO: dynamic / variable
        "POSTGRESQL_USER": "quay",
        "POSTGRESQL_PASSWORD": "password",
        "POSTGRESQL_DATABASE": "quay",
        "POSTGRESQL_ADMIN_PASSWORD": "password",
    }

    def deploy(self, apps_v1_api, core_v1_api):
        """
        Perform the default deployment steps and implement 
        """

    def get_connection_string(self):
        """
        Returns a connection string which Quay can use to connect to the DB within Openshift.
        """
        return "postgresql://%s:%s@%s/%s" % (
            self.username,
            self.password,
            self.app_label,
            self.db_name
        )

    def create_quay_user(self, core_v1_api):
        """
        Create a user for Quay. Required by Quay v3.3.0.
        """
        cmd = '''
        psql -d quay -c " INSERT INTO \"user\" (username, email, password_hash, verified, uuid, organization, robot, invoice_email, last_invalid_login) VALUES ( 'admin', 'example@example.com', '$2a$12$VGiU60jGp1JtJXd9SLw6EucbYlAbGbLX2EJTgrSp8KofKTu4jfCNC', '1', '00ccf29c-704a-414e-9c14-54e490f08382', '0', '0', '0', '2020-01-01'); "
        '''
        raise NotImplementedError("TODO")

    def create_required_extension(self, core_v1_api):
        """
        Enable the Postgres extension required by Quay.
        """

        # Get the Pod's Name
        pod = None
        pods = core_v1_api.list_namespaced_pod(self.namespace)
        for pod in pods:
            print(pod)

        return

        # Execute the query to create the extension
        sql_query = "'CREATE EXTENSION IF NOT EXISTS pg_trgm;'"
        #cmd = "/opt/rh/rh-postgresql10/root/usr/bin/psql -d quay -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm;'"
        example = '''
            oc exec -it postgres-7dfb599b97-dbsj2 -- /bin/bash -c "psql -d quay -c 'CREATE EXTENSION IF NOT EXISTS pg_trgm;'"
        '''
        command = ['/bin/bash', '-c', 'psql', '-d', self.db_name, '-c', sql_query]
        resp = stream(
            core_v1_api.connect_get_namespaced_pod_exec,
            name,
            self.namespace,
            command=command,
            stderr=True, stdin=False,
            stdout=True, tty=False
        )

        logging.info("Enabled extension pg_trgm on Postgres")


class Redis(Base):
    """
    Provisions Redis on Openshift
    """
    image = "registry.access.redhat.com/rhscl/redis-32-rhel7"
    app_label = "redis"
    service_port = (6379, 6379)  # (Target, Exposed)
    container_ports = [6379]


class Quay(Base):
    """
    Provisions Quay on Openshift
    """

    # Infrastructure
    image = "quay.io/redhat/quay:v3.3.0"
    app_label = "quay"
    service_port = (8443, 443)  # (Target, Exposed)
    container_ports = [
        8443,  # Quay HTTPs
        9090,  # Prometheus
        9091,  # Prometheus Push Gateway
    ]
    config_secret_name = "quay-enterprise-config-secret"

    # Application
    db_uri = None  # TODO: Include this during __init__()?
    redis_host = None  # TODO: same as db_uri
    admin_users = ["admin"]

    def __init__(self, *args, **kwargs):
        """
        Initialize all that is needed to deploy or teardown Quay.
        """
        super().__init__(*args, **kwargs)

        # Quay uses this to look for its configuration secret
        self.env_vars["QE_K8S_NAMESPACE"] = self.namespace

    def create_role(self):
        """ Create a role for Quay. """
        pass

    def create_role_binding(self):
        """ Create the Role Binding for Quay. """
        pass

    def deploy(self, apps_v1_api, core_v1_api, routes_api):
        """
        Deploy Quay to Openshift. Requires a few extra resources compared to most components.
        """
        # Route
        route_data = self.create_route()
        resp = routes_api.create(body=route_data, namespace=self.namespace)
        self.hostname = resp.get('spec', {}).get('host')
        logger.info("Created Route: %s" % self.app_label)
        logger.info("Route Hostname for '%s': %s" % (self.app_label, self.hostname))

        # Generate the Configuration. Convert to YAML and Base64-encode
        quay_config = self.create_configuration()
        quay_config_yaml = yaml.dump(quay_config, sort_keys=True)

        # Generate the Self-Signed Certificates for TLS
        ssl_cert, ssl_key = self.create_certificates()

        # Create Quay's configuration secret. It includes Quay's configuration file and the
        # certificate+key used for TLS termination.
        quay_secret_body = self.create_configuration_secret(quay_config_yaml, ssl_cert, ssl_key)
        core_v1_api.create_namespaced_secret(self.namespace, quay_secret_body)

        # Run this last. Quay requires its configuration secret and some other resources before it
        # can successfully start.
        super().deploy(apps_v1_api, core_v1_api)

    def teardown(self, apps_v1_api, core_v1_api, routes_api):
        """
        Removes all Resources created during the Quay deployment.
        """
        super().teardown(apps_v1_api, core_v1_api)

        # Route
        try:
            routes_api.delete(name=self.app_label, namespace=self.namespace)
            logger.info("Deleted Route: %s", self.app_label)
        except client.rest.ApiException:
            logger.exception("Unable to delete '%s' route. Skipping.", self.app_label)

        # Configuration Secret
        try:
            core_v1_api.delete_namespaced_secret(self.config_secret_name, self.namespace)
            logger.info("Deleted Quay's Config Secret: %s", self.config_secret_name)
        except client.rest.ApiException:
            logger.exception("Unable to delete '%s' Secret. Skipping.", self.config_secret_name)

    def create_route(self):
        """
        Create a Route definition
        """
        resource = {
            "apiVersion": "route.openshift.io/v1",
            "kind": "Route",
            "metadata": {
                "name": self.app_label,
            },
            "spec": {
                "to": {
                    "kind": "Service",
                    "name": self.app_label
                },
                "tls": {
                    "termination": "passthrough"
                }
            }
        }

        return resource

    def create_pull_secrets(self):
        pull_secrets = [client.V1LocalObjectReference(name="redhat-pull-secret")]  # TODO: variable
        return pull_secrets

    def create_volume_mounts(self):
        """
        Mounts the Quay Configuration secret as a volume on the Pod.
        """
        mounts = [
            client.V1VolumeMount(mount_path="/conf/stack", read_only=False, name="configvolume")
        ]
        return mounts

    def create_template_volumes(self):
        """
        Overridden to include Quay's configuration secret in the deployment template specification.
        """
        secret = client.V1SecretVolumeSource(secret_name=self.config_secret_name)
        return [client.V1Volume(name="configvolume", secret=secret)]

    def create_configuration(self):
        """
        Create the Quay Configuration file.
        """
        if not self.db_uri:
            raise Exception("Unable to create Quay configuration. No database URI specified.")

        if not self.redis_host:
            raise Exception("Unable to create Quay configuration. Redis host not specified.")

        if not self.hostname:
            raise Exception("Unable to create Quay configuration. No hostname found.")

        quay_config = {
            "DB_URI": self.db_uri,
            "PREFERRED_URL_SCHEME": "https",
            "SERVER_HOSTNAME": self.hostname,
            "SECRET_KEY": "a36c9d7d-25a9-30f4-a586-3d2f8dc40a83",  # TODO: generate
            "AUTHENTICATION_TYPE": "Database",  # TODO: required?
            "USER_EVENTS_REDIS": {
                "host": self.redis_host,
            },
            "SUPER_USERS": ["admin"],
            "DATABASE_SECRET_KEY": "mys3cretk3y",
            "FEATURE_MAILING": False,  # TODO: required?
            "SETUP_COMPLETE": True,
        }

        return quay_config

    def create_configuration_secret(self, config_yaml, ssl_cert, ssl_key):
        """
        Create Quay's configuration secret.
        """
        quay_config_base64 = base64.b64encode(config_yaml.encode("UTF-8")).decode('UTF-8')
        ssl_cert_base64 = base64.b64encode(ssl_cert.encode("UTF-8")).decode('UTF-8')
        ssl_key_base64 = base64.b64encode(ssl_key.encode("UTF-8")).decode('UTF-8')

        data = {
            "config.yaml": quay_config_base64,
            "ssl.cert": ssl_cert_base64,
            "ssl.key": ssl_key_base64,
        }

        metadata = {"name": self.config_secret_name}
        body = client.V1Secret("v1", data , "Secret", metadata)

        return body

    def create_certificates(self):
        """
        Generate a self-signed certificate and return the cert and key strings.
        """
        if not self.hostname:
            raise Exception("Unable to generate certificates. Quay's hostname is not specified")

        # Attribution/Inspiration: https://stackoverflow.com/a/60804101

        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)
        
        cert = crypto.X509()
        cert.get_subject().CN = self.hostname
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')

        ssl_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
        ssl_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8")

        return (ssl_cert, ssl_key)


if __name__ == '__main__':

    logger.info("setup.py version: %s" % __VERSION__)

    # TODO: This could all be enhanced
    parser = argparse.ArgumentParser()
    parser.add_argument('--namespace', type=str, required=True)
    parser.add_argument('action')
    args = parser.parse_args()

    config.load_kube_config()
    k8s_client = config.new_client_from_config()
    dyn_client = DynamicClient(k8s_client)

    # Native k8s APIs
    apps_v1_api = client.AppsV1Api()  # Deployments
    core_v1_api = client.CoreV1Api()  # Services

    # Openshift APIs
    routes_api = dyn_client.resources.get(api_version='route.openshift.io/v1', kind='Route')

    # Components
    quay = Quay(namespace=args.namespace)
    redis = Redis(namespace=args.namespace)
    postgres = Postgres(namespace=args.namespace)

    if args.action == 'create':
        """
        Deploy all components and their resources.
        """
        logger.info("Deploying all Quay-related components in namespace: %s" % args.namespace)
        redis.deploy(apps_v1_api, core_v1_api)
        postgres.deploy(apps_v1_api, core_v1_api)

        quay.db_uri = postgres.get_connection_string()
        quay.redis_host = redis.app_label
        quay.deploy(apps_v1_api, core_v1_api, routes_api)

    elif args.action == "teardown":
        """
        Remove all components and their resources.
        """
        logger.info("Tearing down all Quay-related components in namespace: %s" % args.namespace)
        redis.teardown(apps_v1_api, core_v1_api)
        postgres.teardown(apps_v1_api, core_v1_api)
        quay.teardown(apps_v1_api, core_v1_api, routes_api)
