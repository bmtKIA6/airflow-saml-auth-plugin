from airflow.plugins_manager import AirflowPlugin


# Defining the plugin class
class AirflowSAMLAuthPlugin(AirflowPlugin):
    name = "saml_auth_plugin"
