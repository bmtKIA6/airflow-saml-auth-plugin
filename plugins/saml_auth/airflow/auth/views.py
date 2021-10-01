from flask_appbuilder.views import expose
from flask_appbuilder.security.views import AuthView

from flask import (
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    Response,
    session,
    url_for,
)

from jinja2 import Environment, PackageLoader


class AuthSAMLView(AuthView):
    login_template = "templates/login_saml.html"
    endpoint = ""

    env = Environment(loader=PackageLoader("saml_auth", "templates"))

    def __init__(self):
        super(AuthView, self).__init__()

    @expose("/login/", methods=["GET", "POST"])
    def login(self):
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)

        tmpl = self.env.get_template("login_saml.html")

        return tmpl.render()
