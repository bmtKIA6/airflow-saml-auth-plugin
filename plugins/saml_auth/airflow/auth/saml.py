import flask_login
import json
import os

from airflow.configuration import AirflowConfigException, conf
from airflow.utils.db import provide_session
from airflow.www.app import csrf
from flask import (
    abort,
    flash,
    redirect,
    request,
    session as flask_session,
    url_for,
    make_response,
    render_template,
)

from flask_babel import lazy_gettext as _

from flask_appbuilder.security.manager import AUTH_REMOTE_USER
from flask_appbuilder.security.sqla.models import User
from flask_appbuilder.security.views import AuthView, expose
from flask_login import (
    current_user,
    login_user,
    logout_user,
    LoginManager,
    login_required,
)
from logging import getLogger
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from urllib.parse import urlparse
from typing import Dict, List, Optional, Set, Tuple

from saml_auth.airflow.auth.views import AuthSAMLView

from flask_appbuilder.views import expose, ModelView, SimpleFormView
from flask_appbuilder.security.views import AuthView, UserModelView
from flask_appbuilder.security.decorators import has_access
from flask_appbuilder.security.forms import (
    LoginForm_db,
    LoginForm_oid,
    ResetPasswordForm,
    UserInfoEdit,
)
from flask_appbuilder._compat import as_unicode

from wtforms import PasswordField, validators
from flask_appbuilder.fieldwidgets import BS3PasswordFieldWidget
from flask_babel import lazy_gettext
from flask_login import login_user, logout_user

from flask import (
    abort,
    current_app,
    flash,
    g,
    redirect,
    request,
    Response,
    session,
    url_for,
)

from typing import Optional
from urllib.parse import urlparse

try:
    from airflow.www_rbac.security import AirflowSecurityManager, EXISTING_ROLES
except ImportError:
    try:
        from airflow.www.security import AirflowSecurityManager, EXISTING_ROLES
    except ImportError:
        # Airflow not installed, likely we are running setup.py to _install_ things
        class AirflowSecurityManager(object):
            def __init__(self, appbuilder):
                pass

            EXISTING_ROLES = []


log = getLogger(__name__)


class SAMLLoginManager(LoginManager):
    def __init__(self, app=None, add_context_processor=True):

        # self.login_manager = flask_login.LoginManager()
        # self.login_manager.login_view = 'airflow.login'
        # self.login_manager.session_protection
        self.app = app
        self.api_url = None
        self.session = None
        self.sm = None

        super().__init__(app, add_context_processor)

        self.user_loader(self.load_user)

    def prepare_flask_request(self, request):
        # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
        url_data = urlparse(request.url)
        return {
            "https": "on" if request.scheme == "https" else "off",
            "http_host": request.host,
            "request_uri": "/saml/login",
            "server_port": url_data.port,
            "script_name": request.path,
            "get_data": request.args.copy(),
            # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
            # 'lowercase_urlencoding': True,
            "post_data": request.form.copy(),
        }

    def init_saml_auth(self, req):

        settings_path = str(conf.get("saml_auth", "saml_path"))

        auth = OneLogin_Saml2_Auth(req, custom_base_path=settings_path)
        return auth

    def init_app(self, app=None, add_context_processor=True):

        super().init_app(app)

        app.login_manager = self

        self.user_loader(self.load_user)

        # metadata file route
        app.add_url_rule("/saml/metadata.xml", "metadata", self.metadata)

        # sso login uri
        app.add_url_rule(
            "/saml/login", "saml_login", self.saml_login, methods=["GET", "POST"]
        )

    def login(self, request):
        return redirect(
            url_for("AuthSAMLView"),
        )

    def metadata(self):
        req = self.prepare_flask_request(request)
        auth = self.init_saml_auth(req)
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if len(errors) == 0:
            resp = make_response(metadata, 200)
            resp.headers["Content-Type"] = "text/xml"
        else:
            resp = make_response(", ".join(errors), 500)
        return resp

    #    @provide_session
    @csrf.exempt
    def saml_login(self):  # , session=None):

        log.debug(f"saml_login request: {request}")

        req = self.prepare_flask_request(request)

        auth = self.init_saml_auth(req)
        errors = []
        error_reason = None
        not_auth_warn = False
        success_slo = False
        attributes = False
        paint_logout = False

        if "sso" in request.args:
            return redirect(auth.login())
        elif ("sso2" in request.args or len(request.args) == 0) and (
            "Referer" not in request.headers
        ):
            return_to = "%sadmin/" % request.host_url
            return redirect(auth.login(return_to))
        elif "slo" in request.args:
            name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
            if "samlNameId" in flask_session:
                name_id = flask_session["samlNameId"]
            if "samlSessionIndex" in flask_session:
                session_index = flask_session["samlSessionIndex"]
            if "samlNameIdFormat" in flask_session:
                name_id_format = flask_session["samlNameIdFormat"]
            if "samlNameIdNameQualifier" in flask_session:
                name_id_nq = flask_session["samlNameIdNameQualifier"]
            if "samlNameIdSPNameQualifier" in flask_session:
                name_id_spnq = flask_session["samlNameIdSPNameQualifier"]

            return redirect(
                auth.logout(
                    name_id=name_id,
                    session_index=session_index,
                    nq=name_id_nq,
                    name_id_format=name_id_format,
                    spnq=name_id_spnq,
                )
            )
        elif "acs" in request.args:
            auth.process_response()
            errors = auth.get_errors()
            not_auth_warn = not auth.is_authenticated()
            if len(errors) == 0:
                # stuff for flask_login
                username = auth.get_nameid()
                email = auth.get_nameid()
                user = (
                    self.session.query(User).filter(User.username == username).first()
                )

                log.info(f"SAML ACS: username: {username} email: {email}")

                attrs = auth.get_attributes()
                log.info(f"attributes: {attrs}")

                userinfo = self._saml_user_info(email, attrs)

                # If the user is new, register them
                if (not user) and self.sm.auth_user_registration:

                    user = self.sm.add_user(
                        username=username,
                        first_name=userinfo.get("first_name", ""),
                        last_name=userinfo.get("last_name", ""),
                        email=userinfo.get("email", "") or f"{username}@email.notfound",
                        role=self._calculate_user_roles(userinfo),
                    )

                    # If user registration failed, go away
                    if not user:
                        log.error("Error creating a new SAML user {0}".format(username))
                        return None

                    log.debug("New user registered: {0}".format(user))

                    # first_name=attrs["First Name"][0],
                    # last_name=attrs["Last Name"][0],

                    self.session.merge(user)
                else:
                    user.active = True
                    user.first_name = (attrs["First Name"][0],)
                    user.last_name = (attrs["Last Name"][0],)

                    # Sync the user's roles
                    if user and self.sm.auth_roles_sync_at_login:
                        user.roles = self._calculate_user_roles(userinfo)
                        log.debug(
                            "Calculated new roles for user='{0}' as: {1}".format(
                                username, user.roles
                            )
                        )

                    self.session.merge(user)
                    self.session.commit()
                    login_user(user)
                    self.session.commit()
                    # end stuff for flask_login

                self.sm.update_user_auth_stat(user)

                self_url = OneLogin_Saml2_Utils.get_self_url(req)
                return_to = self.appbuilder.get_url_for_index

                if (
                    "RelayState" in request.form
                    and self_url != request.form["RelayState"]
                ):

                    return redirect(auth.redirect_to(request.form["RelayState"]))
                    if request.form["RelayState"] == "":
                        return_to = "%sadmin/" % request.host_url

                return redirect(auth.login(return_to))

        elif "sls" in request.args:
            request_id = None
            if "LogoutRequestID" in flask_session:
                request_id = flask_session["LogoutRequestID"]
                dscb = lambda: flask_session.clear()
                url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
                errors = auth.get_errors()
            if len(errors) == 0:
                if url is not None:
                    return redirect(url)
                else:
                    success_slo = True
            elif auth.get_settings().is_debug_active():
                error_reason = auth.get_last_error_reason()
        elif "Referer" in request.headers and len(request.args) == 0:
            # return redirect(auth.get_slo_url()) # LOgout from one application but cookies will be used for furthur login
            return redirect(
                "https://XXXXX.awsapps.com/start#/signout"
            )  # Logout from app completly

        if "samlUserdata" in flask_session:
            paint_logout = True
            if len(flask_session["samlUserdata"]) > 0:
                attributes = flask_session["samlUserdata"].items()

    def load_user(self, userid):  # , session=None):

        if not userid or userid == "None":
            return None

        user = self.session.query(User).filter(User.id == int(userid)).first()

        return user

    def _saml_user_info(self, email, attrs):

        userinfo = {}

        if "First Name" in attrs:
            userinfo["first_name"] = attrs["First Name"]

        if "Last Name" in attrs:
            userinfo["last_name"] = attrs["Last Name"]

        userinfo["username"] = f"saml_{email}"
        userinfo["email"] = email

        return userinfo

    def _calculate_user_roles(self, userinfo) -> List[str]:
        user_role_objects = set()

        # apply AUTH_ROLES_MAPPING
        if len(self.sm.auth_roles_mapping) > 0:
            user_role_keys = userinfo.get("role_keys", [])
            user_role_objects.update(self.sm.get_roles_from_keys(user_role_keys))

        # apply AUTH_USER_REGISTRATION_ROLE
        if self.sm.auth_user_registration:
            registration_role_name = self.sm.auth_user_registration_role

            # if AUTH_USER_REGISTRATION_ROLE_JMESPATH is set,
            # use it for the registration role
            if self.sm.auth_user_registration_role_jmespath:
                import jmespath

                registration_role_name = jmespath.search(
                    self.sm.auth_user_registration_role_jmespath, userinfo
                )

            # lookup registration role in flask db
            fab_role = self.sm.find_role(registration_role_name)
            if fab_role:
                user_role_objects.add(fab_role)
            else:
                log.warning(
                    "Can't find AUTH_USER_REGISTRATION role: {0}".format(
                        registration_role_name
                    )
                )

        return list(user_role_objects)

    def auth_user_saml(self, userinfo):
        """
        Method for authenticating user with OAuth.

        :userinfo: dict with user information
                   (keys are the same as User model columns)
        """
        # extract the username from `userinfo`
        if "username" in userinfo:
            username = userinfo["username"]
        elif "email" in userinfo:
            username = userinfo["email"]
        else:
            log.error(
                "OAUTH userinfo does not have username or email {0}".format(userinfo)
            )
            return None

        # If username is empty, go away
        if (username is None) or username == "":
            return None

        # Search the DB for this user
        user = self.find_user(username=username)

        # If user is not active, go away
        if user and (not user.is_active):
            return None

        # If user is not registered, and not self-registration, go away
        if (not user) and (not self.auth_user_registration):
            return None

        # Sync the user's roles
        if user and self.auth_roles_sync_at_login:
            user.roles = self._oauth_calculate_user_roles(userinfo)
            log.debug(
                "Calculated new roles for user='{0}' as: {1}".format(
                    username, user.roles
                )
            )

        # If the user is new, register them
        if (not user) and self.auth_user_registration:
            user = self.add_user(
                username=username,
                first_name=userinfo.get("first_name", ""),
                last_name=userinfo.get("last_name", ""),
                email=userinfo.get("email", "") or f"{username}@email.notfound",
                role=self._oauth_calculate_user_roles(userinfo),
            )
            log.debug("New user registered: {0}".format(user))

            # If user registration failed, go away
            if not user:
                log.error("Error creating a new OAuth user {0}".format(username))
                return None

        # LOGIN SUCCESS (only if user is now registered)
        if user:
            self.update_user_auth_stat(user)
            return user
        else:
            return None


class AirflowSAMLSecurityManager(AirflowSecurityManager):
    def register_views(self):

        if not self.appbuilder.app.config.get("FAB_ADD_SECURITY_VIEWS", True):
            return

        self.appbuilder.add_api(self.security_api)

        self.appbuilder.add_view_no_menu(self.resetpasswordview())
        self.appbuilder.add_view_no_menu(self.resetmypasswordview())
        self.appbuilder.add_view_no_menu(self.userinfoeditview())

        self.user_view = self.userdbmodelview
        self.auth_view = AuthSAMLView()

        self.user_view = self.appbuilder.add_view(
            self.user_view,
            "List Users",
            icon="fa-user",
            label=_("List Users"),
            category="Security",
            category_icon="fa-cogs",
            category_label=_("Security"),
        )

        self.appbuilder.add_view_no_menu(self.auth_view)

        role_view = self.appbuilder.add_view(
            self.rolemodelview,
            "List Roles",
            icon="fa-group",
            label=_("List Roles"),
            category="Security",
            category_icon="fa-cogs",
        )
        role_view.related_views = [self.user_view.__class__]

    def create_login_manager(self, app) -> LoginManager:
        """
        Override to implement your custom login manager instance

        :param app: Flask app

        """
        lm = SAMLLoginManager(app)
        lm.session = self.get_session
        lm.appbuilder = self.appbuilder
        lm.sm = self
        return lm
