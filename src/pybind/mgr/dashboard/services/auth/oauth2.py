
import importlib
import json
import logging
import time
from typing import Dict, List
from urllib.parse import quote

import cherrypy
import requests

from ... import mgr
from ...services.auth import BaseAuth, SSOAuth, decode_jwt_segment
from ...tools import prepare_url_prefix
from ..access_control import Role, User, UserAlreadyExists

try:
    jmespath = importlib.import_module("jmespath")
except ModuleNotFoundError:
    logging.error("Module 'jmespath' is not installed.")

logger = logging.getLogger(__name__)


class OAuth2(SSOAuth):
    LOGIN_URL = 'auth/oauth2/login'
    LOGOUT_URL = 'auth/oauth2/logout'
    sso = True

    class OAuth2Config(BaseAuth.Config):
        roles_path: str

    def __init__(self, roles_path=None):
        self.roles_path = roles_path

    def get_roles_path(self):
        return self.roles_path

    @staticmethod
    def enabled():
        return mgr.get_module_option('sso_oauth2')

    def to_dict(self) -> 'OAuth2Config':
        return {
            'roles_path': self.roles_path
        }

    @classmethod
    def from_dict(cls, s_dict: OAuth2Config) -> 'OAuth2':
        try:
            return OAuth2(s_dict['roles_path'])
        except KeyError:
            return OAuth2({})

    @classmethod
    def get_auth_name(cls):
        return cls.__name__.lower()

    @classmethod
    # pylint: disable=protected-access
    def get_token(cls, request: cherrypy._ThreadLocalProxy) -> str:
        try:
            return request.cookie['token'].value
        except KeyError:
            return request.headers.get('X-Access-Token')

    @classmethod
    def get_token_payload(cls) -> Dict:
        try:
            return cherrypy.request.jwt_payload
        except AttributeError:
            {}

    @classmethod
    def set_token_payload(cls, token):
        cherrypy.request.jwt_token = token
        cherrypy.request.jwt_payload = decode_jwt_segment(token.split(".")[1])

    @classmethod
    def get_user_roles(cls, user_info) -> List[Role]:
        roles: List[Role] = []

        if jmespath and getattr(mgr.SSO_DB.config, 'roles_path', None):
            logger.debug("Using 'roles_path' to fetch roles")
            roles = jmespath.search(mgr.SSO_DB.config.roles_path, user_info) or []
        # e.g Keycloak
        elif 'resource_access' in user_info or 'realm_access' in user_info:
            logger.debug("Using 'resource_access' or 'realm_access' to fetch roles")
            roles = jmespath.search(
                "resource_access.*[?@!='account'].roles[] || realm_access.roles[]",
                user_info) or []
        elif 'roles' in user_info:
            logger.debug("Using 'roles' to fetch roles")
            roles = [user_info['roles']] if isinstance(user_info['roles'], str) else [user_info['roles']]

        return Role.map_to_system_roles(roles)

    @classmethod
    def get_user(cls, token: str) -> User:
        try:
            return cherrypy.request.user
        except AttributeError:
            cls.set_token_payload(token)
            cls._create_user()
        return cherrypy.request.user

    @classmethod
    def _create_user(cls):
        try:
            jwt_payload = cherrypy.request.jwt_payload
        except AttributeError:
            raise cherrypy.HTTPError(401)

        name = jwt_payload.get('name', None)
        email = jwt_payload.get('email', None)
        roles = cls.get_user_roles(jwt_payload)

        if name is None or email is None or len(roles) == 0:
            user_info = cls.get_user_info()
            if name is None:
                name = user_info.get('name', None)
            if email is None:
                email = user_info.get('email', None)
            if len(roles) == 0:
                roles = cls.get_user_roles(user_info)

        # Forbid access for users without any roles.
        if len(roles) == 0:
            raise cherrypy.HTTPError(403)

        try:
            user = mgr.ACCESS_CTRL_DB.create_user(jwt_payload['sub'], None, name, email)
        except UserAlreadyExists:
            logger.debug("User already exists")
            user = mgr.ACCESS_CTRL_DB.get_user(jwt_payload['sub'])
        except KeyError as e:
            raise cherrypy.HTTPError(500, f'Invalid token payload: {e}')

        with open('/var/log/ceph/debug.log', 'a+') as f:
            f.write(f"user_name: {user_name}\n")
            f.write(f"user_email: {user_email}\n")
            f.write(f"user_roles: {[user_role.name for user_role in user_roles]}\n")

        user.name = name
        user.email = email
        user.set_roles(roles)
        # set user last update to token time issued
        user.last_update = jwt_payload.get('iat', 0)
        cherrypy.request.user = user

    @classmethod
    def reset_user(cls):
        try:
            mgr.ACCESS_CTRL_DB.delete_user(cherrypy.request.user.username)
            cherrypy.request.user = None
        except AttributeError:
            raise cherrypy.HTTPError()

    @classmethod
    def is_token_expired(cls, token: str) -> bool:
        try:
            payload = decode_jwt_segment(token.split(".")[1])
            return time.time() > payload.get('exp', 0)
        except Exception:
            raise cherrypy.HTTPError(500, 'Failed to verify session')

    @classmethod
    def get_token_iss(cls, token=''):
        if token:
            cls.set_token_payload(token)
        return cls.get_token_payload()['iss']

    @classmethod
    def get_user_info(cls):
        openid_config = cls.get_openid_config(cls.get_token_iss())
        userinfo_endpoint = openid_config.get('userinfo_endpoint')

        try:
            token = cherrypy.request.jwt_token
        except AttributeError:
            raise cherrypy.HTTPError(401)

        msg = 'Failed to get user info: could not contact IDP'
        try:
            response = requests.get(userinfo_endpoint, headers={'Authorization': f'Bearer {token}'})
        except requests.exceptions.RequestException as e:
            raise cherrypy.HTTPError(500, message=f"{msg}: {e}")
        if response.status_code != 200:
            raise cherrypy.HTTPError(500, message=f"{msg}: Status code: {response.status_code}")

        return json.loads(response.text)

    @classmethod
    def get_openid_config(cls, iss):
        msg = 'Failed to logout: could not contact IDP'
        try:
            response = requests.get(f'{iss}/.well-known/openid-configuration')
        except requests.exceptions.RequestException:
            raise cherrypy.HTTPError(500, message=msg)
        if response.status_code != 200:
            raise cherrypy.HTTPError(500, message=msg)
        return json.loads(response.text)

    @classmethod
    def get_login_redirect_url(cls, token) -> str:
        url_prefix = prepare_url_prefix(mgr.get_module_option('url_prefix', default=''))
        return f"{url_prefix}/#/login?access_token={token}"

    @classmethod
    def get_logout_redirect_url(cls, token) -> str:
        openid_config = cls.get_openid_config(cls.get_token_iss(token))
        end_session_url = openid_config.get('end_session_endpoint')
        encoded_end_session_url = quote(end_session_url, safe="")
        url_prefix = prepare_url_prefix(mgr.get_module_option('url_prefix', default=''))
        return f'{url_prefix}/oauth2/sign_out?rd={encoded_end_session_url}'
