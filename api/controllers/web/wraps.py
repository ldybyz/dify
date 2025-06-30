from functools import wraps

from flask import request
from flask_restful import Resource
from werkzeug.exceptions import BadRequest, NotFound, Unauthorized

from controllers.web.error import WebAppAuthAccessDeniedError, WebAppAuthRequiredError
from extensions.ext_database import db
from libs.passport import PassportService
from models.model import App, EndUser, Site
from services.enterprise.enterprise_service import EnterpriseService
from services.feature_service import FeatureService


def validate_jwt_token(view=None):
    def decorator(view):
        @wraps(view)
        def decorated(*args, **kwargs):
            app_model, end_user = decode_jwt_token()

            return view(app_model, end_user, *args, **kwargs)

        return decorated

    if view:
        return decorator(view)
    return decorator


def decode_jwt_token():
    system_features = FeatureService.get_system_features()
    app_code = str(request.headers.get("X-App-Code"))
    try:
        auth_header = request.headers.get("Authorization")
        if auth_header is None:
            raise Unauthorized("Authorization header is missing.")

        if " " not in auth_header:
            raise Unauthorized("Invalid Authorization header format. Expected 'Bearer <api-key>' format.")

        auth_scheme, tk = auth_header.split(None, 1)
        auth_scheme = auth_scheme.lower()

        if auth_scheme != "bearer":
            raise Unauthorized("Invalid Authorization header format. Expected 'Bearer <api-key>' format.")
        decoded = PassportService().verify(tk)
        app_code = decoded.get("app_code")
        app_model = db.session.query(App).filter(App.id == decoded["app_id"]).first()
        site = db.session.query(Site).filter(Site.code == app_code).first()
        if not app_model:
            raise NotFound()
        if not app_code or not site:
            raise BadRequest("Site URL is no longer valid.")
        if app_model.enable_site is False:
            raise BadRequest("Site is disabled.")
        end_user = db.session.query(EndUser).filter(EndUser.id == decoded["end_user_id"]).first()
        if not end_user:
            raise NotFound()

        # for enterprise webapp auth
        app_web_auth_enabled = False
        if system_features.webapp_auth.enabled:
            app_web_auth_enabled = (
                EnterpriseService.WebAppAuth.get_app_access_mode_by_code(app_code=app_code).access_mode != "public"
            )

        _validate_webapp_token(decoded, app_web_auth_enabled, system_features.webapp_auth.enabled)
        _validate_user_accessibility(decoded, app_code, app_web_auth_enabled, system_features.webapp_auth.enabled)

        # 自定义代码

        token = decoded.get("mtk")
        if token is not None:
            #raise Unauthorized("token header is missing.")
        #验证token是否有效,获取用户信息,user_id,group_id
           verify_url =  "https://marketapi.cticert.com/CAI/CAI/VerifyUserLogin?token="+token
           verify_result = requests.post(verify_url)
        # verify_result.raise_for_status()
           result = verify_result.json()
           code = result.get("code")

           if code != 200:
               raise Unauthorized("token header is error.")
           data = result.get("data", {})
           #user_id = data.get("userId")
           group_code = data.get("groupCode")
        #查询app_code是否关联group_id
           sql_query = """ SELECT  count(1) FROM apps t 
INNER JOIN tenants a on t.tenant_id=a.id INNER JOIN sites s on s.app_id=t.id 
 where  t.status='normal' and t.enable_api='t' and t.enable_site='t' and (a.group_code ='C0001' OR a.group_code= :group_code) and s.code= :app_code"""
           with db.engine.begin() as conn:
                count = conn.execute(db.text(sql_query), {"group_code": group_code,"app_code": app_code})
           if count == 0:
               raise Unauthorized("Agent is not find.")
               
        # 自定义代码

        return app_model, end_user
    except Unauthorized as e:
        if system_features.webapp_auth.enabled:
            app_web_auth_enabled = (
                EnterpriseService.WebAppAuth.get_app_access_mode_by_code(app_code=str(app_code)).access_mode != "public"
            )
            if app_web_auth_enabled:
                raise WebAppAuthRequiredError()

        raise Unauthorized(e.description)


def _validate_webapp_token(decoded, app_web_auth_enabled: bool, system_webapp_auth_enabled: bool):
    # Check if authentication is enforced for web app, and if the token source is not webapp,
    # raise an error and redirect to login
    if system_webapp_auth_enabled and app_web_auth_enabled:
        source = decoded.get("token_source")
        if not source or source != "webapp":
            raise WebAppAuthRequiredError()

    # Check if authentication is not enforced for web, and if the token source is webapp,
    # raise an error and redirect to normal passport login
    if not system_webapp_auth_enabled or not app_web_auth_enabled:
        source = decoded.get("token_source")
        if source and source == "webapp":
            raise Unauthorized("webapp token expired.")


def _validate_user_accessibility(decoded, app_code, app_web_auth_enabled: bool, system_webapp_auth_enabled: bool):
    if system_webapp_auth_enabled and app_web_auth_enabled:
        # Check if the user is allowed to access the web app
        user_id = decoded.get("user_id")
        if not user_id:
            raise WebAppAuthRequiredError()

        if not EnterpriseService.WebAppAuth.is_user_allowed_to_access_webapp(user_id, app_code=app_code):
            raise WebAppAuthAccessDeniedError()


class WebApiResource(Resource):
    method_decorators = [validate_jwt_token]
