import uuid

from flask import request
from flask_restful import Resource
from werkzeug.exceptions import NotFound, Unauthorized

from controllers.web import api
from controllers.web.error import WebAppAuthRequiredError
from extensions.ext_database import db
from libs.passport import PassportService
from models.model import App, EndUser, Site
from services.enterprise.enterprise_service import EnterpriseService
from services.feature_service import FeatureService

# 自定义代码
import requests
# 自定义代码



class PassportResource(Resource):
    """Base resource for passport."""

    def get(self):
        system_features = FeatureService.get_system_features()
        app_code = request.headers.get("X-App-Code")
        user_id = request.args.get("user_id")

        if app_code is None:
            raise Unauthorized("X-App-Code header is missing.")

        if system_features.webapp_auth.enabled:
            app_settings = EnterpriseService.WebAppAuth.get_app_access_mode_by_code(app_code=app_code)
            if not app_settings or not app_settings.access_mode == "public":
                raise WebAppAuthRequiredError()

        # 自定义代码


        token = request.headers.get("token")
        if token is None:
            raise Unauthorized("token header is missing.")
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

        # get site from db and check if it is normal
        site = db.session.query(Site).filter(Site.code == app_code, Site.status == "normal").first()
        if not site:
            raise NotFound()
        # get app from db and check if it is normal and enable_site
        app_model = db.session.query(App).filter(App.id == site.app_id).first()
        if not app_model or app_model.status != "normal" or not app_model.enable_site:
            raise NotFound()

        if user_id:
            end_user = (
                db.session.query(EndUser).filter(EndUser.app_id == app_model.id, EndUser.session_id == user_id).first()
            )

            if end_user:
                pass
            else:
                end_user = EndUser(
                    tenant_id=app_model.tenant_id,
                    app_id=app_model.id,
                    type="browser",
                    is_anonymous=True,
                    session_id=user_id,
                )
                db.session.add(end_user)
                db.session.commit()
        else:
            end_user = EndUser(
                tenant_id=app_model.tenant_id,
                app_id=app_model.id,
                type="browser",
                is_anonymous=True,
                session_id=generate_session_id(),
            )
            db.session.add(end_user)
            db.session.commit()
        
        # 自定义代码 添加"mtk":token
        payload = {
            "iss": site.app_id,
            "sub": "Web API Passport",
            "app_id": site.app_id,
            "app_code": app_code,
            "end_user_id": end_user.id,
            "mtk":token
        }

        tk = PassportService().issue(payload)

        return {
            "access_token": tk,
        }


api.add_resource(PassportResource, "/passport")


def generate_session_id():
    """
    Generate a unique session ID.
    """
    while True:
        session_id = str(uuid.uuid4())
        existing_count = db.session.query(EndUser).filter(EndUser.session_id == session_id).count()
        if existing_count == 0:
            return session_id
