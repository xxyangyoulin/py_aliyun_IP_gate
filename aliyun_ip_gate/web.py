import os
import secrets
import sqlite3
from hashlib import sha256
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.middleware.sessions import SessionMiddleware

from .config import Settings
from .database import Database
from .ip import parse_additional_ips
from .sync_service import SyncAlreadyRunning, sync_once
from .web_config import load_web_config


PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATABASE_PATH = os.path.join(PROJECT_DIR, "data", "app.db")
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))

database = Database(DATABASE_PATH)
database.initialize()
app = FastAPI(title="Aliyun IP Gate")
app.state.web_config = load_web_config(os.path.join(PROJECT_DIR, ".env"))


@app.middleware("http")
async def require_access_token(request, call_next):
    if request.url.path == "/login" or request.url.path.startswith("/static/"):
        return await call_next(request)
    access_token = request.app.state.web_config.access_token
    fingerprint = sha256(access_token.encode()).hexdigest()
    if not access_token or request.session.get("access_token") != fingerprint:
        return RedirectResponse("/login", status_code=303)
    return await call_next(request)


app.add_middleware(
    SessionMiddleware,
    secret_key=database.get_web_secret(),
    same_site="strict",
    https_only=False,
)
app.mount(
    "/static",
    StaticFiles(directory=os.path.join(PACKAGE_DIR, "static")),
    name="static",
)
templates = Jinja2Templates(directory=os.path.join(PACKAGE_DIR, "templates"))


def mask_secret(value):
    if not value:
        return "未配置"
    if len(value) <= 8:
        return "••••••••"
    return f"{value[:4]}••••{value[-4:]}"


templates.env.globals["mask_secret"] = mask_secret


def render(request, template_name, **context):
    status_code = context.pop("status_code", 200)
    csrf_token = request.session.get("csrf_token")
    if not csrf_token:
        csrf_token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = csrf_token
    context.update(
        {
            "request": request,
            "csrf_token": csrf_token,
            "flash": request.session.pop("flash", None),
        }
    )
    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context=context,
        status_code=status_code,
    )


async def read_form(request):
    form = await request.form()
    expected = request.session.get("csrf_token", "")
    actual = str(form.get("csrf_token", ""))
    if not expected or not secrets.compare_digest(expected, actual):
        raise HTTPException(status_code=403, detail="CSRF 校验失败")
    return form


def parse_security_groups(value):
    targets = []
    for item in value.replace(",", "\n").splitlines():
        item = item.strip()
        if not item:
            continue
        try:
            region_id, security_group_id = item.split(":", 1)
        except ValueError as error:
            raise ValueError(f"安全组格式错误: {item}") from error
        if not region_id.strip() or not security_group_id.strip():
            raise ValueError(f"安全组格式错误: {item}")
        targets.append((region_id.strip(), security_group_id.strip()))
    return sorted(set(targets))


def parse_rds_instances(value):
    return sorted(
        {
            item.strip()
            for item in value.replace(",", "\n").splitlines()
            if item.strip()
        }
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render(
        request,
        "login.html",
        token_configured=bool(request.app.state.web_config.access_token),
    )


@app.post("/login")
async def login(request: Request):
    form = await read_form(request)
    access_token = request.app.state.web_config.access_token
    supplied_token = str(form.get("access_token", ""))
    if not access_token:
        return render(
            request,
            "login.html",
            token_configured=False,
            error="WEB_ACCESS_TOKEN 尚未配置",
            status_code=503,
        )
    if not secrets.compare_digest(access_token, supplied_token):
        return render(
            request,
            "login.html",
            token_configured=True,
            error="访问 Token 错误",
            status_code=401,
        )
    request.session["access_token"] = sha256(access_token.encode()).hexdigest()
    request.session["flash"] = "登录成功"
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
async def logout(request: Request):
    await read_form(request)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    state = database.get_runtime_state()
    accounts = database.list_accounts()
    return render(
        request,
        "dashboard.html",
        state=state,
        account_count=len(accounts),
        ecs_count=sum(len(account.security_groups) for account in accounts),
        rds_count=sum(len(account.rds_instances) for account in accounts),
        additional_ip_count=len(database.get_additional_ips()),
        runs=database.list_sync_runs(10),
    )


@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    return render(request, "settings.html", settings=database.get_settings())


@app.post("/settings")
async def save_settings(request: Request):
    form = await read_form(request)
    current = database.get_settings()
    try:
        interval = int(str(form.get("check_interval_seconds", "")))
        if interval <= 0:
            raise ValueError("检查间隔必须大于 0")
        description = str(form.get("ecs_rule_description", "")).strip()
        if not description:
            raise ValueError("ECS 规则描述禁止为空")
        whitelist_name = str(form.get("rds_whitelist_name", "")).strip()
        if not whitelist_name or whitelist_name.lower() == "default":
            raise ValueError("RDS 白名单名称禁止为空或使用 default")

        ipinfo_token = str(form.get("ipinfo_token", "")).strip()
        if "clear_ipinfo_token" in form:
            ipinfo_token = ""
        elif not ipinfo_token:
            ipinfo_token = current.ipinfo_token
        webhook_url = str(form.get("feishu_webhook_url", "")).strip()
        if "clear_feishu_webhook_url" in form:
            webhook_url = ""
        elif not webhook_url:
            webhook_url = current.feishu_webhook_url
        if webhook_url:
            parsed_url = urlparse(webhook_url)
            if parsed_url.scheme != "https" or not parsed_url.netloc:
                raise ValueError("飞书 Webhook 必须是有效 HTTPS 地址")

        settings = Settings(
            check_interval_seconds=interval,
            allowed_country=str(form.get("allowed_country", "")).strip(),
            allowed_region=str(form.get("allowed_region", "")).strip(),
            ipinfo_token=ipinfo_token,
            ecs_rule_description=description,
            rds_whitelist_name=whitelist_name,
            feishu_webhook_url=webhook_url,
            keep_history="keep_history" in form,
        )
        database.save_settings(settings)
    except ValueError as error:
        return render(
            request,
            "settings.html",
            settings=current,
            error=str(error),
            status_code=400,
        )
    request.session["flash"] = "设置已保存"
    return RedirectResponse("/settings", status_code=303)


@app.get("/accounts", response_class=HTMLResponse)
def accounts_page(request: Request):
    return render(request, "accounts.html", accounts=database.list_accounts())


@app.get("/accounts/new", response_class=HTMLResponse)
def new_account_page(request: Request):
    return render(request, "account_form.html", account=None, is_edit=False)


@app.get("/accounts/{account_id}/edit", response_class=HTMLResponse)
def edit_account_page(account_id: int, request: Request):
    account = database.get_account(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="账号不存在")
    return render(request, "account_form.html", account=account, is_edit=True)


@app.post("/accounts/save")
async def save_account(request: Request):
    form = await read_form(request)
    account_id_value = str(form.get("account_id", "")).strip()
    try:
        account_id = int(account_id_value) if account_id_value else None
    except ValueError as error:
        raise HTTPException(status_code=400, detail="账号 ID 无效") from error
    current = database.get_account(account_id) if account_id is not None else None
    if account_id is not None and current is None:
        raise HTTPException(status_code=404, detail="账号不存在")
    try:
        name = str(form.get("name", "")).strip().upper()
        access_key_id = str(form.get("access_key_id", "")).strip()
        access_key_secret = str(form.get("access_key_secret", "")).strip()
        if not name or not access_key_id:
            raise ValueError("账号名称和 AccessKey ID 禁止为空")
        if not access_key_secret:
            if current is None:
                raise ValueError("新账号必须填写 AccessKey Secret")
            access_key_secret = current.access_key_secret
        security_groups = parse_security_groups(
            str(form.get("security_groups", ""))
        )
        rds_instances = parse_rds_instances(str(form.get("rds_instances", "")))
        database.save_account(
            account_id,
            name,
            access_key_id,
            access_key_secret,
            security_groups,
            rds_instances,
        )
    except (ValueError, sqlite3.IntegrityError) as error:
        account = {
            "id": account_id_value,
            "name": str(form.get("name", "")),
            "access_key_id": str(form.get("access_key_id", "")),
            "security_groups": parse_rds_instances(
                str(form.get("security_groups", ""))
            ),
            "rds_instances": parse_rds_instances(
                str(form.get("rds_instances", ""))
            ),
        }
        return render(
            request,
            "account_form.html",
            account=account,
            is_edit=account_id is not None,
            error=f"保存失败: {error}",
            status_code=400,
        )
    request.session["flash"] = "账号配置已保存"
    return RedirectResponse("/accounts", status_code=303)


@app.post("/accounts/{account_id}/delete")
async def delete_account(account_id: int, request: Request):
    await read_form(request)
    database.delete_account(account_id)
    request.session["flash"] = "账号已删除"
    return RedirectResponse("/accounts", status_code=303)


@app.get("/additional-ips", response_class=HTMLResponse)
def additional_ips_page(request: Request):
    return render(
        request,
        "additional_ips.html",
        additional_ips=database.get_additional_ips(),
    )


@app.post("/additional-ips")
async def save_additional_ips(request: Request):
    form = await read_form(request)
    value = str(form.get("additional_ips", "")).replace("\n", ",")
    try:
        additional_ips = parse_additional_ips(value)
    except ValueError as error:
        return render(
            request,
            "additional_ips.html",
            additional_ips=tuple(
                item.strip() for item in value.split(",") if item.strip()
            ),
            error=str(error),
            status_code=400,
        )
    database.set_additional_ips(additional_ips)
    request.session["flash"] = "附加 IP 已保存"
    return RedirectResponse("/additional-ips", status_code=303)


@app.get("/runs", response_class=HTMLResponse)
def runs_page(request: Request):
    return render(request, "runs.html", runs=database.list_sync_runs(100))


@app.post("/sync")
async def run_sync(request: Request):
    await read_form(request)
    try:
        result = await run_in_threadpool(sync_once, database)
        request.session["flash"] = result["message"]
    except SyncAlreadyRunning as error:
        request.session["flash"] = str(error)
    except Exception as error:
        request.session["flash"] = f"同步失败: {error}"
    return RedirectResponse("/", status_code=303)
