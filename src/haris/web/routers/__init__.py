from fastapi import APIRouter

from . import (
    account,
    admin,
    auth_login,
    health,
    llm_chat,
    llm_scan,
    oidc,
    pages,
    scan_data,
    scan_templates,
    scans,
    websites,
)

ALL_ROUTERS: list[APIRouter] = [
    health.router,
    auth_login.router,
    oidc.router,
    account.router,
    admin.router,
    pages.router,
    websites.router,
    scans.router,
    scan_data.router,
    scan_templates.router,
    llm_scan.router,
    llm_chat.router,
]
