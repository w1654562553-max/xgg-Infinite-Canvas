"""
用户认证模块

提供：
- 用户表（data/users.json）
- 登录 token（data/tokens/{hash}.json）
- 每个用户独立数据目录（data/users/{user_id}/）
- FastAPI 依赖项：get_current_user, require_admin
- 登录/登出/me/改密码/管理用户 API

默认管理员账号：admin / 123
所有新建账号初始密码：123
登录 token 永久有效（直到用户主动登出或被管理员撤销）
"""

import hashlib
import json
import os
import secrets
import time
import uuid
from threading import Lock
from typing import Optional, Dict, Any, List

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Header, Request, Response
from pydantic import BaseModel, Field

# 这些常量会在 main.py 里初始化时被覆盖
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.json")
TOKENS_DIR = os.path.join(DATA_DIR, "tokens")
USERS_DATA_DIR = os.path.join(DATA_DIR, "users")

_auth_lock = Lock()


# ---------- 用户表读写 ----------

def _ensure_dirs():
    os.makedirs(TOKENS_DIR, exist_ok=True)
    os.makedirs(USERS_DATA_DIR, exist_ok=True)


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def _load_users() -> Dict[str, Any]:
    if not os.path.exists(USERS_FILE):
        return {"users": []}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"users": []}


def _save_users(data: Dict[str, Any]):
    _ensure_dirs()
    tmp = USERS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, USERS_FILE)


def _user_dir(user_id: str) -> str:
    return os.path.join(USERS_DATA_DIR, user_id)


def ensure_user_dir(user_id: str):
    """确保用户数据目录存在（创建时调用一次）"""
    d = _user_dir(user_id)
    os.makedirs(d, exist_ok=True)
    for sub in ("canvases", "conversations", "media_previews"):
        os.makedirs(os.path.join(d, sub), exist_ok=True)


def ensure_admin():
    """确保 admin 账号存在。如果不存在则创建，并把现有 data/ 内容迁到 admin 数据目录。"""
    _ensure_dirs()
    data = _load_users()
    for u in data["users"]:
        if u.get("username") == "admin":
            return  # 已存在

    admin_id = uuid.uuid4().hex
    admin = {
        "id": admin_id,
        "username": "admin",
        "password_hash": _hash_password("123"),
        "is_admin": True,
        "must_change_password": True,  # 首次登录后强制改密码
        "created_at": int(time.time() * 1000),
        "last_login_at": None,
    }
    data["users"].append(admin)
    _save_users(data)
    ensure_user_dir(admin_id)

    # 把现有 data/ 内容迁到 admin 数据目录
    _migrate_existing_data_to_admin(admin_id)


def _migrate_existing_data_to_admin(admin_id: str):
    """把当前 data/ 下的用户数据文件迁到 admin 数据目录。
    仅在目标位置为空时迁移（避免覆盖已有数据）。
    """
    import shutil

    src = DATA_DIR
    dst = _user_dir(admin_id)

    # 要迁移的文件/目录
    migrate_items = [
        "canvases",
        "conversations",
        "media_previews",
        "asset_library.json",
        "prompt_libraries.json",
        "api_providers.json",
        "runninghub_workflows.json",
        "shared_folders.json",
    ]

    for item in migrate_items:
        src_path = os.path.join(src, item)
        dst_path = os.path.join(dst, item)
        if not os.path.exists(src_path):
            continue
        # 如果目标是空目录或不存在，才迁移
        try:
            if os.path.isdir(src_path):
                if not os.path.exists(dst_path):
                    shutil.copytree(src_path, dst_path)
                else:
                    # 目录已存在：把里面的内容合并过去
                    for entry in os.listdir(src_path):
                        s = os.path.join(src_path, entry)
                        d = os.path.join(dst_path, entry)
                        if os.path.isdir(s):
                            if not os.path.exists(d):
                                shutil.copytree(s, d)
                        else:
                            if not os.path.exists(d):
                                shutil.copy2(s, d)
            else:
                if not os.path.exists(dst_path):
                    shutil.copy2(src_path, dst_path)
        except Exception as e:
            print(f"[auth] 迁移 {item} 失败: {e}")


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    data = _load_users()
    for u in data["users"]:
        if u["id"] == user_id:
            return u
    return None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    data = _load_users()
    for u in data["users"]:
        if u["username"] == username:
            return u
    return None


# ---------- Token 管理 ----------

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _token_file(token: str) -> str:
    return os.path.join(TOKENS_DIR, _token_hash(token) + ".json")


def create_token(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    token_file = _token_file(token)
    _ensure_dirs()
    payload = {
        "token_hash": _token_hash(token),
        "user_id": user_id,
        "created_at": int(time.time() * 1000),
    }
    with open(token_file, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    return token


def revoke_token(token: str):
    token_file = _token_file(token)
    try:
        if os.path.exists(token_file):
            os.remove(token_file)
    except Exception:
        pass


def lookup_token(token: str) -> Optional[Dict[str, Any]]:
    token_file = _token_file(token)
    if not os.path.exists(token_file):
        return None
    try:
        with open(token_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def revoke_all_user_tokens(user_id: str):
    """撤销某个用户的所有 token（管理员重置密码时调用）"""
    if not os.path.exists(TOKENS_DIR):
        return
    for fn in os.listdir(TOKENS_DIR):
        fp = os.path.join(TOKENS_DIR, fn)
        try:
            with open(fp, "r", encoding="utf-8") as f:
                payload = json.load(f)
            if payload.get("user_id") == user_id:
                os.remove(fp)
        except Exception:
            pass


# ---------- Pydantic 模型 ----------

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(..., min_length=1, max_length=256)
    new_password: str = Field(..., min_length=6, max_length=256)


class AdminCreateUserRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: Optional[str] = Field(None, min_length=1, max_length=256)  # 默认 123


class AdminResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=1, max_length=256)


# ---------- FastAPI 依赖项 ----------

def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """FastAPI 依赖项：从 Authorization 头拿 token，返回当前用户"""
    if not authorization:
        raise HTTPException(status_code=401, detail="未登录")
    token = authorization
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    payload = lookup_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="登录已失效，请重新登录")
    user = get_user_by_id(payload["user_id"])
    if not user:
        raise HTTPException(status_code=401, detail="账号已不存在")
    return user


def get_current_user_optional(authorization: Optional[str] = Header(None)) -> Optional[Dict[str, Any]]:
    """FastAPI 依赖项：可选登录（用于判断是否需要跳登录页）"""
    if not authorization:
        return None
    token = authorization
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    payload = lookup_token(token)
    if not payload:
        return None
    return get_user_by_id(payload["user_id"])


def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="需要管理员权限")
    return user


# ---------- 辅助函数：把用户信息转成 API 返回值（不包含密码哈希） ----------

def public_user(u: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": u["id"],
        "username": u["username"],
        "is_admin": u.get("is_admin", False),
        "must_change_password": u.get("must_change_password", False),
        "created_at": u.get("created_at"),
        "last_login_at": u.get("last_login_at"),
    }


# ---------- API 路由 ----------

auth_router = APIRouter()


@auth_router.post("/api/login")
def login(body: LoginRequest):
    user = get_user_by_username(body.username)
    if not user or not _verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    token = create_token(user["id"])
    # 更新最后登录时间
    data = _load_users()
    for u in data["users"]:
        if u["id"] == user["id"]:
            u["last_login_at"] = int(time.time() * 1000)
            break
    _save_users(data)
    return {
        "token": token,
        "user": public_user(user),
    }


@auth_router.post("/api/logout")
def logout(authorization: Optional[str] = Header(None), user: Dict[str, Any] = Depends(get_current_user)):
    if authorization:
        token = authorization
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        revoke_token(token)
    return {"ok": True}


@auth_router.get("/api/me")
def me(user: Dict[str, Any] = Depends(get_current_user)):
    return public_user(user)


@auth_router.post("/api/me/password")
def change_my_password(body: ChangePasswordRequest, user: Dict[str, Any] = Depends(get_current_user)):
    if not _verify_password(body.old_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="旧密码错误")
    if body.old_password == body.new_password:
        raise HTTPException(status_code=400, detail="新密码不能和旧密码相同")

    data = _load_users()
    for u in data["users"]:
        if u["id"] == user["id"]:
            u["password_hash"] = _hash_password(body.new_password)
            u["must_change_password"] = False
            break
    _save_users(data)
    return {"ok": True, "message": "密码已更新"}


# ---------- 管理员 API ----------

@auth_router.get("/api/admin/users")
def admin_list_users(_admin: Dict[str, Any] = Depends(require_admin)):
    data = _load_users()
    return {"users": [public_user(u) for u in data["users"]]}


@auth_router.post("/api/admin/users")
def admin_create_user(body: AdminCreateUserRequest, admin: Dict[str, Any] = Depends(require_admin)):
    username = body.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="用户名不能为空")
    if get_user_by_username(username):
        raise HTTPException(status_code=400, detail="用户名已存在")

    password = body.password or "123"
    user_id = uuid.uuid4().hex
    new_user = {
        "id": user_id,
        "username": username,
        "password_hash": _hash_password(password),
        "is_admin": False,
        "must_change_password": True,
        "created_at": int(time.time() * 1000),
        "last_login_at": None,
        "created_by": admin["id"],
    }
    data = _load_users()
    data["users"].append(new_user)
    _save_users(data)
    ensure_user_dir(user_id)
    return public_user(new_user)


@auth_router.post("/api/admin/users/{user_id}/reset-password")
def admin_reset_password(user_id: str, body: AdminResetPasswordRequest, _admin: Dict[str, Any] = Depends(require_admin)):
    target = get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="用户不存在")
    if target.get("is_admin") and not _admin.get("is_admin"):
        raise HTTPException(status_code=403, detail="无法重置管理员密码")

    data = _load_users()
    for u in data["users"]:
        if u["id"] == user_id:
            u["password_hash"] = _hash_password(body.new_password)
            u["must_change_password"] = True  # 让用户登录后必须改
            break
    _save_users(data)
    # 重置密码后撤销该用户所有 token，强制重新登录
    revoke_all_user_tokens(user_id)
    return {"ok": True, "message": f"密码已重置为 {body.new_password}，用户需重新登录"}


@auth_router.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: str, _admin: Dict[str, Any] = Depends(require_admin)):
    if user_id == _admin["id"]:
        raise HTTPException(status_code=400, detail="不能删除自己")
    target = get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="用户不存在")
    if target.get("is_admin"):
        raise HTTPException(status_code=400, detail="不能删除管理员")

    data = _load_users()
    data["users"] = [u for u in data["users"] if u["id"] != user_id]
    _save_users(data)
    revoke_all_user_tokens(user_id)
    # 注意：用户数据目录不删除（作为软删除）
    return {"ok": True, "message": "用户已删除"}


# ---------- 当前用户数据路径解析 ----------

def current_user_data_dir(user: Dict[str, Any]) -> str:
    """返回当前用户的数据目录绝对路径"""
    return _user_dir(user["id"])