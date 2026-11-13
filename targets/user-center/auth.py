"""JWT 签发与登录校验。

U3 硬编码密钥：JWT 签名密钥直接写在源码里。
"""

import datetime
import functools

import jwt
from flask import abort, g, request

JWT_SECRET = "user-center-signing-key-2024"
TOKEN_HOURS = 12


def issue_token(user_id: int) -> str:
    expires = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=TOKEN_HOURS)
    return jwt.encode({"sub": str(user_id), "exp": expires}, JWT_SECRET, algorithm="HS256")


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            abort(401)
        try:
            payload = jwt.decode(header[7:], JWT_SECRET, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            abort(401)
        g.user_id = int(payload["sub"])
        return view(*args, **kwargs)

    return wrapped
