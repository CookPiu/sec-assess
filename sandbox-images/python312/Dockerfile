# 评估沙箱镜像：Python 3.12 运行时 + Flask 常见依赖，任务运行时以非 root 用户、只读根文件系统、无网络启动。
FROM python:3.12-slim

ARG SANDBOX_UID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# 预装依赖：工程依赖拿不到 wheel 时，任务虚拟环境（--system-site-packages）回退到这里的版本。
# PyJWT 故意不预装，用于验证依赖自动准备（SC-010）。
RUN pip install \
        "flask>=3,<4" \
        "flask-sqlalchemy>=3.1,<4" \
        "flask-login>=0.6,<1" \
        "sqlalchemy>=2,<3" \
        "jinja2>=3.1,<4" \
        "werkzeug>=3,<4"

# /work 由任务专属 Docker 卷覆盖；新卷会继承这里的属主，非 root 用户才能写入。
RUN useradd --uid "${SANDBOX_UID}" --create-home --home-dir /home/sandbox --shell /usr/sbin/nologin sandbox \
    && mkdir -p /src /work /wheels /opt/probe \
    && chown "${SANDBOX_UID}:${SANDBOX_UID}" /work

USER ${SANDBOX_UID}:${SANDBOX_UID}
WORKDIR /work
CMD ["sleep", "infinity"]
