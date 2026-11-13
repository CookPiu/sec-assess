# user-center 用户中心靶场

sec-assess 的教学靶场，故意包含 DESIGN.md 第 8 节列出的 U1–U3 漏洞，以及一个按当前用户过滤的诱饵接口。依赖里的 PyJWT 不在沙箱预装镜像中，用于验证依赖自动准备。只在 sec-assess 创建的无网络沙箱容器里运行，不要部署到任何可被他人访问的环境。

## 运行

```bash
pip install -r requirements.txt
python app.py
```

服务监听 `127.0.0.1:5000`，首次启动在当前目录生成 `users.db` 并写入两个示例用户和各自的订单，账号密码见 `db.py` 的 `SEED_USERS`。

## 接口

| 方法与路径 | 访问前提 | 说明 |
| --- | --- | --- |
| `POST /api/register` | 匿名 | JSON 字段 `username`、`password`、`email`、`phone` |
| `POST /api/login` | 匿名 | JSON 字段 `username`、`password`，返回 Bearer token |
| `GET /api/me` | 普通用户 | 当前用户资料 |
| `GET /api/users/<id>` | 普通用户 | 按 ID 查看用户资料（U1） |
| `GET /api/orders/<id>` | 普通用户 | 订单详情，只能看自己的订单（诱饵） |
| `GET /api/users/export` | 匿名 | 导出全部用户（U2） |

U3（`auth.py` 中写死的 `JWT_SECRET`）没有对应接口。
