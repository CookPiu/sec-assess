# shop-admin 电商后台靶场

sec-assess 的教学靶场，故意包含 DESIGN.md 第 8 节列出的 S1–S9 漏洞，以及外观相似但已正确防护的诱饵写法。只在 sec-assess 创建的无网络沙箱容器里运行，不要部署到任何可被他人访问的环境。

## 运行

```bash
pip install -r requirements.txt
python app.py
```

服务监听 `127.0.0.1:5000`，首次启动在当前目录生成 `shop.db` 并写入种子数据：管理员 `admin` 与普通账号 `operator`，密码见 `db.py` 的 `SEED_USERS`。

## 接口

| 方法与路径 | 访问前提 | 说明 |
| --- | --- | --- |
| `GET /orders/search?keyword=` | 匿名 | 按客户名查询订单（S1） |
| `GET /products?sort=` | 匿名 | 商品列表，排序列走白名单（诱饵） |
| `GET /products/<id>` | 匿名 | 商品详情，参数化查询（诱饵） |
| `GET /debug/config` | 匿名 | 返回部分配置（S2） |
| `POST /login`、`POST /logout` | 匿名 | 表单字段 `username`、`password` |
| `POST /admin/logistics/ping` | 管理员 | 物流节点连通性检测（S6） |
| `POST /admin/logistics/lookup` | 管理员 | 域名解析检测，列表参数调用（诱饵） |
| `POST /admin/backup/import` | 管理员 | 导入备份文件（S7） |
| `POST /admin/mail/preview` | 管理员 | 邮件模板预览（S8） |
| `POST /admin/products/<id>/image` | 管理员 | 上传商品图片（S9） |
| `POST /admin/products/<id>/manual` | 管理员 | 上传说明书，文件名经过 `secure_filename`（诱饵） |

源码中的 S3（`app.run(debug=True)`）、S4（`config.py` 中的 `SECRET_KEY`）、S5（无盐 MD5 密码）没有对应接口。
