```markdown
# FilmCMS

基于 Cloudflare Workers + D1 + KV 构建的轻量级影视内容管理系统，无需服务器，免费部署。

## 功能特性

- 🎬 影片管理（增删改查、关键词搜索）
- 📡 采集源管理（支持苹果 CMS V10 接口格式）
- 📋 采集任务记录
- 🏷️ 分类管理
- 🔐 管理员登录 / 修改密码
- ⚡ 全部运行在 Cloudflare Edge，无需服务器

## 技术栈

- **运行时**：Cloudflare Workers
- **数据库**：Cloudflare D1（SQLite）
- **缓存**：Cloudflare KV
- **前端**：原生 HTML + JS（内嵌在 Worker）
- **认证**：JWT（HMAC-SHA256）

## 部署教程

### 1. 创建 D1 数据库

1. 登录 [dash.cloudflare.com](https://dash.cloudflare.com)
2. 进入 **Storage & Databases → D1 SQL Database**
3. 创建数据库，名称：`filmcms-db`
4. 在 **Console** 中逐条执行以下建表 SQL：

```sql
CREATE TABLE IF NOT EXISTS admins (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS movies (
  id TEXT PRIMARY KEY,
  source_id TEXT,
  remote_id TEXT,
  title TEXT NOT NULL,
  poster_url TEXT,
  type TEXT,
  year TEXT,
  rating TEXT,
  description TEXT,
  play_sources TEXT,
  created_at INTEGER,
  updated_at INTEGER
);

CREATE TABLE IF NOT EXISTS collect_sources (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  api_url TEXT NOT NULL,
  auto_collect INTEGER DEFAULT 0,
  enabled INTEGER DEFAULT 1,
  last_collected_at INTEGER,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS collect_tasks (
  id TEXT PRIMARY KEY,
  source_id TEXT,
  source_name TEXT,
  trigger TEXT,
  status TEXT,
  total INTEGER DEFAULT 0,
  inserted INTEGER DEFAULT 0,
  updated INTEGER DEFAULT 0,
  started_at INTEGER,
  finished_at INTEGER
);

CREATE TABLE IF NOT EXISTS categories (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL
);
```

再单独执行插入默认管理员：

```sql
INSERT OR IGNORE INTO admins (id, username, password_hash) VALUES (
  'admin-001',
  'admin',
  '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9'
);
```

### 2. 创建 KV 命名空间

1. 进入 **Storage & Databases → KV**
2. 创建命名空间，名称：`filmcms-kv`

### 3. 创建 Worker

1. 进入 **Workers & Pages → Create Worker**
2. 粘贴 `worker.js` 全部代码 → Deploy

### 4. 绑定环境变量

在 Worker **Settings → Bindings** 中添加：

| Type | Variable Name | 值 |
|------|-------------|---|
| D1 Database | `DB` | 选择 `filmcms-db` |
| KV Namespace | `KV` | 选择 `filmcms-kv` |
| Text | `JWT_SECRET` | 任意随机字符串 |

## 默认账号

| 字段 | 值 |
|------|----|
| 账号 | `admin` |
| 密码 | `admin123` |

> ⚠️ 首次登录后请立即在「设置 → 修改密码」中更改默认密码。

## 采集源格式

支持标准苹果 CMS V10 JSON API，接口格式示例：

```
https://example.com/api.php/provide/vod
```

## License

MIT
```
