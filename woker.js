async function generateToken(payload, secret) {
  const enc = (obj) => btoa(JSON.stringify(obj)).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')
  const header = { alg: 'HS256', typ: 'JWT' }
  const data = `${enc(header)}.${enc(payload)}`
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g,'').replace(/\+/g,'-').replace(/\//g,'_')
  return `${data}.${sigB64}`
}

async function verifyToken(token, secret) {
  try {
    const [header, payload, sig] = token.split('.')
    const data = `${header}.${payload}`
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['verify'])
    const sigBuf = Uint8Array.from(atob(sig.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0))
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf, new TextEncoder().encode(data))
    if (!valid) return null
    const decoded = JSON.parse(atob(payload.replace(/-/g,'+').replace(/_/g,'/')))
    if (decoded.exp && decoded.exp < Date.now()/1000) return null
    return decoded
  } catch { return null }
}

async function hashPassword(password) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('')
}

function generateId() { return crypto.randomUUID() }

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type':'application/json', 'Access-Control-Allow-Origin':'*' }
  })
}

async function authMiddleware(request, env) {
  const auth = request.headers.get('Authorization') || ''
  const token = auth.replace('Bearer ','')
  if (!token) return null
  return await verifyToken(token, env.JWT_SECRET)
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url)
    const path = url.pathname
    const method = request.method

    if (method === 'OPTIONS') {
      return new Response(null, { headers: {
        'Access-Control-Allow-Origin':'*',
        'Access-Control-Allow-Methods':'GET,POST,PUT,DELETE,OPTIONS',
        'Access-Control-Allow-Headers':'Content-Type,Authorization'
      }})
    }

    if (path === '/api/ping') return json({ ok: true, time: new Date().toISOString() })

    if (path === '/api/admin/login' && method === 'POST') {
      const { username, password } = await request.json()
      const hash = await hashPassword(password)
      const admin = await env.DB.prepare('SELECT * FROM admins WHERE username=? AND password_hash=?').bind(username, hash).first()
      if (!admin) return json({ error:'用户名或密码错误' }, 401)
      const token = await generateToken({ id: admin.id, username: admin.username, exp: Math.floor(Date.now()/1000)+86400*7 }, env.JWT_SECRET)
      return json({ token, username: admin.username })
    }

    if (path === '/api/admin/password' && method === 'POST') {
      const user = await authMiddleware(request, env)
      if (!user) return json({ error:'未授权' }, 401)
      const { oldPassword, newPassword } = await request.json()
      const oldHash = await hashPassword(oldPassword)
      const admin = await env.DB.prepare('SELECT * FROM admins WHERE id=? AND password_hash=?').bind(user.id, oldHash).first()
      if (!admin) return json({ error:'原密码错误' }, 400)
      const newHash = await hashPassword(newPassword)
      await env.DB.prepare('UPDATE admins SET password_hash=? WHERE id=?').bind(newHash, user.id).run()
      return json({ ok: true })
    }

    if (path === '/api/movies' && method === 'GET') {
      const page = parseInt(url.searchParams.get('page') || '1')
      const limit = parseInt(url.searchParams.get('limit') || '20')
      const keyword = url.searchParams.get('keyword') || ''
      const offset = (page-1)*limit
      let movies, total
      if (keyword) {
        movies = await env.DB.prepare('SELECT * FROM movies WHERE title LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(`%${keyword}%`, limit, offset).all()
        total = await env.DB.prepare('SELECT COUNT(*) as count FROM movies WHERE title LIKE ?').bind(`%${keyword}%`).first()
      } else {
        movies = await env.DB.prepare('SELECT * FROM movies ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(limit, offset).all()
        total = await env.DB.prepare('SELECT COUNT(*) as count FROM movies').first()
      }
      return json({ list: movies.results, total: total.count, page, limit })
    }

    if (path === '/api/movies' && method === 'POST') {
      const user = await authMiddleware(request, env)
      if (!user) return json({ error:'未授权' }, 401)
      const body = await request.json()
      const id = generateId()
      const now = Math.floor(Date.now()/1000)
      await env.DB.prepare('INSERT INTO movies (id,title,poster_url,type,year,rating,description,play_sources,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(id, body.title, body.poster_url||'', body.type||'', body.year||'', body.rating||'', body.description||'', body.play_sources||'[]', now, now).run()
      return json({ ok: true, id })
    }

    const movieMatch = path.match(/^\/api\/movies\/([^/]+)$/)
    if (movieMatch) {
      const id = movieMatch[1]
      if (method === 'GET') {
        const movie = await env.DB.prepare('SELECT * FROM movies WHERE id=?').bind(id).first()
        if (!movie) return json({ error:'不存在' }, 404)
        return json(movie)
      }
      if (method === 'PUT') {
        const user = await authMiddleware(request, env)
        if (!user) return json({ error:'未授权' }, 401)
        const body = await request.json()
        const now = Math.floor(Date.now()/1000)
        await env.DB.prepare('UPDATE movies SET title=?,poster_url=?,type=?,year=?,rating=?,description=?,play_sources=?,updated_at=? WHERE id=?').bind(body.title, body.poster_url||'', body.type||'', body.year||'', body.rating||'', body.description||'', body.play_sources||'[]', now, id).run()
        return json({ ok: true })
      }
      if (method === 'DELETE') {
        const user = await authMiddleware(request, env)
        if (!user) return json({ error:'未授权' }, 401)
        await env.DB.prepare('DELETE FROM movies WHERE id=?').bind(id).run()
        return json({ ok: true })
      }
    }

    if (path === '/api/sources' && method === 'GET') {
      const user = await authMiddleware(request, env)
      if (!user) return json({ error:'未授权' }, 401)
      const sources = await env.DB.prepare('SELECT * FROM collect_sources ORDER BY created_at DESC').all()
      return json(sources.results)
    }

    if (path === '/api/sources' && method === 'POST') {
      const user = await authMiddleware(request, env)
      if (!user) return json({ error:'未授权' }, 401)
      const body = await request.json()
      const id = generateId()
      const now = Math.floor(Date.now()/1000)
      await env.DB.prepare('INSERT INTO collect_sources (id,name,api_url,auto_collect,enabled,created_at) VALUES (?,?,?,?,?,?)').bind(id, body.name, body.api_url, body.auto_collect?1:0, 1, now).run()
      return json({ ok: true, id })
    }

    const srcMatch = path.match(/^\/api\/sources\/([^/]+)$/)
    if (srcMatch && method === 'DELETE') {
      const user = await authMiddleware(request, env)
      if (!user) return json({ error:'未授权' }, 401)
      await env.DB.prepare('DELETE FROM collect_sources WHERE id=?').bind(srcMatch[1]).run()
      return json({ ok: true })
    }

    const collectMatch = path.match(/^\/api\/sources\/([^/]+)\/collect$/)
    if (collectMatch && method === 'POST') {
      const user = await authMiddleware(request, env)
      if (!user) return json({ error:'未授权' }, 401)
      const sourceId = collectMatch[1]
      const source = await env.DB.prepare('SELECT * FROM collect_sources WHERE id=?').bind(sourceId).first()
      if (!source) return json({ error:'采集源不存在' }, 404)
      const taskId = generateId()
      const now = Math.floor(Date.now()/1000)
      await env.DB.prepare('INSERT INTO collect_tasks (id,source_id,source_name,trigger,status,total,inserted,updated,started_at) VALUES (?,?,?,?,?,?,?,?,?)').bind(taskId, sourceId, source.name, 'manual', 'running', 0, 0, 0, now).run()
      ctx.waitUntil(doCollect(env, source, taskId))
      return json({ ok: true, taskId })
    }

    if (path === '/api/tasks' && method === 'GET') {
      const user = await authMiddleware(request, env)
      if (!user) return json({ error:'未授权' }, 401)
      const tasks = await env.DB.prepare('SELECT * FROM collect_tasks ORDER BY started_at DESC LIMIT 50').all()
      return json(tasks.results)
    }

    if (path === '/api/categories' && method === 'GET') {
      const cats = await env.DB.prepare('SELECT * FROM categories ORDER BY name').all()
      return json(cats.results)
    }

    if (path === '/api/categories' && method === 'POST') {
      const user = await authMiddleware(request, env)
      if (!user) return json({ error:'未授权' }, 401)
      const body = await request.json()
      const id = generateId()
      await env.DB.prepare('INSERT INTO categories (id,name,slug) VALUES (?,?,?)').bind(id, body.name, body.slug).run()
      return json({ ok: true, id })
    }

    const catMatch = path.match(/^\/api\/categories\/([^/]+)$/)
    if (catMatch && method === 'DELETE') {
      const user = await authMiddleware(request, env)
      if (!user) return json({ error:'未授权' }, 401)
      await env.DB.prepare('DELETE FROM categories WHERE id=?').bind(catMatch[1]).run()
      return json({ ok: true })
    }

    if (path === '/admin' || path === '/admin/' || path.startsWith('/admin/') || path === '/' || path === '') {
      return new Response(getAdminHTML(), { headers: { 'Content-Type':'text/html;charset=UTF-8' } })
    }

    return json({ error:'Not Found' }, 404)
  }
}

async function doCollect(env, source, taskId) {
  try {
    let inserted = 0, updated = 0, total = 0
    const res = await fetch(`${source.api_url}?ac=list`)
    const data = await res.json()
    total = data.total || 0
    const pageCount = Math.ceil(total / (data.limit || 20))
    for (let p = 1; p <= Math.min(pageCount, 10); p++) {
      const pageRes = await fetch(`${source.api_url}?ac=detail&pg=${p}`)
      const pageData = await pageRes.json()
      for (const item of (pageData.list || [])) {
        const existing = await env.DB.prepare('SELECT id FROM movies WHERE source_id=? AND remote_id=?').bind(source.id, String(item.vod_id)).first()
        const now = Math.floor(Date.now()/1000)
        const playSources = JSON.stringify(item.vod_play_url || '')
        if (existing) {
          await env.DB.prepare('UPDATE movies SET title=?,poster_url=?,type=?,year=?,rating=?,description=?,play_sources=?,updated_at=? WHERE id=?').bind(item.vod_name, item.vod_pic||'', item.type_name||'', String(item.vod_year||''), String(item.vod_score||''), item.vod_content||'', playSources, now, existing.id).run()
          updated++
        } else {
          const id = generateId()
          await env.DB.prepare('INSERT INTO movies (id,source_id,remote_id,title,poster_url,type,year,rating,description,play_sources,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)').bind(id, source.id, String(item.vod_id), item.vod_name, item.vod_pic||'', item.type_name||'', String(item.vod_year||''), String(item.vod_score||''), item.vod_content||'', playSources, now, now).run()
          inserted++
        }
      }
    }
    await env.DB.prepare('UPDATE collect_tasks SET status=?,total=?,inserted=?,updated=?,finished_at=? WHERE id=?').bind('done', total, inserted, updated, Math.floor(Date.now()/1000), taskId).run()
    await env.DB.prepare('UPDATE collect_sources SET last_collected_at=? WHERE id=?').bind(Math.floor(Date.now()/1000), source.id).run()
  } catch(e) {
    await env.DB.prepare('UPDATE collect_tasks SET status=?,finished_at=? WHERE id=?').bind('error', Math.floor(Date.now()/1000), taskId).run()
  }
}

function getAdminHTML() {
  return `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>FilmCMS 管理后台</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;color:#333}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh}
.login-box{background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);width:360px}
.login-box h2{text-align:center;margin-bottom:28px;font-size:22px}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-size:14px;color:#555}
.form-group input,.form-group textarea,.form-group select{width:100%;padding:10px 14px;border:1px solid #ddd;border-radius:8px;font-size:14px;outline:none;transition:border .2s}
.form-group input:focus,.form-group textarea:focus{border-color:#1677ff}
.form-group textarea{resize:vertical;min-height:80px}
.btn{display:inline-block;padding:10px 20px;border:none;border-radius:8px;cursor:pointer;font-size:14px;transition:all .2s}
.btn-primary{background:#1677ff;color:#fff}
.btn-primary:hover{background:#0958d9}
.btn-danger{background:#ff4d4f;color:#fff}
.btn-danger:hover{background:#cf1322}
.btn-default{background:#fff;border:1px solid #ddd;color:#333}
.btn-default:hover{border-color:#1677ff;color:#1677ff}
.btn-block{width:100%;display:block}
.layout{display:flex;min-height:100vh}
.sidebar{width:200px;background:#001529;color:#fff;flex-shrink:0}
.sidebar-logo{padding:20px;font-size:18px;font-weight:bold;border-bottom:1px solid rgba(255,255,255,.1)}
.sidebar-menu{list-style:none;padding:8px 0}
.sidebar-menu li a{display:block;padding:12px 20px;color:rgba(255,255,255,.65);text-decoration:none;transition:all .2s;font-size:14px}
.sidebar-menu li a:hover,.sidebar-menu li a.active{background:#1677ff;color:#fff}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.topbar{background:#fff;padding:0 24px;height:56px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.topbar-title{font-size:16px;font-weight:600}
.content{padding:24px;flex:1;overflow-y:auto}
.card{background:#fff;border-radius:10px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.06);margin-bottom:20px}
.card-title{font-size:16px;font-weight:600;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid #f0f0f0}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}
.stat-card{background:#fff;border-radius:10px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.06);text-align:center}
.stat-num{font-size:32px;font-weight:bold;color:#1677ff}
.stat-label{font-size:13px;color:#888;margin-top:4px}
table{width:100%;border-collapse:collapse}
th,td{padding:12px 16px;text-align:left;border-bottom:1px solid #f0f0f0;font-size:14px}
th{background:#fafafa;font-weight:600;color:#555}
tr:hover td{background:#fafafa}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px}
.tag-blue{background:#e6f4ff;color:#1677ff}
.tag-green{background:#f6ffed;color:#52c41a}
.tag-red{background:#fff2f0;color:#ff4d4f}
.tag-orange{background:#fff7e6;color:#fa8c16}
.search-bar{display:flex;gap:10px;margin-bottom:16px}
.search-bar input{flex:1;padding:8px 14px;border:1px solid #ddd;border-radius:8px;font-size:14px;outline:none}
.search-bar input:focus{border-color:#1677ff}
.modal-mask{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:1000;display:flex;align-items:center;justify-content:center}
.modal{background:#fff;border-radius:12px;padding:24px;width:500px;max-height:80vh;overflow-y:auto;box-shadow:0 8px 32px rgba(0,0,0,.15)}
.modal-title{font-size:18px;font-weight:600;margin-bottom:20px}
.modal-footer{margin-top:20px;display:flex;justify-content:flex-end;gap:10px}
.pagination{display:flex;gap:6px;align-items:center;justify-content:center;margin-top:16px}
.pagination button{padding:6px 12px;border:1px solid #ddd;border-radius:6px;background:#fff;cursor:pointer;font-size:13px}
.pagination button.active{background:#1677ff;color:#fff;border-color:#1677ff}
.pagination button:disabled{opacity:.4;cursor:not-allowed}
.hidden{display:none!important}
.alert{padding:10px 16px;border-radius:8px;margin-bottom:12px;font-size:14px}
.alert-error{background:#fff2f0;color:#ff4d4f;border:1px solid #ffccc7}
.alert-success{background:#f6ffed;color:#52c41a;border:1px solid #b7eb8f}
</style>
</head>
<body>
<div id="app"></div>
<script>
const API = ''
let token = localStorage.getItem('cms_token') || ''
let currentUser = localStorage.getItem('cms_user') || ''
let currentPage = 'dashboard'
let moviePage = 1
let movieTotal = 0
let movieKeyword = ''

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' }
  if (token) headers['Authorization'] = 'Bearer ' + token
  const res = await fetch(API + path, { method, headers, body: body ? JSON.stringify(body) : undefined })
  return res.json()
}

function render() {
  if (!token) { renderLogin(); return }
  renderLayout()
}

function renderLogin() {
  document.getElementById('app').innerHTML = \`
    <div class="login-wrap">
      <div class="login-box">
        <h2>🎬 FilmCMS</h2>
        <div id="login-alert"></div>
        <div class="form-group"><label>用户名</label><input id="username" placeholder="admin"></div>
        <div class="form-group"><label>密码</label><input id="password" type="password" placeholder="••••••"></div>
        <button class="btn btn-primary btn-block" onclick="doLogin()">登 录</button>
      </div>
    </div>
  \`
  document.getElementById('password').addEventListener('keydown', e => { if(e.key==='Enter') doLogin() })
}

async function doLogin() {
  const username = document.getElementById('username').value.trim()
  const password = document.getElementById('password').value
  if (!username || !password) return
  const res = await request('POST', '/api/admin/login', { username, password })
  if (res.token) {
    token = res.token
    currentUser = res.username
    localStorage.setItem('cms_token', token)
    localStorage.setItem('cms_user', currentUser)
    render()
  } else {
    document.getElementById('login-alert').innerHTML = \`<div class="alert alert-error">\${res.error||'登录失败'}</div>\`
  }
}

function renderLayout() {
  document.getElementById('app').innerHTML = \`
    <div class="layout">
      <div class="sidebar">
        <div class="sidebar-logo">🎬 FilmCMS</div>
        <ul class="sidebar-menu">
          <li><a href="#" onclick="nav('dashboard')" id="nav-dashboard">📊 仪表盘</a></li>
          <li><a href="#" onclick="nav('movies')" id="nav-movies">🎬 影片管理</a></li>
          <li><a href="#" onclick="nav('sources')" id="nav-sources">📡 采集源</a></li>
          <li><a href="#" onclick="nav('tasks')" id="nav-tasks">📋 采集任务</a></li>
          <li><a href="#" onclick="nav('categories')" id="nav-categories">🏷️ 分类管理</a></li>
          <li><a href="#" onclick="nav('settings')" id="nav-settings">⚙️ 设置</a></li>
        </ul>
      </div>
      <div class="main">
        <div class="topbar">
          <div class="topbar-title" id="topbar-title">仪表盘</div>
          <div style="display:flex;align-items:center;gap:12px">
            <span style="font-size:14px;color:#888">👤 \${currentUser}</span>
            <button class="btn btn-default" onclick="logout()" style="padding:6px 14px">退出</button>
          </div>
        </div>
        <div class="content" id="content"></div>
      </div>
    </div>
  \`
  nav(currentPage)
}

function nav(page) {
  currentPage = page
  document.querySelectorAll('.sidebar-menu a').forEach(a => a.classList.remove('active'))
  const el = document.getElementById('nav-'+page)
  if (el) el.classList.add('active')
  const titles = { dashboard:'仪表盘', movies:'影片管理', sources:'采集源管理', tasks:'采集任务', categories:'分类管理', settings:'设置' }
  document.getElementById('topbar-title').textContent = titles[page] || page
  const pages = { dashboard: renderDashboard, movies: renderMovies, sources: renderSources, tasks: renderTasks, categories: renderCategories, settings: renderSettings }
  if (pages[page]) pages[page]()
  return false
}

async function renderDashboard() {
  const content = document.getElementById('content')
  content.innerHTML = '<div style="text-align:center;padding:40px;color:#888">加载中...</div>'
  const [moviesRes, sourcesRes] = await Promise.all([
    request('GET', '/api/movies?limit=1'),
    request('GET', '/api/sources')
  ])
  const movieCount = moviesRes.total || 0
  const sourceCount = Array.isArray(sourcesRes) ? sourcesRes.length : 0
  content.innerHTML = \`
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-num">\${movieCount}</div><div class="stat-label">总影片数</div></div>
      <div class="stat-card"><div class="stat-num">\${sourceCount}</div><div class="stat-label">采集源数</div></div>
      <div class="stat-card"><div class="stat-num">0</div><div class="stat-label">今日新增</div></div>
      <div class="stat-card"><div class="stat-num">v1.0</div><div class="stat-label">系统版本</div></div>
    </div>
    <div class="card">
      <div class="card-title">快速操作</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap">
        <button class="btn btn-primary" onclick="nav('movies')">➕ 添加影片</button>
        <button class="btn btn-primary" onclick="nav('sources')">📡 管理采集源</button>
        <button class="btn btn-default" onclick="nav('tasks')">📋 查看采集任务</button>
      </div>
    </div>
  \`
}

async function renderMovies() {
  const content = document.getElementById('content')
  content.innerHTML = '<div style="text-align:center;padding:40px;color:#888">加载中...</div>'
  const res = await request('GET', \`/api/movies?page=\${moviePage}&limit=20&keyword=\${movieKeyword}\`)
  movieTotal = res.total || 0
  const totalPages = Math.ceil(movieTotal / 20)
  content.innerHTML = \`
    <div class="card">
      <div class="search-bar">
        <input id="movie-search" placeholder="搜索影片标题..." value="\${movieKeyword}">
        <button class="btn btn-primary" onclick="searchMovies()">搜索</button>
        <button class="btn btn-default" onclick="clearSearch()">清空</button>
        <button class="btn btn-primary" onclick="showAddMovie()" style="margin-left:auto">+ 添加影片</button>
      </div>
      <div style="margin-bottom:12px;font-size:13px;color:#888">共 \${movieTotal} 条记录</div>
      <table>
        <thead><tr><th>标题</th><th>类型</th><th>年份</th><th>评分</th><th>操作</th></tr></thead>
        <tbody>
          \${(res.list||[]).map(m => \`
            <tr>
              <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">\${m.title}</td>
              <td><span class="tag tag-blue">\${m.type||'-'}</span></td>
              <td>\${m.year||'-'}</td>
              <td>\${m.rating||'-'}</td>
              <td>
                <button class="btn btn-default" style="padding:4px 10px;font-size:12px" onclick="editMovie('\${m.id}')">编辑</button>
                <button class="btn btn-danger" style="padding:4px 10px;font-size:12px;margin-left:6px" onclick="deleteMovie('\${m.id}','\${m.title}')">删除</button>
              </td>
            </tr>
          \`).join('')}
        </tbody>
      </table>
      <div class="pagination">
        <button onclick="movieGoPage(\${moviePage-1})" \${moviePage<=1?'disabled':''}>上一页</button>
        <span style="padding:0 10px;font-size:13px">\${moviePage} / \${totalPages||1}</span>
        <button onclick="movieGoPage(\${moviePage+1})" \${moviePage>=totalPages?'disabled':''}>下一页</button>
      </div>
    </div>
  \`
  document.getElementById('movie-search').addEventListener('keydown', e => { if(e.key==='Enter') searchMovies() })
}

function searchMovies() { movieKeyword = document.getElementById('movie-search').value.trim(); moviePage = 1; renderMovies() }
function clearSearch() { movieKeyword = ''; moviePage = 1; renderMovies() }
function movieGoPage(p) { if(p<1) return; moviePage = p; renderMovies() }

function showAddMovie() {
  showMovieModal()
}

async function editMovie(id) {
  const movie = await request('GET', \`/api/movies/\${id}\`)
  showMovieModal(movie)
}

function showMovieModal(movie = null) {
  const isEdit = !!movie
  document.body.insertAdjacentHTML('beforeend', \`
    <div class="modal-mask" id="movie-modal">
      <div class="modal">
        <div class="modal-title">\${isEdit?'编辑影片':'添加影片'}</div>
        <div class="form-group"><label>标题 *</label><input id="m-title" value="\${movie?.title||''}"></div>
        <div class="form-group"><label>封面URL</label><input id="m-poster" value="\${movie?.poster_url||''}"></div>
        <div class="form-group"><label>类型</label><input id="m-type" value="\${movie?.type||''}" placeholder="电影/电视剧/综艺..."></div>
        <div class="form-group"><label>年份</label><input id="m-year" value="\${movie?.year||''}"></div>
        <div class="form-group"><label>评分</label><input id="m-rating" value="\${movie?.rating||''}"></div>
        <div class="form-group"><label>简介</label><textarea id="m-desc">\${movie?.description||''}</textarea></div>
        <div class="form-group"><label>播放源 (JSON)</label><textarea id="m-play" style="min-height:100px">\${movie?.play_sources||'[]'}</textarea></div>
        <div id="movie-modal-alert"></div>
        <div class="modal-footer">
          <button class="btn btn-default" onclick="closeModal('movie-modal')">取消</button>
          <button class="btn btn-primary" onclick="saveMovie('\${movie?.id||''}')">\${isEdit?'保存':'添加'}</button>
        </div>
      </div>
    </div>
  \`)
}

async function saveMovie(id) {
  const body = {
    title: document.getElementById('m-title').value.trim(),
    poster_url: document.getElementById('m-poster').value.trim(),
    type: document.getElementById('m-type').value.trim(),
    year: document.getElementById('m-year').value.trim(),
    rating: document.getElementById('m-rating').value.trim(),
    description: document.getElementById('m-desc').value.trim(),
    play_sources: document.getElementById('m-play').value.trim()
  }
  if (!body.title) { document.getElementById('movie-modal-alert').innerHTML = '<div class="alert alert-error">标题不能为空</div>'; return }
  const res = id ? await request('PUT', \`/api/movies/\${id}\`, body) : await request('POST', '/api/movies', body)
  if (res.ok) { closeModal('movie-modal'); renderMovies() }
  else document.getElementById('movie-modal-alert').innerHTML = \`<div class="alert alert-error">\${res.error||'操作失败'}</div>\`
}

async function deleteMovie(id, title) {
  if (!confirm(\`确定删除《\${title}》？\`)) return
  await request('DELETE', \`/api/movies/\${id}\`)
  renderMovies()
}

async function renderSources() {
  const content = document.getElementById('content')
  content.innerHTML = '<div style="text-align:center;padding:40px;color:#888">加载中...</div>'
  const sources = await request('GET', '/api/sources')
  content.innerHTML = \`
    <div class="card">
      <div style="display:flex;justify-content:flex-end;margin-bottom:16px">
        <button class="btn btn-primary" onclick="showAddSource()">+ 添加采集源</button>
      </div>
      <table>
        <thead><tr><th>名称</th><th>API地址</th><th>最后采集</th><th>操作</th></tr></thead>
        <tbody>
          \${(Array.isArray(sources)?sources:[]).map(s => \`
            <tr>
              <td>\${s.name}</td>
              <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:#888">\${s.api_url}</td>
              <td>\${s.last_collected_at ? new Date(s.last_collected_at*1000).toLocaleString() : '从未'}</td>
              <td>
                <button class="btn btn-primary" style="padding:4px 10px;font-size:12px" onclick="collectNow('\${s.id}','\${s.name}')">立即采集</button>
                <button class="btn btn-danger" style="padding:4px 10px;font-size:12px;margin-left:6px" onclick="deleteSource('\${s.id}','\${s.name}')">删除</button>
              </td>
            </tr>
          \`).join('')}
        </tbody>
      </table>
    </div>
  \`
}

function showAddSource() {
  document.body.insertAdjacentHTML('beforeend', \`
    <div class="modal-mask" id="source-modal">
      <div class="modal">
        <div class="modal-title">添加采集源</div>
        <div class="form-group"><label>名称 *</label><input id="s-name" placeholder="如：某某资源站"></div>
        <div class="form-group"><label>API地址 *</label><input id="s-url" placeholder="https://example.com/api.php/provide/vod"></div>
        <div id="source-modal-alert"></div>
        <div class="modal-footer">
          <button class="btn btn-default" onclick="closeModal('source-modal')">取消</button>
          <button class="btn btn-primary" onclick="saveSource()">添加</button>
        </div>
      </div>
    </div>
  \`)
}

async function saveSource() {
  const name = document.getElementById('s-name').value.trim()
  const api_url = document.getElementById('s-url').value.trim()
  if (!name || !api_url) { document.getElementById('source-modal-alert').innerHTML = '<div class="alert alert-error">名称和API地址不能为空</div>'; return }
  const res = await request('POST', '/api/sources', { name, api_url })
  if (res.ok) { closeModal('source-modal'); renderSources() }
  else document.getElementById('source-modal-alert').innerHTML = \`<div class="alert alert-error">\${res.error||'添加失败'}</div>\`
}

async function collectNow(id, name) {
  if (!confirm(\`立即采集「\${name}」？\`)) return
  const res = await request('POST', \`/api/sources/\${id}/collect\`)
  if (res.ok) { alert('采集任务已启动，请在「采集任务」页查看进度'); nav('tasks') }
  else alert(res.error || '启动失败')
}

async function deleteSource(id, name) {
  if (!confirm(\`确定删除采集源「\${name}」？\`)) return
  await request('DELETE', \`/api/sources/\${id}\`)
  renderSources()
}

async function renderTasks() {
  const content = document.getElementById('content')
  content.innerHTML = '<div style="text-align:center;padding:40px;color:#888">加载中...</div>'
  const tasks = await request('GET', '/api/tasks')
  content.innerHTML = \`
    <div class="card">
      <div style="display:flex;justify-content:flex-end;margin-bottom:16px">
        <button class="btn btn-default" onclick="renderTasks()">🔄 刷新</button>
      </div>
      <table>
        <thead><tr><th>采集源</th><th>触发方式</th><th>状态</th><th>总数/新增/更新</th><th>开始时间</th></tr></thead>
        <tbody>
          \${(Array.isArray(tasks)?tasks:[]).map(t => \`
            <tr>
              <td>\${t.source_name}</td>
              <td>\${t.trigger==='manual'?'手动':'自动'}</td>
              <td><span class="tag \${t.status==='done'?'tag-green':t.status==='error'?'tag-red':'tag-orange'}">\${t.status==='done'?'完成':t.status==='error'?'错误':'进行中'}</span></td>
              <td>\${t.total} / \${t.inserted} / \${t.updated}</td>
              <td>\${t.started_at ? new Date(t.started_at*1000).toLocaleString() : '-'}</td>
            </tr>
          \`).join('')}
        </tbody>
      </table>
    </div>
  \`
}

async function renderCategories() {
  const content = document.getElementById('content')
  content.innerHTML = '<div style="text-align:center;padding:40px;color:#888">加载中...</div>'
  const cats = await request('GET', '/api/categories')
  content.innerHTML = \`
    <div class="card">
      <div style="display:flex;justify-content:flex-end;margin-bottom:16px">
        <button class="btn btn-primary" onclick="showAddCat()">+ 添加分类</button>
      </div>
      <table>
        <thead><tr><th>名称</th><th>Slug</th><th>操作</th></tr></thead>
        <tbody>
          \${(Array.isArray(cats)?cats:[]).map(c => \`
            <tr>
              <td>\${c.name}</td>
              <td>\${c.slug}</td>
              <td><button class="btn btn-danger" style="padding:4px 10px;font-size:12px" onclick="deleteCat('\${c.id}','\${c.name}')">删除</button></td>
            </tr>
          \`).join('')}
        </tbody>
      </table>
    </div>
  \`
}

function showAddCat() {
  document.body.insertAdjacentHTML('beforeend', \`
    <div class="modal-mask" id="cat-modal">
      <div class="modal">
        <div class="modal-title">添加分类</div>
        <div class="form-group"><label>名称 *</label><input id="c-name" placeholder="如：电影"></div>
        <div class="form-group"><label>Slug *</label><input id="c-slug" placeholder="如：movie"></div>
        <div id="cat-modal-alert"></div>
        <div class="modal-footer">
          <button class="btn btn-default" onclick="closeModal('cat-modal')">取消</button>
          <button class="btn btn-primary" onclick="saveCat()">添加</button>
        </div>
      </div>
    </div>
  \`)
}

async function saveCat() {
  const name = document.getElementById('c-name').value.trim()
  const slug = document.getElementById('c-slug').value.trim()
  if (!name || !slug) { document.getElementById('cat-modal-alert').innerHTML = '<div class="alert alert-error">名称和Slug不能为空</div>'; return }
  const res = await request('POST', '/api/categories', { name, slug })
  if (res.ok) { closeModal('cat-modal'); renderCategories() }
  else document.getElementById('cat-modal-alert').innerHTML = \`<div class="alert alert-error">\${res.error||'添加失败'}</div>\`
}

async function deleteCat(id, name) {
  if (!confirm(\`确定删除分类「\${name}」？\`)) return
  await request('DELETE', \`/api/categories/\${id}\`)
  renderCategories()
}

function renderSettings() {
  document.getElementById('content').innerHTML = \`
    <div class="card" style="max-width:480px">
      <div class="card-title">修改密码</div>
      <div class="form-group"><label>原密码</label><input id="old-pwd" type="password"></div>
      <div class="form-group"><label>新密码</label><input id="new-pwd" type="password"></div>
      <div class="form-group"><label>确认新密码</label><input id="confirm-pwd" type="password"></div>
      <div id="pwd-alert"></div>
      <button class="btn btn-primary" onclick="changePassword()">修改密码</button>
    </div>
  \`
}

async function changePassword() {
  const oldPassword = document.getElementById('old-pwd').value
  const newPassword = document.getElementById('new-pwd').value
  const confirmPwd = document.getElementById('confirm-pwd').value
  if (!oldPassword || !newPassword) { document.getElementById('pwd-alert').innerHTML = '<div class="alert alert-error">请填写完整</div>'; return }
  if (newPassword !== confirmPwd) { document.getElementById('pwd-alert').innerHTML = '<div class="alert alert-error">两次密码不一致</div>'; return }
  if (newPassword.length < 6) { document.getElementById('pwd-alert').innerHTML = '<div class="alert alert-error">密码至少6位</div>'; return }
  const res = await request('POST', '/api/admin/password', { oldPassword, newPassword })
  if (res.ok) { document.getElementById('pwd-alert').innerHTML = '<div class="alert alert-success">修改成功，请重新登录</div>'; setTimeout(logout, 1500) }
  else document.getElementById('pwd-alert').innerHTML = \`<div class="alert alert-error">\${res.error||'修改失败'}</div>\`
}

function closeModal(id) { const el = document.getElementById(id); if(el) el.remove() }

function logout() {
  token = ''
  currentUser = ''
  localStorage.removeItem('cms_token')
  localStorage.removeItem('cms_user')
  render()
}

render()
</script>
</body>
</html>`
}
