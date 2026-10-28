const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false });
const publicDir = __dirname;
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
app.use(session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || (() => { if (process.env.NODE_ENV === 'production') throw new Error('SESSION_SECRET must be set in Render environment variables'); return 'local-development-only'; })(),
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000 }
}));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false });
const clean = s => String(s || '').trim();
const slugify = s => clean(s).toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,100);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const safeUrl = s => { try { const u = new URL(s); return ['https:','http:'].includes(u.protocol) ? u.href : ''; } catch { return ''; } };
async function initDb() {
  await pool.query(`CREATE TABLE IF NOT EXISTS articles (
    id BIGSERIAL PRIMARY KEY, headline TEXT NOT NULL, slug TEXT UNIQUE NOT NULL,
    sport TEXT NOT NULL DEFAULT 'Opinion', author TEXT NOT NULL DEFAULT 'TheGameIndex',
    thumbnail_url TEXT NOT NULL DEFAULT '', excerpt TEXT NOT NULL DEFAULT '',
    body TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','published')),
    published_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )`);
}
function requireAdmin(req,res,next){ if(req.session && req.session.admin === true) return next(); return res.status(401).json({error:'Please sign in again.'}); }
function renderArticle(a) {
 const image = safeUrl(a.thumbnail_url);
 const body = esc(a.body).replace(/\r?\n/g,'<br>\n');
 return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(a.headline)} — TheGameIndex</title><meta name="description" content="${esc(a.excerpt)}"><style>body{margin:0;background:#f4f4f1;color:#101113;font:17px/1.8 Arial,sans-serif}.top{background:#101113;color:#bbb;padding:12px 5%;font:11px monospace}.top a{color:#f05a28;text-decoration:none}.wrap{max-width:820px;margin:50px auto;padding:0 22px}.tag{font:12px monospace;color:#f05a28;text-transform:uppercase}h1{font-size:clamp(36px,7vw,64px);line-height:1.02;letter-spacing:-.05em;margin:18px 0} .meta{color:#777;font:12px monospace;margin:20px 0 28px}img{width:100%;max-height:470px;object-fit:cover;margin-bottom:25px;background:#ddd}.excerpt{font-size:22px;line-height:1.5;color:#555}.body{white-space:normal;overflow-wrap:anywhere}.back{display:inline-block;margin-top:35px;color:#f05a28;text-decoration:none;font:12px monospace}footer{border-top:1px solid #ddd;padding:25px 5%;font:11px monospace;color:#777}</style></head><body><div class="top"><a href="/">THEGAMEINDEX</a> / SPORTS · DATA · OPINION</div><main class="wrap"><div class="tag">${esc(a.sport)}</div><h1>${esc(a.headline)}</h1><div class="meta">BY ${esc(a.author)} · ${new Date(a.published_at || a.created_at).toLocaleDateString()}</div>${image ? '<img src="'+esc(image)+'" alt="'+esc(a.headline)+'">' : ''}<p class="excerpt">${esc(a.excerpt)}</p><div class="body">${body}</div><a class="back" href="/">← BACK TO THE INDEX</a></main><footer>© THEGAMEINDEX · THE NUMBERS TELL THE STORY.</footer></body></html>`;
}
function renderCard(a) {
 const image=safeUrl(a.thumbnail_url);
 return `<article class="story" data-category="${esc(a.sport)}"><a href="/story/${encodeURIComponent(a.slug)}" style="color:inherit;text-decoration:none;display:flex;flex-direction:column;height:100%">${image ? '<div class="visual" style="padding:0;height:170px"><img src="'+esc(image)+'" alt="" style="width:100%;height:100%;object-fit:cover"></div>' : '<div class="visual"><small>'+esc(a.sport)+' / THE INDEX</small><b>'+esc(a.sport.toUpperCase())+'.</b></div>'}<div class="story-body"><div class="meta">${esc(a.sport).toUpperCase()} · STORY</div><h3>${esc(a.headline)}</h3><p>${esc(a.excerpt)}</p><span class="read">READ STORY ↗</span></div></a></article>`;
}
app.get('/', async (req,res,next) => {
 try {
  const html=fs.readFileSync(path.join(publicDir,'index.html'),'utf8');
  const {rows}=await pool.query("SELECT headline,slug,sport,author,thumbnail_url,excerpt,body,status,published_at,created_at FROM articles WHERE status='published' ORDER BY COALESCE(published_at,created_at) DESC LIMIT 12");
  let out=html;
  if(rows.length) out=out.replace(/<div class="stories" id="stories">[\s\S]*?<\/div><aside class="side">/, '<div class="stories" id="stories">'+rows.map(renderCard).join('')+'</div><aside class="side">');
  res.type('html').send(out);
 } catch(e){ next(e); }
});
app.get('/admin', (req,res)=>res.sendFile(path.join(publicDir,'admin.html')));
app.get('/api/session', (req,res)=>res.json({authenticated:req.session?.admin===true, configured:Boolean(process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD_HASH)}));
app.post('/api/login', loginLimiter, async (req,res) => {
 const email=clean(req.body.email).toLowerCase(), password=String(req.body.password||'');
 if(!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD_HASH) return res.status(503).json({error:'Admin login is not configured yet. Set ADMIN_EMAIL and ADMIN_PASSWORD_HASH in Render environment variables.'});
 const ok=email===process.env.ADMIN_EMAIL.toLowerCase() && await bcrypt.compare(password,process.env.ADMIN_PASSWORD_HASH);
 if(!ok) return res.status(401).json({error:'Email or password is incorrect.'});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Could not start session.'});req.session.admin=true;req.session.email=email;res.json({ok:true});});
});
app.post('/api/logout', requireAdmin, (req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/articles', requireAdmin, async (req,res,next)=>{try{const {rows}=await pool.query('SELECT * FROM articles ORDER BY updated_at DESC');res.json(rows)}catch(e){next(e)}});
app.post('/api/articles', requireAdmin, async (req,res,next)=>{
 try {
  const b=req.body||{}, headline=clean(b.headline), sport=clean(b.sport)||'Opinion', author=clean(b.author)||'TheGameIndex';
  const slug=slugify(b.slug||headline), thumb=safeUrl(b.thumbnail_url||''), excerpt=clean(b.excerpt), body=String(b.body||''), status=b.status==='published'?'published':'draft';
  if(!headline||!slug||!excerpt||!body) return res.status(400).json({error:'Headline, slug, excerpt and article body are required.'});
  const {rows}=await pool.query(`INSERT INTO articles(headline,slug,sport,author,thumbnail_url,excerpt,body,status,published_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,CASE WHEN $8='published' THEN NOW() ELSE NULL END,NOW()) RETURNING *`,[headline,slug,sport,author,thumb,excerpt,body,status]);
  res.status(201).json(rows[0]);
 } catch(e){if(e.code==='23505')return res.status(409).json({error:'That slug is already in use. Choose a different slug.'});next(e)}
});
app.put('/api/articles/:id', requireAdmin, async (req,res,next)=>{
 try{
  const b=req.body||{},headline=clean(b.headline),slug=slugify(b.slug||headline),status=b.status==='published'?'published':'draft';
  if(!headline||!slug||!clean(b.excerpt)||!String(b.body||''))return res.status(400).json({error:'Headline, slug, excerpt and article body are required.'});
  const {rows}=await pool.query(`UPDATE articles SET headline=$1,slug=$2,sport=$3,author=$4,thumbnail_url=$5,excerpt=$6,body=$7,status=$8,published_at=CASE WHEN $8='published' THEN COALESCE(published_at,NOW()) ELSE NULL END,updated_at=NOW() WHERE id=$9 RETURNING *`,[headline,slug,clean(b.sport)||'Opinion',clean(b.author)||'TheGameIndex',safeUrl(b.thumbnail_url||''),clean(b.excerpt),String(b.body),status,req.params.id]);
  if(!rows.length)return res.status(404).json({error:'Story not found.'});res.json(rows[0]);
 }catch(e){if(e.code==='23505')return res.status(409).json({error:'That slug is already in use.'});next(e)}
});
app.delete('/api/articles/:id',requireAdmin,async(req,res,next)=>{try{const r=await pool.query('DELETE FROM articles WHERE id=$1 RETURNING id', [req.params.id]);if(!r.rowCount)return res.status(404).json({error:'Story not found.'});res.json({ok:true})}catch(e){next(e)}});
app.get('/story/:slug',async(req,res,next)=>{try{const {rows}=await pool.query("SELECT * FROM articles WHERE slug=$1 AND status='published'",[req.params.slug]);if(!rows.length)return res.status(404).send('<h1>Story not found</h1><a href="/">Back to TheGameIndex</a>');res.type('html').send(renderArticle(rows[0]))}catch(e){next(e)}});
app.use((err,req,res,next)=>{console.error(err);if(res.headersSent)return next(err);res.status(500).json({error:'Something went wrong. Please try again.'})});
initDb().then(()=>app.listen(port,'0.0.0.0',()=>console.log('TheGameIndex listening on '+port))).catch(e=>{console.error('Database initialization failed',e);process.exit(1)});
