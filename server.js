/**
 * Mini Social Platform — single-file demo app
 * Features:
 * - Register/Login/Logout (session-based)
 * - Browse users
 * - Send/Accept/Decline friend requests
 * - See your friends list
 * - 1:1 simple messaging with friends (page refresh, not realtime)
 *
 * How to run:
 * 1) Save this file as `server.js`
 * 2) Run:  npm init -y
 * 3) Run:  npm i express sqlite3 bcrypt express-session body-parser
 * 4) Start: node server.js
 * 5) Open:  http://localhost:3000
 */
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.static("public"));

const PORT = process.env.PORT || 3000;

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'defaultSecret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 12 }, // 12h
  })
);

const db = new sqlite3.Database(process.env.DB_PATH || 'app.db');


// Basic styles
const baseStyles = `
  *{box-sizing:border-box}body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Helvetica,Arial,sans-serif;margin:0;background:#0b1220;color:#e6eaf2}
  a{color:#8ab4ff;text-decoration:none}a:hover{text-decoration:underline}
  .wrap{max-width:980px;margin:0 auto;padding:24px}
  header{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;background:#0f172a;border-bottom:1px solid #1f2a44}
  .brand{font-weight:700}nav a{margin-right:12px}
  .card{background:#0f172a;border:1px solid #1f2a44;border-radius:16px;padding:20px;margin:16px 0}
  input,textarea,select{width:100%;padding:10px;border-radius:12px;border:1px solid #27324f;background:#0c1427;color:#e6eaf2}
  button{background:#2563eb;border:0;color:white;padding:10px 14px;border-radius:12px;cursor:pointer}
  button.secondary{background:#334155}
  .row{display:grid;gap:12px}
  .two{grid-template-columns:repeat(2,1fr)}
  .list{list-style:none;padding:0;margin:0}
  .list li{display:flex;justify-content:space-between;align-items:center;padding:10px;border-bottom:1px solid #1f2a44}
  .muted{color:#94a3b8}
  .badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#1e293b;color:#cbd5e1;border:1px solid #334155;font-size:12px}
  .success{color:#22c55e} .error{color:#ef4444}
`;

// ---------- DB Setup ----------
const db = new sqlite3.Database('app.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id INTEGER NOT NULL,
    to_user_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(from_user_id, to_user_id),
    FOREIGN KEY(from_user_id) REFERENCES users(id),
    FOREIGN KEY(to_user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS friendships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER NOT NULL,
    user2_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user1_id, user2_id),
    FOREIGN KEY(user1_id) REFERENCES users(id),
    FOREIGN KEY(user2_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(sender_id) REFERENCES users(id),
    FOREIGN KEY(receiver_id) REFERENCES users(id)
  )`);
});

// ---------- Helpers ----------
function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function layout({ title = 'Mini Social', user, content, flash = '' }) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${title}</title>
  
  <link rel="stylesheet" href="/style.css">


  </head><body>
  <header>
    <div class="brand">🌐 Mini Social</div>
    <nav>
      ${user ? `<span class="badge">@${user.username}</span> <a href="/dashboard">Dashboard</a> <a href="/users">Users</a> <a href="/requests">Requests</a> <a href="/friends">Friends</a> <a href="/logout">Logout</a>` : `<a href="/login">Login</a> <a href="/register">Register</a>`}
    </nav>
  </header>
  <div class="wrap">
    ${flash}
    ${content}
  </div>
  </body></html>`;
}

function page(res, opts) {
  res.send(layout(opts));
}

function isFriends(a, b) {
  return new Promise((resolve, reject) => {
    const [x, y] = a < b ? [a, b] : [b, a];
    db.get(
      'SELECT 1 FROM friendships WHERE user1_id=? AND user2_id=?',
      [x, y],
      (err, row) => {
        if (err) return reject(err);
        resolve(!!row);
      }
    );
  });
}

// ---------- Routes ----------
app.get('/', (req, res) => {
  const content = `
  <div class="card">
    <h2>Welcome</h2>
    <p>This is a tiny social platform demo. Create an account, send friend requests, accept them, and chat 1:1 with friends.</p>
    <div class="row two">
      <div><a href="/register"><button>Create account</button></a></div>
      <div><a href="/login"><button class="secondary">I already have an account</button></a></div>
    </div>
  </div>`;
  page(res, { content, user: req.session.user });
});

app.get('/register', (req, res) => {
  const content = `
    <div class="card">
      <h2>Create your account</h2>
      <form method="post" action="/register">
        <label>Username</label>
        <input name="username" minlength="3" maxlength="24" required />
        <label>Password</label>
        <input type="password" name="password" minlength="6" required />
        <div style="margin-top:12px"><button type="submit">Register</button></div>
      </form>
      <p class="muted">Already have an account? <a href="/login">Login</a></p>
    </div>`;
  page(res, { content, user: req.session.user });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)',
      [username.trim().toLowerCase(), hash],
      function (err) {
        if (err) {
          const content = `<div class="card"><p class="error">${err.message.includes('UNIQUE') ? 'Username is taken' : 'Something went wrong'}</p><a href="/register">Back</a></div>`;
          return page(res, { content });
        }
        req.session.user = { id: this.lastID, username: username.trim().toLowerCase() };
        res.redirect('/dashboard');
      }
    );
  } catch (e) {
    const content = `<div class="card"><p class="error">${e.message}</p></div>`;
    page(res, { content });
  }
});

app.get('/login', (req, res) => {
  const content = `
    <div class="card">
      <h2>Login</h2>
      <form method="post" action="/login">
        <label>Username</label>
        <input name="username" required />
        <label>Password</label>
        <input type="password" name="password" required />
        <div style="margin-top:12px"><button type="submit">Login</button></div>
      </form>
      <p class="muted">No account? <a href="/register">Register</a></p>
    </div>`;
  page(res, { content, user: req.session.user });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username.trim().toLowerCase()], async (err, user) => {
    if (err || !user) {
      const content = `<div class="card"><p class="error">Invalid credentials</p><a href="/login">Try again</a></div>`;
      return page(res, { content });
    }
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      const content = `<div class="card"><p class="error">Invalid credentials</p><a href="/login">Try again</a></div>`;
      return page(res, { content });
    }
    req.session.user = { id: user.id, username: user.username };
    res.redirect('/dashboard');
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.get('/dashboard', requireAuth, (req, res) => {
  const content = `
    <div class="card">
      <h2>Dashboard</h2>
      <p>Welcome, <strong>@${req.session.user.username}</strong> 👋</p>
      <div class="row two">
        <a href="/users"><button>Find people</button></a>
        <a href="/requests"><button class="secondary">Friend requests</button></a>
      </div>
    </div>`;
  page(res, { content, user: req.session.user });
});

// List users to send requests
app.get('/users', requireAuth, (req, res) => {
  db.all('SELECT id, username FROM users WHERE id != ? ORDER BY username', [req.session.user.id], async (err, users) => {
    if (err) users = [];

    // Fetch existing friend relationships and requests to show status buttons
    const uId = req.session.user.id;

    const items = await Promise.all(
      users.map(async (u) => {
        const friends = await isFriends(uId, u.id);
        return new Promise((resolve) => {
          db.get(
            `SELECT status, from_user_id as fromId FROM friend_requests
             WHERE (from_user_id=? AND to_user_id=?) OR (from_user_id=? AND to_user_id=?)`,
            [uId, u.id, u.id, uId],
            (e, row) => {
              let action = '';
              if (friends) {
                action = `<span class="badge">Friends</span> <a href="/message/${u.id}"><button>Message</button></a>`;
              } else if (row) {
                if (row.status === 'PENDING') {
                  if (row.fromId === uId) action = `<span class="badge">Request sent</span>`;
                  else action = `<a href="/requests"><button>Respond</button></a>`;
                } else if (row.status === 'DECLINED') {
                  action = `<span class="badge">Declined</span>`;
                }
              } else {
                action = `<form method="post" action="/friend-request/${u.id}" style="margin:0"><button type="submit">Add friend</button></form>`;
              }
              resolve(`<li><div>@${u.username}</div><div>${action}</div></li>`);
            }
          );
        });
      })
    );

    const content = `
      <div class="card">
        <h2>All users</h2>
        <ul class="list">${items.join('')}</ul>
      </div>`;
    page(res, { content, user: req.session.user });
  });
});

// Send friend request
app.post('/friend-request/:id', requireAuth, (req, res) => {
  const fromId = req.session.user.id;
  const toId = parseInt(req.params.id, 10);
  if (fromId === toId) return res.redirect('/users');

  // prevent duplicates or if already friends
  isFriends(fromId, toId).then((friends) => {
    if (friends) return res.redirect('/users');
    db.run(
      `INSERT OR IGNORE INTO friend_requests (from_user_id, to_user_id, status) VALUES (?, ?, 'PENDING')`,
      [fromId, toId],
      () => res.redirect('/users')
    );
  });
});

// View incoming + outgoing requests
app.get('/requests', requireAuth, (req, res) => {
  const uid = req.session.user.id;
  db.all(
    `SELECT fr.id, fr.status, u.username as from_name, u.id as from_id
     FROM friend_requests fr JOIN users u ON u.id = fr.from_user_id
     WHERE fr.to_user_id = ? AND fr.status = 'PENDING'`,
    [uid],
    (err, incoming) => {
      db.all(
        `SELECT fr.id, fr.status, u.username as to_name, u.id as to_id
         FROM friend_requests fr JOIN users u ON u.id = fr.to_user_id
         WHERE fr.from_user_id = ? AND fr.status = 'PENDING'`,
        [uid],
        (err2, outgoing) => {
          const inc = (incoming || [])
            .map(
              (r) => `<li><div>@${r.from_name}</div><div>
                  <form method="post" action="/accept/${r.id}" style="display:inline"><button type="submit">Accept</button></form>
                  <form method="post" action="/decline/${r.id}" style="display:inline;margin-left:8px"><button class="secondary" type="submit">Decline</button></form>
                </div></li>`
            )
            .join('');

          const out = (outgoing || [])
            .map((r) => `<li><div>To @${r.to_name}</div><div><span class="badge">Pending</span></div></li>`)
            .join('');

          const content = `
            <div class="card">
              <h2>Incoming requests</h2>
              <ul class="list">${inc || '<li class="muted">No incoming</li>'}</ul>
            </div>
            <div class="card">
              <h2>Outgoing requests</h2>
              <ul class="list">${out || '<li class="muted">No outgoing</li>'}</ul>
            </div>`;
          page(res, { content, user: req.session.user });
        }
      );
    }
  );
});

// Accept/Decline
app.post('/accept/:reqId', requireAuth, (req, res) => {
  const uid = req.session.user.id;
  const reqId = parseInt(req.params.reqId, 10);
  db.get('SELECT * FROM friend_requests WHERE id=? AND to_user_id=?', [reqId, uid], (err, row) => {
    if (!row || row.status !== 'PENDING') return res.redirect('/requests');
    const [a, b] = row.from_user_id < row.to_user_id ? [row.from_user_id, row.to_user_id] : [row.to_user_id, row.from_user_id];
    db.serialize(() => {
      db.run('UPDATE friend_requests SET status="ACCEPTED" WHERE id=?', [reqId]);
      db.run('INSERT OR IGNORE INTO friendships (user1_id, user2_id) VALUES (?, ?)', [a, b], () => res.redirect('/friends'));
    });
  });
});

app.post('/decline/:reqId', requireAuth, (req, res) => {
  const uid = req.session.user.id;
  const reqId = parseInt(req.params.reqId, 10);
  db.run('UPDATE friend_requests SET status="DECLINED" WHERE id=? AND to_user_id=?', [reqId, uid], () => res.redirect('/requests'));
});

// Friends list
app.get('/friends', requireAuth, (req, res) => {
  const uid = req.session.user.id;
  db.all(
    `SELECT CASE WHEN f.user1_id = ? THEN f.user2_id ELSE f.user1_id END as fid
     FROM friendships f WHERE f.user1_id = ? OR f.user2_id = ?`,
    [uid, uid, uid],
    (err, rows) => {
      const ids = (rows || []).map((r) => r.fid);
      if (ids.length === 0) {
        const content = `<div class="card"><h2>Your friends</h2><p class="muted">No friends yet.</p></div>`;
        return page(res, { content, user: req.session.user });
      }
      const q = `SELECT id, username FROM users WHERE id IN (${ids.map(() => '?').join(',')}) ORDER BY username`;
      db.all(q, ids, (e2, users) => {
        const list = users
          .map((u) => `<li><div>@${u.username}</div><div><a href="/message/${u.id}"><button>Message</button></a></div></li>`)
          .join('');
        const content = `<div class="card"><h2>Your friends</h2><ul class="list">${list}</ul></div>`;
        page(res, { content, user: req.session.user });
      });
    }
  );
});

// Messaging (simple, non-realtime)
app.get('/message/:friendId', requireAuth, async (req, res) => {
  const uid = req.session.user.id;
  const fid = parseInt(req.params.friendId, 10);
  if (!(await isFriends(uid, fid))) return res.redirect('/friends');

  db.get('SELECT id, username FROM users WHERE id=?', [fid], (e, friend) => {
    db.all(
      `SELECT * FROM messages WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?) ORDER BY created_at ASC`,
      [uid, fid, fid, uid],
      (err, msgs) => {
        const bubbles = (msgs || [])
          .map((m) => {
            const mine = m.sender_id === uid;
            return `<div style="display:flex;${mine ? 'justify-content:flex-end' : 'justify-content:flex-start'};margin:6px 0">
              <div style="max-width:70%;padding:10px;border-radius:14px;${mine ? 'background:#1d4ed8' : 'background:#1e293b'}">${escapeHtml(m.content)}
                <div class="muted" style="font-size:11px;margin-top:4px">${new Date(m.created_at).toLocaleString()}</div>
              </div>
            </div>`;
          })
          .join('');

        const content = `
          <div class="card">
            <h2>Chat with @${friend.username}</h2>
            <div style="height:360px;overflow:auto;border:1px solid #1f2a44;border-radius:12px;padding:12px;background:#0c1427">${bubbles || '<p class="muted">No messages yet.</p>'}</div>
            <form method="post" action="/message/${friend.id}" style="margin-top:12px">
              <textarea name="content" rows="3" placeholder="Type a message..." required></textarea>
              <div style="margin-top:8px"><button type="submit">Send</button> <a href="/friends"><button class="secondary" type="button">Back</button></a></div>
            </form>
          </div>`;
        page(res, { content, user: req.session.user });
      }
    );
  });
});

app.post('/message/:friendId', requireAuth, async (req, res) => {
  const uid = req.session.user.id;
  const fid = parseInt(req.params.friendId, 10);
  const { content } = req.body;
  if (!(await isFriends(uid, fid))) return res.redirect('/friends');
  db.run(
    'INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
    [uid, fid, content.trim().slice(0, 2000)],
    () => res.redirect(`/message/${fid}`)
  );
});

// ---------- Utilities ----------
function escapeHtml(str) {
  return str
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`Mini Social running on http://localhost:${PORT}`);
});
