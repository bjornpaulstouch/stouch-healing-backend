const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3001;
const SECRET = process.env.JWT_SECRET || 'supersecretkey';

app.use(cors());
app.use(express.json());

// SQLite DB Setup
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) throw err;
  console.log('SQLite DB verbunden.');
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    username TEXT UNIQUE,
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    points INTEGER,
    balance INTEGER,
    date TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// Hilfsfunktion: Auth-Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Registrierung
app.post('/api/register', (req, res) => {
  const { email, username, password } = req.body;
  if (!email || !username || !password) return res.status(400).json({ error: 'Alle Felder erforderlich.' });
  const hash = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (email, username, password) VALUES (?, ?, ?)', [email, username, hash], function(err) {
    if (err) return res.status(400).json({ error: 'E-Mail oder Username existiert bereits.' });
    const token = jwt.sign({ id: this.lastID, username }, SECRET, { expiresIn: '7d' });
    res.json({ token, username });
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'User nicht gefunden.' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Falsches Passwort.' });
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET, { expiresIn: '7d' });
    res.json({ token, username: user.username });
  });
});

// Sessionpunkte speichern
app.post('/api/session', authenticateToken, (req, res) => {
  const { points, balance } = req.body;
  const date = new Date().toISOString().slice(0,10);
  db.run('INSERT INTO sessions (user_id, points, balance, date) VALUES (?, ?, ?, ?)', [req.user.id, points, balance, date], function(err) {
    if (err) return res.status(500).json({ error: 'Fehler beim Speichern.' });
    res.json({ success: true });
  });
});

// Dashboard-Daten abrufen
app.get('/api/dashboard', authenticateToken, (req, res) => {
  const userId = req.user.id;
  db.get('SELECT username FROM users WHERE id = ?', [userId], (err, user) => {
    if (err || !user) return res.status(400).json({ error: 'User nicht gefunden.' });
    db.all('SELECT * FROM sessions WHERE user_id = ?', [userId], (err, sessions) => {
      if (err) return res.status(500).json({ error: 'Fehler beim Laden.' });
      const total = sessions.reduce((sum, s) => sum + (s.points||0), 0);
      const today = new Date().toISOString().slice(0,10);
      const sessionToday = sessions.filter(s => s.date === today).reduce((sum, s) => sum + (s.points||0), 0);
      const rekord = sessions.reduce((max, s) => Math.max(max, s.points||0), 0);
      const balanceAvg = sessions.length ? Math.round(sessions.reduce((sum, s) => sum + (s.balance||0), 0) / sessions.length) : 0;
      res.json({
        username: user.username,
        total,
        session: sessionToday,
        rekord,
        balance: balanceAvg
      });
    });
  });
});

app.listen(PORT, () => {
  console.log('Server läuft auf Port', PORT);
}); 