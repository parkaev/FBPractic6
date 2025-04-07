const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));

// Session configuration
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// In-memory storage
let users = [];
const CACHE_FILE = 'cache.json';

// Middleware: Authentication check
const requireAuth = (req, res, next) => {
  req.session.userId ? next() : res.redirect('/');
};

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/register', async (req, res) => {
  const { login, password } = req.body;
  if (users.some(u => u.login === login)) return res.status(400).send('User exists');
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ id: Date.now(), login, password: hashedPassword });
  res.redirect('/');
});

app.post('/login', async (req, res) => {
  const { login, password } = req.body;
  const user = users.find(u => u.login === login);
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).send('Invalid credentials');
  req.session.userId = user.id;
  res.redirect('/profile');
});

app.get('/profile', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Cache handling
const getCachedData = () => {
  try { return JSON.parse(fs.readFileSync(CACHE_FILE)); } 
  catch { return null; }
};

const updateCache = data => {
  fs.writeFileSync(CACHE_FILE, JSON.stringify({ 
    timestamp: Date.now(), 
    data 
  }));
};

app.get('/data', (req, res) => {
  const cache = getCachedData();
  if (cache && Date.now() - cache.timestamp < 60000) return res.json(cache.data);
  const newData = { message: 'Cached data', timestamp: new Date().toISOString() };
  updateCache(newData);
  res.json(newData);
});

app.listen(port, () => console.log(`Server running on http://localhost:${port}`));