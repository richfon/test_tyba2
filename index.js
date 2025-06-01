require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const { Sequelize, DataTypes } = require('sequelize');

const app = express();
app.use(cors());
app.use(express.json());

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: './database.sqlite',
});

const User = sequelize.define('User', {
  username: { type: DataTypes.STRING, unique: true, allowNull: false },
  password: { type: DataTypes.STRING, allowNull: false },
});

const Transaction = sequelize.define('Transaction', {
  userId: { type: DataTypes.INTEGER, allowNull: false },
  query: { type: DataTypes.STRING, allowNull: false },
  timestamp: { type: DataTypes.DATE, defaultValue: DataTypes.NOW },
});

User.hasMany(Transaction, { foreignKey: 'userId' });
Transaction.belongsTo(User, { foreignKey: 'userId' });

const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';

function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
}

async function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token provided' });
  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const user = await User.create({ username, password: hash });
    res.json({ message: 'User registered' });
  } catch {
    res.status(400).json({ error: 'Username already exists' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ where: { username } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = generateToken(user);
  res.json({ token });
});

app.post('/logout', (req, res) => {
  // JWT is stateless; logout is handled on client by deleting token
  res.json({ message: 'Logged out (client should delete token)' });
});

app.get('/restaurants', authMiddleware, async (req, res) => {
  let { city, lat, lon } = req.query;
  if (city) {
    // Get coordinates from city name
    const geo = await axios.get('https://nominatim.openstreetmap.org/search', {
      params: { q: city, format: 'json' },
    });
    if (!geo.data.length) return res.status(404).json({ error: 'City not found' });
    lat = geo.data[0].lat;
    lon = geo.data[0].lon;
  }
  if (!lat || !lon) return res.status(400).json({ error: 'Provide city or coordinates' });
  // Overpass API for restaurants
  const query = `
    [out:json];
    node[amenity=restaurant](around:3000,${lat},${lon});
    out;
  `;
  const overpass = await axios.post('https://overpass-api.de/api/interpreter', query, {
    headers: { 'Content-Type': 'text/plain' },
  });
  const restaurants = overpass.data.elements.map(r => ({
    name: r.tags?.name || 'Unknown',
    lat: r.lat,
    lon: r.lon,
  }));
  await Transaction.create({ userId: req.user.id, query: `${lat},${lon}` });
  res.json(restaurants);
});

app.get('/transactions', authMiddleware, async (req, res) => {
  const txs = await Transaction.findAll({ where: { userId: req.user.id }, order: [['timestamp', 'DESC']] });
  res.json(txs);
});

sequelize.sync().then(() => {
  app.listen(3000, () => console.log('Server running on http://localhost:3000'));
});
