const express = require('express');
const cors = require('cors');
const path = require('path');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS and parse JSON payloads. Set body size limits large enough for base64 images
app.use(cors());
app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ limit: '15mb', extended: true }));

let db;

// Helper to generate IDs
const uid = () => Math.random().toString(36).slice(2) + Date.now().toString(36);

// Initialize DB and start server
async function start() {
  db = await open({
    filename: path.join(__dirname, 'wardrobe.db'),
    driver: sqlite3.Database
  });

  // Enable foreign keys
  await db.get('PRAGMA foreign_keys = ON');

  // Create Users Table
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      createdAt TEXT NOT NULL
    )
  `);

  // Create Clothes Table
  await db.exec(`
    CREATE TABLE IF NOT EXISTS clothes (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      name TEXT,
      type TEXT NOT NULL,
      category TEXT NOT NULL,
      pattern TEXT NOT NULL,
      style TEXT NOT NULL,
      season TEXT NOT NULL,
      color TEXT NOT NULL,
      colorHex TEXT NOT NULL,
      imageData TEXT NOT NULL,
      createdAt TEXT NOT NULL,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // Create Saved Outfits Table
  await db.exec(`
    CREATE TABLE IF NOT EXISTS outfits (
      id TEXT PRIMARY KEY,
      userId TEXT NOT NULL,
      name TEXT NOT NULL,
      score INTEGER NOT NULL,
      reasons TEXT NOT NULL, -- JSON stringified array
      occasion TEXT NOT NULL,
      weather TEXT NOT NULL,
      items TEXT NOT NULL,   -- JSON stringified array of clothing items
      createdAt TEXT NOT NULL,
      FOREIGN KEY (userId) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

// ─── AUTH ENDPOINTS ──────────────────────────────────────────

// Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required.' });
  }

  try {
    const existing = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (existing) {
      return res.status(400).json({ error: 'Email already registered.' });
    }

    const userId = uid();
    const hashedPassword = await bcrypt.hash(password, 10);
    const createdAt = new Date().toISOString();

    await db.run(
      'INSERT INTO users (id, name, email, password, createdAt) VALUES (?, ?, ?, ?, ?)',
      [userId, name, email, hashedPassword, createdAt]
    );

    res.status(201).json({ id: userId, name, email, createdAt });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: 'Failed to create user.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  try {
    const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) {
      return res.status(400).json({ error: 'No account found with this email.' });
    }

    const matches = await bcrypt.compare(password, user.password);
    if (!matches) {
      return res.status(400).json({ error: 'Incorrect password.' });
    }

    res.json({ id: user.id, name: user.name, email: user.email, createdAt: user.createdAt });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Failed to login.' });
  }
});

// Update Profile User Name
app.put('/api/auth/user', async (req, res) => {
  const { userId, name } = req.body;
  if (!userId || !name) {
    return res.status(400).json({ error: 'User ID and name are required.' });
  }

  try {
    await db.run('UPDATE users SET name = ? WHERE id = ?', [name, userId]);
    const updatedUser = await db.get('SELECT id, name, email, createdAt FROM users WHERE id = ?', [userId]);
    res.json(updatedUser);
  } catch (err) {
    console.error('Update user error:', err);
    res.status(500).json({ error: 'Failed to update display name.' });
  }
});

// Change Password
app.put('/api/auth/password', async (req, res) => {
  const { userId, currentPassword, nextPassword } = req.body;
  if (!userId || !currentPassword || !nextPassword) {
    return res.status(400).json({ error: 'All password fields are required.' });
  }

  try {
    const user = await db.get('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const matches = await bcrypt.compare(currentPassword, user.password);
    if (!matches) {
      return res.status(400).json({ error: 'Current password is wrong.' });
    }

    const hashedNext = await bcrypt.hash(nextPassword, 10);
    await db.run('UPDATE users SET password = ? WHERE id = ?', [hashedNext, userId]);
    res.json({ success: true, message: 'Password updated successfully.' });
  } catch (err) {
    console.error('Change password error:', err);
    res.status(500).json({ error: 'Failed to change password.' });
  }
});


// ─── CLOTHES ENDPOINTS ───────────────────────────────────────

// Get all clothes for a user (with optional filters)
app.get('/api/clothes', async (req, res) => {
  const { userId, category, style, search } = req.query;
  if (!userId) {
    return res.status(400).json({ error: 'User ID is required.' });
  }

  try {
    let query = 'SELECT * FROM clothes WHERE userId = ?';
    const params = [userId];

    if (category && category !== 'all') {
      query += ' AND category = ?';
      params.push(category);
    }

    if (style && style !== 'all') {
      query += ' AND style = ?';
      params.push(style);
    }

    if (search) {
      query += ' AND name LIKE ?';
      params.push(`%${search}%`);
    }

    // Sort by newest addition first
    query += ' ORDER BY datetime(createdAt) DESC';

    const items = await db.all(query, params);
    res.json(items);
  } catch (err) {
    console.error('Get clothes error:', err);
    res.status(500).json({ error: 'Failed to retrieve clothes.' });
  }
});

// Add clothing item
app.post('/api/clothes', async (req, res) => {
  const { userId, name, type, category, pattern, style, season, color, colorHex, imageData } = req.body;
  if (!userId || !type || !category || !color || !colorHex || !imageData) {
    return res.status(400).json({ error: 'Missing required clothing properties.' });
  }

  try {
    const itemID = uid();
    const createdAt = new Date().toISOString();

    await db.run(
      `INSERT INTO clothes (id, userId, name, type, category, pattern, style, season, color, colorHex, imageData, createdAt) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [itemID, userId, name, type, category, pattern, style, season, color, colorHex, imageData, createdAt]
    );

    const newItem = await db.get('SELECT * FROM clothes WHERE id = ?', [itemID]);
    res.status(201).json(newItem);
  } catch (err) {
    console.error('Add clothes error:', err);
    res.status(500).json({ error: 'Failed to save clothing item.' });
  }
});

// Update clothing item
app.put('/api/clothes/:id', async (req, res) => {
  const { id } = req.params;
  const { name, color, colorHex, style, season } = req.body;

  try {
    await db.run(
      'UPDATE clothes SET name = ?, color = ?, colorHex = ?, style = ?, season = ? WHERE id = ?',
      [name, color, colorHex, style, season, id]
    );
    const updated = await db.get('SELECT * FROM clothes WHERE id = ?', [id]);
    res.json(updated);
  } catch (err) {
    console.error('Update clothes error:', err);
    res.status(500).json({ error: 'Failed to update item.' });
  }
});

// Delete clothing item
app.delete('/api/clothes/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.run('DELETE FROM clothes WHERE id = ?', [id]);
    res.json({ success: true, message: 'Item deleted.' });
  } catch (err) {
    console.error('Delete clothes error:', err);
    res.status(500).json({ error: 'Failed to delete item.' });
  }
});

// Clear all wardrobe data for a user
app.delete('/api/clothes/all/:userId', async (req, res) => {
  const { userId } = req.params;
  try {
    await db.run('DELETE FROM clothes WHERE userId = ?', [userId]);
    await db.run('DELETE FROM outfits WHERE userId = ?', [userId]);
    res.json({ success: true, message: 'All wardrobe data cleared.' });
  } catch (err) {
    console.error('Clear data error:', err);
    res.status(500).json({ error: 'Failed to clear wardrobe data.' });
  }
});


// ─── SAVED OUTFITS ENDPOINTS ─────────────────────────────────

// Get all saved outfits for a user
app.get('/api/outfits', async (req, res) => {
  const { userId } = req.query;
  if (!userId) {
    return res.status(400).json({ error: 'User ID is required.' });
  }

  try {
    const rows = await db.all('SELECT * FROM outfits WHERE userId = ? ORDER BY datetime(createdAt) DESC', [userId]);
    // Parse JSON strings back to arrays
    const parsed = rows.map(r => ({
      ...r,
      reasons: JSON.parse(r.reasons),
      items: JSON.parse(r.items)
    }));
    res.json(parsed);
  } catch (err) {
    console.error('Get outfits error:', err);
    res.status(500).json({ error: 'Failed to retrieve saved outfits.' });
  }
});

// Save outfit combination
app.post('/api/outfits', async (req, res) => {
  const { userId, name, score, reasons, occasion, weather, items } = req.body;
  if (!userId || !name || score === undefined || !reasons || !occasion || !weather || !items) {
    return res.status(400).json({ error: 'Missing required outfit combination properties.' });
  }

  try {
    const outfitId = uid();
    const createdAt = new Date().toISOString();

    await db.run(
      `INSERT INTO outfits (id, userId, name, score, reasons, occasion, weather, items, createdAt) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        outfitId,
        userId,
        name,
        score,
        JSON.stringify(reasons),
        occasion,
        weather,
        JSON.stringify(items),
        createdAt
      ]
    );

    const savedOutfit = await db.get('SELECT * FROM outfits WHERE id = ?', [outfitId]);
    res.status(201).json({
      ...savedOutfit,
      reasons: JSON.parse(savedOutfit.reasons),
      items: JSON.parse(savedOutfit.items)
    });
  } catch (err) {
    console.error('Save outfit error:', err);
    res.status(500).json({ error: 'Failed to save outfit.' });
  }
});

// Delete saved outfit
app.delete('/api/outfits/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await db.run('DELETE FROM outfits WHERE id = ?', [id]);
    res.json({ success: true, message: 'Outfit removed.' });
  } catch (err) {
    console.error('Delete outfit error:', err);
    res.status(500).json({ error: 'Failed to remove saved outfit.' });
  }
});

// Serve static React build files in production
app.use(express.static(path.join(__dirname, 'build')));

// Fallback for React SPA client-side routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'build', 'index.html'));
});

start().catch(err => {
  console.error('Failed to start server:', err);
});

