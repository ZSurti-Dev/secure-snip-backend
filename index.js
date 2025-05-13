require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
app.use(cors({
  origin: [ 'http://localhost:5173',
            'https://secure-snip-aadidya05-zsurti-devs-projects-99463xfdf0xm788nptbq3wtn6e.vercel.app',
            'https://secure-snip-bv1uhc1dt-zsurti-devs-projects.vercel.app',
            'secure-snip-mj0v066pj-zsurti-devs-projects.vercel.app'],
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type'],
}));
app.use(express.json());

// Use environment variables with fallbacks for local testing
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/secure-snip';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012'; // 32-character default key

// MongoDB Connection
const connectToMongoDB = async () => {
  try {
    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
    });
    console.log('MongoDB connected successfully to:', MONGO_URI);
  } catch (err) {
    console.error('MongoDB connection error:', err.message, err.stack);
    if (err.name === 'MongoServerError') {
      console.error('MongoServerError details:', err.code, err.codeName);
    }
    console.log('MongoDB connection failed. Check MONGO_URI in environment variables.');
  }
};

// Snippet Schema
const snippetSchema = new mongoose.Schema({
  title: { type: String, required: true },
  encryptedData: { type: String, required: true },
  password: { type: String, required: true },
  tags: { type: String },
  createdAt: { type: Date, default: Date.now },
}, { collection: 'Users' });

const Snippet = mongoose.model('Snippet', snippetSchema);

// AES-256 Encryption
const encrypt = (text) => {
  try {
    if (!text || typeof text !== 'string') {
      throw new Error('Invalid input for encryption: text must be a non-empty string');
    }
    const iv = crypto.randomBytes(16);
    const key = crypto.createHash('sha256').update(ENCRYPTION_KEY).digest();
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return `${iv.toString('base64')}:${encrypted}`;
  } catch (err) {
    console.error('Encryption error:', err.message, err.stack);
    throw err;
  }
};

// AES-256 Decryption
const decrypt = (encryptedText) => {
  try {
    if (!encryptedText || typeof encryptedText !== 'string') {
      throw new Error('Invalid input for decryption: encryptedText must be a non-empty string');
    }
    const [iv, encrypted] = encryptedText.split(':');
    const key = crypto.createHash('sha256').update(ENCRYPTION_KEY).digest();
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'base64'));
    let decrypted = decipher.update(encrypted, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.error('Decryption error:', err.message, err.stack);
    throw err;
  }
};

// POST /api/snippets
app.post('/api/snippets', async (req, res) => {
  const { title, message, password, tags } = req.body;
  console.log('Received request to /api/snippets:', { title, message, password, tags });

  try {
    if (!title || !message || !password) {
      return res.status(400).json({ success: false, error: 'Title, message, and password are required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const encryptedData = encrypt(message);
    const snippet = new Snippet({ title, encryptedData, password: hashedPassword, tags });
    const savedSnippet = await snippet.save(); // Ensure save is awaited

    res.status(201).json({ success: true, encryptedData, title, id: savedSnippet._id });
  } catch (err) {
    console.error('Error in /api/snippets:', err.message, err.stack);
    if (err.name === 'ValidationError') {
      return res.status(400).json({ success: false, error: 'Validation failed: ' + err.message });
    }
    res.status(500).json({ success: false, error: 'Internal server error: ' + err.message });
  }
});

// POST /api/decrypt
app.post('/api/decrypt', async (req, res) => {
  const { id, password } = req.body;
  console.log('Received request to /api/decrypt:', { id, password });

  try {
    const snippet = await Snippet.findById(id);
    if (!snippet) {
      return res.status(404).json({ success: false, error: 'Snippet not found' });
    }

    const isMatch = await bcrypt.compare(password, snippet.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, error: 'Invalid password' });
    }

    const decrypted = decrypt(snippet.encryptedData);
    res.json({ success: true, message: decrypted });
  } catch (err) {
    console.error('Error in /api/decrypt:', err.message, err.stack);
    res.status(400).json({ success: false, error: 'Decryption failed: ' + err.message });
  }
});

// GET /api/snippets
app.get('/api/snippets', async (req, res) => {
  try {
    const snippets = await Snippet.find();
    res.status(200).json(snippets);
  } catch (err) {
    console.error('Error fetching snippets:', err.message, err.stack);
    res.status(500).json({ success: false, error: 'Failed to fetch snippets: ' + err.message });
  }
});

// DELETE /api/snippets/:id
app.delete('/api/snippets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deletedSnippet = await Snippet.findByIdAndDelete(id);
    if (!deletedSnippet) {
      return res.status(404).json({ message: 'Snippet not found' });
    }
    res.status(200).json({ success: true, message: 'Snippet deleted successfully' });
  } catch (err) {
    console.error('Error deleting snippet:', err.message, err.stack);
    res.status(500).json({ message: 'Failed to delete snippet: ' + err.message });
  }
});

// GET /api/snippets/:id
app.get('/api/snippets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const snippet = await Snippet.findById(id);
    if (!snippet) {
      return res.status(404).json({ message: 'Snippet not found' });
    }
    res.status(200).json({ encryptedData: snippet.encryptedData, title: snippet.title, createdAt: snippet.createdAt });
  } catch (err) {
    console.error('Error fetching snippet:', err.message, err.stack);
    res.status(500).json({ message: 'Failed to fetch snippet: ' + err.message });
  }
});

// Start server
const port = process.env.PORT || 5000;
connectToMongoDB().then(() => {
  app.listen(port, () => console.log(`Server running on port ${port}`));
}).catch(err => {
  console.error('Failed to start server due to MongoDB error:', err.message);
});