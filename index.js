require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();

const allowedOrigins = [
  'https://secure-snip.vercel.app',
  'https://secure-snip-mj0v066pj-zsurti-devs-projects.vercel.app',
  'http://localhost:5173'
];

app.use(cors({
  origin: function(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1 || !origin) {
      callback(null, true);
    } else {
      console.log('CORS blocked for origin:', origin);
      callback(null, true);
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/secure-snip';
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || '12345678901234567890123456789012';

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

const snippetSchema = new mongoose.Schema({
  title: { type: String, required: true },
  encryptedData: { type: String, required: true },
  password: { type: String, required: true },
  tags: { type: String },
  createdAt: { type: Date, default: Date.now },
}, { collection: 'Users' });

const Snippet = mongoose.model('Snippet', snippetSchema);

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

app.options('*', cors());

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Server is running' });
});

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
    const savedSnippet = await snippet.save();
    
    res.status(201).json({ success: true, encryptedData, title, id: savedSnippet._id });
  } catch (err) {
    console.error('Error in /api/snippets:', err.message, err.stack);
    if (err.name === 'ValidationError') {
      return res.status(400).json({ success: false, error: 'Validation failed: ' + err.message });
    }
    res.status(500).json({ success: false, error: 'Internal server error: ' + err.message });
  }
});

app.post('/api/decrypt', async (req, res) => {
  const { id, password } = req.body;
  try {
    const snippet = await Snippet.findById(id); // Query by _id
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
    res.status(400).json({ success: false, error: 'Decryption failed: ' + err.message });
  }
});

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

app.delete('/api/snippets/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const deletedSnippet = await Snippet.findByIdAndDelete(id); // Query by _id
    if (!deletedSnippet) {
      return res.status(404).json({ message: 'Snippet not found' });
    }
    res.status(200).json({ success: true, message: 'Snippet deleted successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to delete snippet: ' + err.message });
  }
});

const port = process.env.PORT || 5000;
connectToMongoDB().then(() => {
  app.listen(port, () => console.log(`Server running on port ${port}`));
}).catch(err => {
  console.error('Failed to start server due to MongoDB error:', err.message);
});