const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;
const secretKey = process.env.SECRET_KEY || 'default_secret_key';

app.use(bodyParser.json());
app.use(cors());

const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/aitool';

mongoose.connect(MONGO_URI, {
  useNewUrlParser: true
})
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });


const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  terms: { type: Boolean, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  created_at: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Routes
app.post('/register', async (req, res) => {
  try {
    console.log(req.body);
    const { name, terms, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).send({ message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, terms, email, password: hashedPassword });

    await newUser.save();
    res.status(200).send({ message: 'Registration successful' });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).send({ message: 'Server error', error: error.message });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).send({ message: 'Email and password are required' });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).send({ message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).send({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: user._id, email: user.email }, secretKey, { expiresIn: '1h' });
    res.status(200).send({ message: 'Login successful', token });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).send({ message: 'Server error', error: error.message });
  }
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send({ message: 'No token provided' });

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).send({ message: 'Invalid token' });

    req.user = user;
    next();
  });
};

app.get('/dashboard', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) return res.status(404).send({ message: 'User not found' });

    res.send({
      message: `Welcome to the dashboard, ${user.name}`,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).send({ message: 'Server error', error: error.message });
  }
});

const searchHistorySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  query: {
    type: String,
    required: true
  },
  response: {
    type: String,
    required: true
  },
  model: {
    type: String,
    default: 'llama3-8b-8192'
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

const SearchHistory = mongoose.model('SearchHistory', searchHistorySchema);

 
app.post('/api/search-history', authenticateToken, async (req, res) => {
  try {
    const { query, response, model } = req.body;
    
    const newSearchHistory = new SearchHistory({
      userId: req.user.id,
      query,
      response,
      model
    });
    
    await newSearchHistory.save();
    res.status(201).send({ message: 'Search history saved successfully' });
  } catch (error) {
    console.error('Error saving search history:', error);
    res.status(500).send({ message: 'Server error', error: error.message });
  }
});

app.get('/api/search-history', authenticateToken, async (req, res) => {
  try {
    const searchHistory = await SearchHistory.find({ userId: req.user.id })
      .sort({ timestamp: -1 }) // Sort by most recent first
      .limit(100); // Limit to last 100 searches
    
    res.status(200).send({ searchHistory });
  } catch (error) {
    console.error('Error fetching search history:', error);
    res.status(500).send({ message: 'Server error', error: error.message });
  }
});
app.listen(port, '0.0.0.0', () => console.log(`🚀 Backend running on port ${port}`));
