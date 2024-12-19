const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');


dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(cookieParser());

// CORS configuration
const allowedOrigins = [
  'http://localhost:2395',
  'http://localhost:8275',
  'http://localhost:6290',
];
app.use(
  cors({
    origin: (origin, callback) => {
      if (allowedOrigins.includes(origin) || !origin) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
  })
);

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error(err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// To-Do Schema
const todoSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  completed: { type: Boolean, default: false },
});

const Todo = mongoose.model('Todo', todoSchema);

// JWT function
const generateAccessToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '5m' });
};

const generateRefreshToken = (userId) => {
  return jwt.sign({ userId }, process.env.REFRESH_SECRET, { expiresIn: '7d' });
};

// Authentication
const authenticateToken = (req, res, next) => {
  const token = req.cookies.accessToken || req.headers['authorization'];
  if (!token) return res.status(401).send('Access denied');

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Invalid token');
    req.user = user;
    next();
  });
};

// Rate limiter
const addTodoLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit to 10 requests per window per user
  handler: (req, res) => {
    res.status(429).send('Too many requests, please try again later.');
  },
});

// Routes

// User signup
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).send('User created');
  } catch (error) {
    res.status(500).send('Error creating user');
  }
});

// User login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).send('User not found');

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(403).send('Invalid credentials');

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    res
      .cookie('accessToken', accessToken, { httpOnly: true, secure: true })
      .cookie('refreshToken', refreshToken, { httpOnly: true, secure: true })
      .send('Logged in');
  } catch (error) {
    res.status(500).send('Error logging in');
  }
});

// Refresh token
app.post('/refresh', (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) return res.status(401).send('Refresh token missing');

  jwt.verify(refreshToken, process.env.REFRESH_SECRET, (err, user) => {
    if (err) return res.status(403).send('Invalid refresh token');

    const accessToken = generateAccessToken(user.userId);
    res.cookie('accessToken', accessToken, { httpOnly: true, secure: true }).send('Token refreshed');
  });
});

// Create a to-do
app.post('/todos', authenticateToken, addTodoLimiter, async (req, res) => {
  try {
    const todo = new Todo({ userId: req.user.userId, text: req.body.text });
    await todo.save();
    res.status(201).send(todo);
  } catch (error) {
    res.status(500).send('Error creating to-do');
  }
});

// Get all to-dos
app.get('/todos', authenticateToken, async (req, res) => {
  try {
    const todos = await Todo.find({ userId: req.user.userId });
    res.status(200).send(todos);
  } catch (error) {
    res.status(500).send('Error fetching to-dos');
  }
});

// Update a to-do
app.put('/todos/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const todo = await Todo.findOneAndUpdate(
      { _id: id, userId: req.user.userId },
      req.body,
      { new: true }
    );
    if (!todo) return res.status(404).send('To-do not found');
    res.status(200).send(todo);
  } catch (error) {
    res.status(500).send('Error updating to-do');
  }
});

// Delete a to-do
app.delete('/todos/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const todo = await Todo.findOneAndDelete({ _id: id, userId: req.user.userId });
    if (!todo) return res.status(404).send('To-do not found');
    res.status(200).send('To-do deleted');
  } catch (error) {
    res.status(500).send('Error deleting to-do');
  }
});

// Start the server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
