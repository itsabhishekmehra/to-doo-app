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

// ===== Middleware =====
app.use(express.json());
app.use(cookieParser());

// ===== CORS =====
const allowedOrigins = [
  'http://localhost:2395',
  'http://localhost:8275',
  'http://localhost:6290',
];

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
  })
);

// ===== MongoDB (Vercel-safe) =====
let isConnected = false;

async function connectDB() {
  if (isConnected) return;

  await mongoose.connect(process.env.MONGO_URI);
  isConnected = true;
  console.log('MongoDB connected');
}

app.use(async (req, res, next) => {
  try {
    await connectDB();
    next();
  } catch (err) {
    console.error(err);
    res.status(500).send('Database connection failed');
  }
});

// ===== Schemas =====
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const todoSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  text: { type: String, required: true },
  completed: { type: Boolean, default: false },
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Todo = mongoose.models.Todo || mongoose.model('Todo', todoSchema);

// ===== JWT =====
const generateAccessToken = (userId) =>
  jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '5m' });

const generateRefreshToken = (userId) =>
  jwt.sign({ userId }, process.env.REFRESH_SECRET, { expiresIn: '7d' });

// ===== Auth middleware =====
const authenticateToken = (req, res, next) => {
  const token = req.cookies.accessToken || req.headers.authorization;
  if (!token) return res.status(401).send('Access denied');

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Invalid token');
    req.user = user;
    next();
  });
};

// ===== Rate limiter =====
const addTodoLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
});

// ===== Routes =====
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    await new User({ username, password: hashedPassword }).save();
    res.status(201).send('User created');
  } catch {
    res.status(500).send('Error creating user');
  }
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).send('User not found');

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(403).send('Invalid credentials');

    res
      .cookie('accessToken', generateAccessToken(user._id), { httpOnly: true, secure: true })
      .cookie('refreshToken', generateRefreshToken(user._id), { httpOnly: true, secure: true })
      .send('Logged in');
  } catch {
    res.status(500).send('Error logging in');
  }
});

app.post('/todos', authenticateToken, addTodoLimiter, async (req, res) => {
  const todo = await new Todo({ userId: req.user.userId, text: req.body.text }).save();
  res.status(201).send(todo);
});

app.get('/todos', authenticateToken, async (req, res) => {
  res.send(await Todo.find({ userId: req.user.userId }));
});

app.put('/todos/:id', authenticateToken, async (req, res) => {
  const todo = await Todo.findOneAndUpdate(
    { _id: req.params.id, userId: req.user.userId },
    req.body,
    { new: true }
  );
  if (!todo) return res.status(404).send('Not found');
  res.send(todo);
});

app.delete('/todos/:id', authenticateToken, async (req, res) => {
  await Todo.findOneAndDelete({ _id: req.params.id, userId: req.user.userId });
  res.send('Deleted');
});

module.exports = app;
