/*
 * Inkwell - mini Medium clone (backend)
 * Express + MongoDB (Mongoose) + JWT. Also serves index.html.
 *
 * Setup:   npm install
 * Run:     npm run dev        then open http://localhost:5000
 *
 * Environment variables (put them in .env):
 *   MONGO_URI   (default mongodb://127.0.0.1:27017/inkwell)
 *   JWT_SECRET  (required when NODE_ENV=production)
 *   PORT        (default 5000)
 */
require('dotenv').config();
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/inkwell';
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  console.error('JWT_SECRET must be set in production.');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-secret-change-me';

/* ------------------------------ Models ------------------------------ */
const userSchema = new mongoose.Schema(
  {
    username: { type: String, required: true, unique: true, trim: true, minlength: 3, maxlength: 30 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
  },
  { timestamps: true }
);
// Never send the password hash to the client
userSchema.set('toJSON', {
  transform: (_doc, ret) => {
    delete ret.passwordHash;
    delete ret.__v;
    return ret;
  },
});
const User = mongoose.model('User', userSchema);

const postSchema = new mongoose.Schema(
  {
    title: { type: String, required: true, trim: true, maxlength: 150 },
    content: { type: String, required: true },
    tags: [{ type: String, lowercase: true, trim: true }],
    // false = private draft. Posts created before drafts existed have no value and count as published.
    published: { type: Boolean, default: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  },
  { timestamps: true }
);
postSchema.index({ title: 'text', content: 'text' });
const Post = mongoose.model('Post', postSchema);

const commentSchema = new mongoose.Schema(
  {
    post: { type: mongoose.Schema.Types.ObjectId, ref: 'Post', required: true, index: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    text: { type: String, required: true, trim: true, maxlength: 1000 },
  },
  { timestamps: true }
);
const Comment = mongoose.model('Comment', commentSchema);

/* ----------------------------- Middleware ---------------------------- */
// Verifies "Authorization: Bearer <token>" and attaches req.user
async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ message: 'Please log in to continue.' });
    const payload = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(payload.id);
    if (!user) return res.status(401).json({ message: 'This account no longer exists.' });
    req.user = user;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Your session has expired. Please log in again.' });
  }
}

// Like auth, but never rejects: sets req.user when a valid token is sent, otherwise carries on as a guest
async function optionalAuth(req, _res, next) {
  try {
    const header = req.headers.authorization || '';
    if (header.startsWith('Bearer ')) {
      const payload = jwt.verify(header.slice(7), JWT_SECRET);
      req.user = await User.findById(payload.id);
    }
  } catch (_err) {
    /* invalid token: treat as guest */
  }
  next();
}

const signToken = (user) => jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });

const parseTags = (tags) =>
  (Array.isArray(tags) ? tags : String(tags || '').split(','))
    .map((t) => String(t).trim().toLowerCase())
    .filter(Boolean)
    .slice(0, 5);

const toBool = (v) => v === true || v === 'true';

// Remove markdown symbols so list excerpts read as plain text
const stripMarkdown = (s) =>
  s
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
    .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
    .replace(/^\s{0,3}(#{1,6}|>|[-*+]|\d+\.)\s+/gm, '')
    .replace(/(\*\*|__|\*|`|~~)/g, '');

const withExcerpt = (post) => {
  const obj = post.toObject();
  obj.excerpt = stripMarkdown(obj.content).replace(/\s+/g, ' ').slice(0, 180).trim();
  obj.readMinutes = Math.max(1, Math.round(obj.content.split(/\s+/).length / 200));
  delete obj.content;
  return obj;
};

// Sends the first validation error back in the {message} format the frontend expects
const validate = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ message: errors.array()[0].msg });
  next();
};

const registerRules = [
  body('username').trim().isLength({ min: 3, max: 30 }).withMessage('Username must be 3 to 30 characters.'),
  body('email').trim().isEmail().withMessage('Please enter a valid email address.'),
  body('password').isLength({ min: 6, max: 100 }).withMessage('Password must be 6 to 100 characters.'),
  validate,
];

// Drafts only need some text; published posts need at least 20 characters
const postRules = [
  body('title').trim().isLength({ min: 1, max: 150 }).withMessage('Title is required (max 150 characters).'),
  body('content').custom((value, { req }) => {
    const text = String(value || '').trim();
    const isDraft = req.body.published === false || req.body.published === 'false';
    if (text.length > 50000) throw new Error('Story must be at most 50,000 characters.');
    if (isDraft && text.length < 1) throw new Error('Write something before saving a draft.');
    if (!isDraft && text.length < 20) throw new Error('Story must be between 20 and 50,000 characters.');
    return true;
  }),
  validate,
];

/* -------------------------------- App -------------------------------- */
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));

// Security headers. The CSP allows the inline script/styles, Google Fonts and the markdown libraries from cdnjs.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
      },
    },
  })
);

// Limit login/register attempts: 20 per 15 minutes per IP
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many attempts. Please try again in a few minutes.' },
});

app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/api/health', (_req, res) => res.json({ status: 'ok' }));

/* ------------------------------- Auth -------------------------------- */
const authRouter = express.Router();

authRouter.post('/register', authLimiter, registerRules, async (req, res, next) => {
  try {
    const { username, email, password } = req.body;
    const passwordHash = await bcrypt.hash(String(password), 10);
    const user = await User.create({ username, email, passwordHash });
    res.status(201).json({ token: signToken(user), user });
  } catch (err) {
    next(err);
  }
});

authRouter.post('/login', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password are required.' });
    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    const ok = user && (await bcrypt.compare(String(password), user.passwordHash));
    if (!ok) return res.status(401).json({ message: 'Email or password is incorrect.' });
    res.json({ token: signToken(user), user });
  } catch (err) {
    next(err);
  }
});

authRouter.get('/me', auth, (req, res) => res.json({ user: req.user }));
app.use('/api/auth', authRouter);

/* ------------------------------- Posts ------------------------------- */
const postsRouter = express.Router();

// GET /api/posts?page=1&limit=10&q=text&tag=node   (public, published posts only)
postsRouter.get('/', async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(30, parseInt(req.query.limit) || 10);
    const filter = { published: { $ne: false } };
    if (req.query.q) filter.$text = { $search: String(req.query.q) };
    if (req.query.tag) filter.tags = String(req.query.tag).toLowerCase();

    const [posts, total] = await Promise.all([
      Post.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).populate('author', 'username'),
      Post.countDocuments(filter),
    ]);
    res.json({ posts: posts.map(withExcerpt), page, pages: Math.ceil(total / limit), total });
  } catch (err) {
    next(err);
  }
});

// GET /api/posts/mine  (logged in) - your published posts and drafts. Declared before /:id on purpose
postsRouter.get('/mine', auth, async (req, res, next) => {
  try {
    const posts = await Post.find({ author: req.user._id }).sort({ createdAt: -1 }).populate('author', 'username');
    res.json({ posts: posts.map(withExcerpt) });
  } catch (err) {
    next(err);
  }
});

// GET /api/posts/:id  (public; drafts are visible to their author only)
postsRouter.get('/:id', optionalAuth, async (req, res, next) => {
  try {
    const post = await Post.findById(req.params.id).populate('author', 'username');
    if (!post) return res.status(404).json({ message: 'Post not found.' });
    const isOwner = req.user && post.author._id.equals(req.user._id);
    if (post.published === false && !isOwner) return res.status(404).json({ message: 'Post not found.' });
    res.json({ post });
  } catch (err) {
    next(err);
  }
});

// POST /api/posts  (logged in)
postsRouter.post('/', auth, postRules, async (req, res, next) => {
  try {
    const { title, content, tags, published } = req.body;
    const post = await Post.create({
      title,
      content,
      tags: parseTags(tags),
      published: published === undefined ? true : toBool(published),
      author: req.user._id,
    });
    await post.populate('author', 'username');
    res.status(201).json({ post });
  } catch (err) {
    next(err);
  }
});

// PUT /api/posts/:id  (owner only)
postsRouter.put('/:id', auth, postRules, async (req, res, next) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ message: 'Post not found.' });
    if (!post.author.equals(req.user._id)) {
      return res.status(403).json({ message: 'You can only edit your own posts.' });
    }
    const { title, content, tags, published } = req.body;
    if (title !== undefined) post.title = title;
    if (content !== undefined) post.content = content;
    if (tags !== undefined) post.tags = parseTags(tags);
    if (published !== undefined) post.published = toBool(published);
    await post.save();
    await post.populate('author', 'username');
    res.json({ post });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/posts/:id  (owner only)
postsRouter.delete('/:id', auth, async (req, res, next) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post) return res.status(404).json({ message: 'Post not found.' });
    if (!post.author.equals(req.user._id)) {
      return res.status(403).json({ message: 'You can only delete your own posts.' });
    }
    await Comment.deleteMany({ post: post._id });
    await post.deleteOne();
    res.json({ message: 'Post deleted.' });
  } catch (err) {
    next(err);
  }
});

/* ------------------------------ Comments ----------------------------- */
// GET /api/posts/:id/comments  (public; hidden while the post is a draft)
postsRouter.get('/:id/comments', optionalAuth, async (req, res, next) => {
  try {
    const post = await Post.findById(req.params.id);
    const isOwner = post && req.user && post.author.equals(req.user._id);
    if (!post || (post.published === false && !isOwner)) {
      return res.status(404).json({ message: 'Post not found.' });
    }
    const comments = await Comment.find({ post: post._id }).sort({ createdAt: 1 }).populate('author', 'username');
    res.json({ comments });
  } catch (err) {
    next(err);
  }
});

// POST /api/posts/:id/comments  (logged in, published posts only)
postsRouter.post('/:id/comments', auth, async (req, res, next) => {
  try {
    const post = await Post.findById(req.params.id);
    if (!post || post.published === false) return res.status(404).json({ message: 'Post not found.' });
    const comment = await Comment.create({ post: post._id, author: req.user._id, text: req.body.text });
    await comment.populate('author', 'username');
    res.status(201).json({ comment });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/posts/:id/comments/:commentId  (comment author or post author)
postsRouter.delete('/:id/comments/:commentId', auth, async (req, res, next) => {
  try {
    const comment = await Comment.findById(req.params.commentId);
    if (!comment) return res.status(404).json({ message: 'Comment not found.' });
    const post = await Post.findById(comment.post);
    const isOwner = comment.author.equals(req.user._id);
    const isPostAuthor = post && post.author.equals(req.user._id);
    if (!isOwner && !isPostAuthor) return res.status(403).json({ message: 'You cannot delete this comment.' });
    await comment.deleteOne();
    res.json({ message: 'Comment deleted.' });
  } catch (err) {
    next(err);
  }
});

app.use('/api/posts', postsRouter);

/* --------------------------- Error handling -------------------------- */
app.use('/api', (req, res) => res.status(404).json({ message: `Route not found: ${req.method} ${req.originalUrl}` }));

app.use((err, _req, res, _next) => {
  if (err instanceof mongoose.Error.ValidationError) {
    return res.status(400).json({ message: Object.values(err.errors).map((e) => e.message).join(' ') });
  }
  if (err instanceof mongoose.Error.CastError) return res.status(400).json({ message: 'Invalid id.' });
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern || {})[0] || 'value';
    return res.status(409).json({ message: `That ${field} is already taken.` });
  }
  console.error(err);
  res.status(500).json({ message: 'Something went wrong on our side.' });
});

/* -------------------------------- Start ------------------------------ */
mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log('MongoDB connected');
    app.listen(PORT, () => console.log(`Inkwell running at http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('MongoDB connection failed:', err.message);
    process.exit(1);
  });