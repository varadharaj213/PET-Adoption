const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const Razorpay = require('razorpay');
const shortid = require('shortid'); // For short receipt IDs

const app = express();
const port = 3000;

// In-memory session store
const sessions = new Map();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname)); // Serve HTML files

// MongoDB connection (no deprecated options)
mongoose.connect('mongodb://localhost:27017/petAdoptionDB')
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);

// Cart Item Schema
const cartItemSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  price: { type: Number, required: true },
  addedAt: { type: Date, default: Date.now }
});
const CartItem = mongoose.model('CartItem', cartItemSchema);

// Order Schema
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  orderId: { type: String, required: true },
  paymentId: { type: String },
  amount: { type: Number, required: true },
  status: { type: String, enum: ['created', 'paid', 'failed'], default: 'created' },
  items: [{ name: String, price: Number }],
  createdAt: { type: Date, default: Date.now }
});
const Order = mongoose.model('Order', orderSchema);

// Razorpay Instance — YOUR KEYS
const razorpay = new Razorpay({
  key_id: 'rzp_test_RYuWgazZjQEj9N',
  key_secret: '1Xfwer23WcMl2D1I2uACJYx2'
});

// Generate secure token
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Register
app.post('/register', async (req, res) => {
  const { fullName, email, username, password, confirmPassword } = req.body;
  if (password !== confirmPassword) return res.status(400).json({ success: false, message: 'Passwords do not match' });

  try {
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) return res.status(400).json({ success: false, message: 'Email or username already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ fullName, email, username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ success: true, message: 'Registration successful! Please login.' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ $or: [{ username }, { email: username }] });
    if (!user) return res.status(400).json({ success: false, message: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, message: 'Invalid credentials' });

    const token = generateToken();
    sessions.set(token, { username: user.username, fullName: user.fullName });

    res.json({
      success: true,
      message: 'Login successful',
      token,
      username: user.username,
      fullName: user.fullName
    });
  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Verify session
app.get('/api/me', (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const session = token && sessions.get(token);
  if (session) {
    res.json({ success: true, ...session });
  } else {
    res.status(401).json({ success: false, message: 'Not authenticated' });
  }
});

// Add to Cart
app.post('/api/cart/add', async (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const session = token && sessions.get(token);
  if (!session) return res.status(401).json({ success: false, message: 'Login required' });

  const { name, price } = req.body;
  if (!name || !price) return res.status(400).json({ success: false, message: 'Missing item data' });

  try {
    const user = await User.findOne({ username: session.username });
    const cartItem = new CartItem({ userId: user._id, name, price: parseInt(price) });
    await cartItem.save();
    res.json({ success: true, message: 'Added to cart' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get Cart
app.get('/api/cart', async (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const session = token && sessions.get(token);
  if (!session) return res.status(401).json({ success: false, message: 'Login required' });

  try {
    const user = await User.findOne({ username: session.username });
    const items = await CartItem.find({ userId: user._id }).sort({ addedAt: -1 });
    const total = items.reduce((sum, item) => sum + item.price, 0);
    res.json({ success: true, items, total });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Remove from Cart
app.delete('/api/cart/remove/:id', async (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const session = token && sessions.get(token);
  if (!session) return res.status(401).json({ success: false, message: 'Login required' });

  try {
    const user = await User.findOne({ username: session.username });
    await CartItem.deleteOne({ _id: req.params.id, userId: user._id });
    res.json({ success: true, message: 'Removed' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Clear Cart
app.delete('/api/cart/clear', async (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const session = token && sessions.get(token);
  if (!session) return res.status(401).json({ success: false, message: 'Login required' });

  try {
    const user = await User.findOne({ username: session.username });
    await CartItem.deleteMany({ userId: user._id });
    res.json({ success: true, message: 'Cart cleared' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Create Razorpay Order
app.post('/api/orders/create', async (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const session = token && sessions.get(token);
  if (!session) return res.status(401).json({ success: false, message: 'Login required' });

  const { amount } = req.body;
  if (!amount || amount <= 0) return res.status(400).json({ success: false, message: 'Invalid amount' });

  try {
    const user = await User.findOne({ username: session.username });
    const receiptId = `rec_${shortid.generate()}`; // Short & safe

    const options = {
      amount: amount * 100,
      currency: 'INR',
      receipt: receiptId
    };

    const razorpayOrder = await razorpay.orders.create(options);
    const dbOrder = new Order({
      userId: user._id,
      orderId: razorpayOrder.id,
      amount: amount
    });
    await dbOrder.save();

    res.json({ success: true, order: razorpayOrder, dbOrderId: dbOrder._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'Failed to create order' });
  }
});

// Verify Payment
app.post('/api/orders/verify', async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, dbOrderId } = req.body;

  const generated_signature = crypto
    .createHmac('sha256', '1Xfwer23WcMl2D1I2uACJYx2')
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');

  if (generated_signature !== razorpay_signature) {
    return res.status(400).json({ success: false, message: 'Invalid signature' });
  }

  try {
    const dbOrder = await Order.findById(dbOrderId);
    const user = await User.findById(dbOrder.userId);
    const cartItems = await CartItem.find({ userId: user._id });

    dbOrder.paymentId = razorpay_payment_id;
    dbOrder.status = 'paid';
    dbOrder.items = cartItems.map(i => ({ name: i.name, price: i.price }));
    await dbOrder.save();

    await CartItem.deleteMany({ userId: user._id });

    res.json({ success: true, message: 'Payment successful', order: dbOrder });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get User Orders
app.get('/api/orders', async (req, res) => {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  const session = token && sessions.get(token);
  if (!session) return res.status(401).json({ success: false, message: 'Login required' });

  try {
    const user = await User.findOne({ username: session.username });
    const orders = await Order.find({ userId: user._id }).sort({ createdAt: -1 });
    res.json({ success: true, orders });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});