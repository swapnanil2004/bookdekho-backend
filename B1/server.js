const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const nodemailer = require('nodemailer');

const app = express();
const JWT_SECRET = 'secret_key';

// Enable CORS for all origins (frontend running on different port)
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'DELETE', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());

// Ensure uploads folder exists
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// Serve uploads folder statically
app.use('/uploads', express.static(uploadDir));

// --------------------- MongoDB Connection --------------------- //
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log("✅ Connected to MongoDB Atlas"))
.catch((err) => console.error("❌ MongoDB error:", err));


// --------------------- Email Setup --------------------- //
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'swapnanil238@gmail.com',
    pass: 'gniimqscawijvrgp' // Make sure this is a valid App Password if 2FA enabled
  }
});

const sendBookUploadEmail = async (book) => {
  const mailOptions = {
    from: 'BookDekho <swapnanil238@gmail.com>',
    to: 'swapnanil238@gmail.com',
    subject: `📚 New Book Uploaded: ${book.title}`,
    text: `
A new book has been uploaded on BookDekho!

📘 Title: ${book.title}
✍️ Author: ${book.author}
🏷️ Category: ${book.category}
🕮 ISBN: ${book.isbn}
🏢 Publisher: ${book.publisher}
🖨️ Printing Press: ${book.printingPress}
📅 Year of Publication: ${book.yearOfPublication}
📥 Year of Addition: ${book.yearOfAddition}
🧾 Introduction: ${book.introduction}

👤 Writer Info:
- Name: ${book.writerName}
- Username: ${book.writerUsername}
- DOB: ${book.writerDOB}
- Birthplace: ${book.birthPlace}
- Address: ${book.address}
- Biography: ${book.biography}

📞 Contact Info:
- Email: ${book.email}
- Mobile: ${book.mobile}
- WhatsApp: ${book.whatsapp}

📂 PDF File: http://localhost:3000${book.pdf}
🖼️ Cover Image: http://localhost:3000${book.coverImage}
👤 Writer Photo: ${book.writerPhoto ? `http://localhost:3000${book.writerPhoto}` : 'Not provided'}

Book ID: ${book._id}
Uploaded by User ID: ${book.userId}

--
📚 BookDekho Admin Notification
    `.trim()
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("📧 Email sent to admin!");
  } catch (error) {
    console.error("❌ Email sending failed:", error);
  }
};

// --------------------- Schemas --------------------- //
const bookSchema = new mongoose.Schema({
  title: String,
  author: String,
  category: String,
  coverImage: String,
  pdf: String,
  userId: String,
  ratings: [
    {
      userId: String,
      value: Number
    }
  ],
  writerName: String,
  writerUsername: String,
  writerPhoto: String,
  writerDOB: String,
  biography: String,
  birthPlace: String,
  address: String,
  email: String,
  mobile: String,
  whatsapp: String,
  yearOfPublication: String,
  yearOfAddition: String,
  isbn: String,
  publisher: String,
  printingPress: String,
  introduction: String
});
const Book = mongoose.model('Book', bookSchema);

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  mobile: String,
  whatsapp: String,
  isAdmin: { type: Boolean, default: false },
});
const User = mongoose.model('User', userSchema);

// --------------------- Multer Setup --------------------- //
const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  },
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Only PDF and image files are allowed'), false);
  }
};

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter,
});

// --------------------- Middleware --------------------- //
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(403).json({ error: 'Authorization token required' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(403).json({ error: 'Authorization token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user?.isAdmin) next();
  else res.status(403).json({ error: 'Access denied. Admins only.' });
};

// --------------------- Routes --------------------- //

// User registration
app.post('/api/register', async (req, res) => {
  const { email, password, mobile, whatsapp } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).json({ error: 'User already exists' });

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = new User({
    email,
    password: hashedPassword,
    mobile,
    whatsapp
  });

  try {
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Error registering user' });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.status(400).json({ error: 'User not found' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: 'Invalid password' });

  const token = jwt.sign({ userId: user._id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Upload book
app.post('/api/books', authenticateJWT, upload.fields([
  { name: 'coverImage' },
  { name: 'pdf' },
  { name: 'writerPhoto' }
]), async (req, res) => {
  try {
    const {
      title, author, category,
      writerName, writerUsername, writerDOB,
      biography, birthPlace, address,
      email, mobile, whatsapp,
      yearOfPublication, yearOfAddition, isbn,
      publisher, printingPress, introduction
    } = req.body;

    const coverImage = req.files['coverImage']?.[0];
    const pdf = req.files['pdf']?.[0];
    const writerPhoto = req.files['writerPhoto']?.[0];

    if (!title || !author || !category || !coverImage || !pdf || !writerName) {
      return res.status(400).json({ error: 'Required fields missing' });
    }

    const book = new Book({
      title,
      author,
      category,
      coverImage: `/uploads/${coverImage.filename}`,
      pdf: `/uploads/${pdf.filename}`,
      userId: req.user.userId,
      ratings: [],
      writerName,
      writerUsername,
      writerPhoto: writerPhoto ? `/uploads/${writerPhoto.filename}` : '',
      writerDOB,
      biography,
      birthPlace,
      address,
      email,
      mobile,
      whatsapp,
      yearOfPublication,
      yearOfAddition,
      isbn,
      publisher,
      printingPress,
      introduction
    });

    await book.save();
    await sendBookUploadEmail(book);
    res.status(201).json(book);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to upload book' });
  }
});

// Get all books
app.get('/api/books', async (req, res) => {
  try {
    const books = await Book.find();
    res.json(books);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch books' });
  }
});

// Admin: List all users
app.get('/api/admin/users', authenticateJWT, isAdmin, async (req, res) => {
  try {
    const users = await User.find({}, '-password');
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Rate a book
app.post('/api/books/:id/rate', authenticateJWT, async (req, res) => {
  const bookId = req.params.id;
  const userId = req.user.userId;
  const { value } = req.body;

  if (!value || value < 1 || value > 5) {
    return res.status(400).json({ error: 'Rating must be between 1 and 5' });
  }

  try {
    const book = await Book.findById(bookId);
    if (!book) return res.status(404).json({ error: 'Book not found' });

    const existingRating = book.ratings.find(r => r.userId === userId);
    if (existingRating) {
      existingRating.value = value;
    } else {
      book.ratings.push({ userId, value });
    }

    await book.save();
    res.json({ message: 'Rating submitted successfully' });
  } catch (err) {
    console.error('Error rating book:', err);
    res.status(500).json({ error: 'Failed to rate book' });
  }
});

// Admin: Delete a book by ID
app.delete('/api/books/:id', authenticateJWT, isAdmin, async (req, res) => {
  const bookId = req.params.id;

  try {
    const book = await Book.findById(bookId);
    if (!book) return res.status(404).json({ error: 'Book not found' });

    // Remove files from uploads folder safely
    if (book.coverImage) {
      const coverPath = path.join(__dirname, book.coverImage);
      if (fs.existsSync(coverPath)) fs.unlinkSync(coverPath);
    }
    if (book.pdf) {
      const pdfPath = path.join(__dirname, book.pdf);
      if (fs.existsSync(pdfPath)) fs.unlinkSync(pdfPath);
    }
    if (book.writerPhoto) {
      const writerPhotoPath = path.join(__dirname, book.writerPhoto);
      if (fs.existsSync(writerPhotoPath)) fs.unlinkSync(writerPhotoPath);
    }

    await Book.findByIdAndDelete(bookId);
    res.json({ message: 'Book deleted successfully' });
  } catch (err) {
    console.error('Error deleting book:', err);
    res.status(500).json({ error: 'Failed to delete book' });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});

