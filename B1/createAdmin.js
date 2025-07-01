const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

mongoose.connect('mongodb://127.0.0.1:27017/bookdekho')
  .then(() => {
    console.log('✅ Connected to MongoDB');
    createAdmin();
  })
  .catch(err => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// Define user schema same as in your server.js
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  mobile: String,
  whatsapp: String,
  isAdmin: { type: Boolean, default: false },
});
const User = mongoose.model('User', userSchema);

async function createAdmin() {
  const email = 'swapnanil238@gmail.com';         // <-- Change to your desired admin email
  const password = 'Swapnanil@04';  // <-- Change to your desired admin password

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      console.log(`⚠️ Admin user with email "${email}" already exists.`);
      mongoose.disconnect();
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const adminUser = new User({
      email,
      password: hashedPassword,
      isAdmin: true,
      mobile: '',
      whatsapp: '',
    });

    await adminUser.save();
    console.log(`✅ Admin user created successfully!`);
    console.log(`Email: ${email}`);
    console.log(`Password: ${password}`);
  } catch (err) {
    console.error('❌ Error creating admin user:', err);
  } finally {
    mongoose.disconnect();
  }
}
