const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const port = 3000;

// Middleware setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser()); // Use cookie-parser middleware

// MongoDB connection
const mongoURI = 'mongodb://localhost:27017/WT';
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch((err) => console.error('Failed to connect to MongoDB:', err));

// Authentication middleware to verify JWT token from cookies
function authenticateToken(req, res, next) {
    const token = req.cookies.token; // Retrieve token from cookies
    if (!token) return res.redirect('/login'); // Redirect to login if token is missing

    jwt.verify(token, 'secretKey', (err, user) => {
        if (err) return res.redirect('/login'); // Redirect if token is invalid
        req.user = user;
        next();
    });
}

// Define Schemas and Models
const appointmentSchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    doctor: String,
    location: String,
    date: Date,
    timeslot: String,
    message: String,
});
const Appointment = mongoose.model('Appointment', appointmentSchema);

const emergencySchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    reason: String,
});
const Emergency = mongoose.model('Emergency', emergencySchema);

const contactSchema = new mongoose.Schema({
    name: String,
    email: String,
    phone: String,
    reason: String,
});
const Contact = mongoose.model('Contact', contactSchema);

const userSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
});
const User = mongoose.model('User', userSchema);

const doctorSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    hospitalId: { type: String, unique: true },
    password: String,
});
const Doctor = mongoose.model('Doctor', doctorSchema);

// Helper function to hash password
async function hashPassword(password) {
    return await bcrypt.hash(password, 10);
}

// API Endpoints

// User Registration
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const hashedPassword = await hashPassword(password);
        const user = new User({ name, email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Error registering user', details: error.message });
    }
});

// Doctor Registration
app.post('/api/register-doctor', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const hospitalId = `HOSP-${Math.floor(Math.random() * 10000)}`;
        const hashedPassword = await hashPassword(password);
        const doctor = new Doctor({ name, email, hospitalId, password: hashedPassword });
        await doctor.save();
        res.status(201).json({ message: 'Doctor registered successfully', hospitalId });
    } catch (error) {
        res.status(500).json({ error: 'Error registering doctor', details: error.message });
    }
});

// User Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (user && await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ userId: user._id, role: 'user' }, 'secretKey', { expiresIn: '1m' }); // 2 minutes expiration
            res.cookie('token', token, { httpOnly: true, maxAge: 120000 }); // 2 minutes cookie expiration
            res.redirect('/profile'); // Redirect to profile on successful login
        } else {
            res.status(401).json({ error: 'Invalid email or password' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Error logging in user', details: error.message });
    }
});

// Doctor Login
app.post('/api/login-doctor', async (req, res) => {
    const { hospitalId, password } = req.body;
    try {
        const doctor = await Doctor.findOne({ hospitalId });
        if (doctor && await bcrypt.compare(password, doctor.password)) {
            const token = jwt.sign({ doctorId: doctor._id, role: 'doctor' }, 'secretKey', { expiresIn: '1m' }); // 2 minutes expiration
            res.cookie('token', token, { httpOnly: true, maxAge: 120000 }); // 2 minutes cookie expiration
            res.redirect('/doctor'); // Redirect to doctor dashboard on successful login
        } else {
            res.status(401).json({ error: 'Invalid hospital ID or password' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Error logging in doctor', details: error.message });
    }
});

// Logout route to clear token cookie
app.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login'); // Redirect to login page after logout
});

// Appointment Booking
app.post('/api/appointments', async (req, res) => {
    try {
        const appointment = new Appointment(req.body);
        await appointment.save();
        res.status(201).send('Appointment booked successfully!');
    } catch (error) {
        res.status(400).send('Error booking appointment: ' + error.message);
    }
});

// Emergency Booking
app.post('/api/emergency', async (req, res) => {
    try {
        const emergency = new Emergency(req.body);
        await emergency.save();
        res.status(201).send('Emergency Appointment booked successfully!');
    } catch (error) {
        res.status(400).send('Error booking appointment: ' + error.message);
    }
});

// Contact Form Submission
app.post('/api/contact', async (req, res) => {
    try {
        const contact = new Contact(req.body);
        await contact.save();
        res.status(201).send('Feedback Submitted successfully!');
    } catch (error) {
        res.status(400).send('Error Submitting Feedback: ' + error.message);
    }
});

// Routes with protected access
app.get('/profile', authenticateToken, (req, res) => res.render('profile'));
app.get('/appointment', authenticateToken, (req, res) => res.render('appointment'));
app.get('/contact', authenticateToken, (req, res) => res.render('contact'));

// Public routes
app.get('/', (req, res) => res.render('index'));
app.get('/login', (req, res) => res.render('login'));
app.get('/emergency', (req, res) => res.render('emergency'));
app.get('/doctor', (req, res) => res.render('doctor'));
app.get('/admin', (req, res) => res.render('admin'));

// Start Server
app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});
