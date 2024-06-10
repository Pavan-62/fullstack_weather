const express = require('express');
const bcrypt = require('bcryptjs'); // Use bcryptjs
const admin = require('firebase-admin');
const session = require('express-session');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');
const fetch = require('node-fetch');
const serviceAccount = require('./key.json');

initializeApp({
  credential: cert(serviceAccount),
});

const db = getFirestore();
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// Set EJS as templating engine
app.set('view engine', 'ejs');

// Session middleware
app.use(session({
  secret: 'secret-key',
  resave: false,
  saveUninitialized: false,
}));

// Routes
app.get('/signup', (req, res) => {
  res.render('signup');
});

app.get('/signin', (req, res) => {
  res.render('signin');
});

app.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Check if email already exists
    await admin.auth().getUserByEmail(email);
    return res.status(400).send('Email already exists');
  } catch (error) {
    if (error.code !== 'auth/user-not-found') {
      return res.status(400).send(error.message);
    }
  }

  try {
    // Create user in Firebase Auth
    const userRecord = await admin.auth().createUser({
      email,
      password,
      displayName: name,
    });

    // Hash the password before storing it in Firestore
    const passwordHash = await bcrypt.hash(password, 10);

    // Store user details in Firestore
    await db.collection('Registered_Data').doc(userRecord.uid).set({
      name,
      email,
      passwordHash // Store hashed password
    });

    res.redirect('/signin');
  } catch (error) {
    res.status(400).send(error.message);
  }
});

app.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Get user by email
    const userRecord = await admin.auth().getUserByEmail(email);

    // Get user data from Firestore
    const userDoc = await db.collection('Registered_Data').doc(userRecord.uid).get();
    if (!userDoc.exists) {
      throw new Error('User not found');
    }

    // Verify password
    const userData = userDoc.data();
    const validPassword = await bcrypt.compare(password, userData.passwordHash);
    if (!validPassword) {
      return res.status(400).send('Invalid credentials');
    }

    // Store user in session
    req.session.user = {
      uid: userRecord.uid,
      name: userRecord.displayName,
      email: userRecord.email,
    };

    res.redirect('/weather');
  } catch (error) {
    res.status(400).send(error.message);
  }
});

app.get('/weather', (req, res) => {
  // Render weather page
  res.render('weather');
});

app.post('/weather', async (req, res) => {
  const { location } = req.body;
  const apiKey = '6793461102434d5f8b160545241006';

  try {
    const response = await fetch(`http://api.weatherapi.com/v1/current.json?key=${apiKey}&q=${location}`);

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`HTTP error! Status: ${response.status} - ${errorText}`);
    }

    const weatherData = await response.json();

    // Render the weather data on the page
    res.render('weather', { weather: weatherData });
  } catch (error) {
    console.error('Error fetching weather data:', error);
    res.status(500).send('Failed to fetch weather data. Please try again later.');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Error logging out');
    }
    res.redirect('/signin');
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
