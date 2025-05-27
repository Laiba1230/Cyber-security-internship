const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');

const app = express();
app.use(express.json());
app.use(helmet());

const users = [];
const JWT_SECRET = 'your_very_strong_secret_key_here'; // In production, use environment variables

// Register Route
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    // Validate Email
    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: 'Invalid email format' });
    }

    // Validate Password
    if (!password || password.length < 8) {
        return res.status(400).json({ message: 'Password must be at least 8 characters' });
    }

    // Check if user exists
    if (users.some(user => user.email === email)) {
        return res.status(400).json({ message: 'User already exists' });
    }

    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Store User
    users.push({ email, password: hashedPassword });
    res.status(201).json({ message: 'User registered successfully' });
});

// Login Route would go here...

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
