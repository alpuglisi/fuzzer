const express = require('express');
const app = express();
const port = 3000;
const path = require('path');
const fs = require('fs');

const jwt = require('jsonwebtoken'); // for generating and verifying JWT tokens
const SECRET_KEY = "REDACTED_JWT_SIGNING_SECRET";

app.use(express.json());


app.use(express.static(path.join(__dirname, 'public')));

const users = [
    { 
        id: 1, 
        username: "juice_student", 
        role: "user",
        secret_data: "My balance: 50 UAH",
        password: "REDACTED_DEMO_PASSWORD"
    },
    {
        id: 2,
        username: "admin_boss",
        role: "admin",
        secret_data: "Main server password: REDACTED_DEMO_PASSWORD",
        password: "REDACTED_DEMO_PASSWORD"
    }
];

app.get('/api/users/:id', (req, res) => {
    const requestedId = parseInt(req.params.id);

    const userToken = req.headers['authorization'];

    if (!userToken) {
        return res.status(401).json({ error: "Access denied: missing authorization token" });
    }

    const token = userToken.replace('Bearer ', '');

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        //!!!if the userId in the token does not match the requested ID, block access
        if (decoded.userId !== requestedId) {
            return res.status(403).json({ error: "Forbidden: IDOR attempt blocked!" });
        }
    } catch (err) {
        return res.status(401).json({ error: "Invalid authorization token" });
    }
    const user = users.find(u => u.id === requestedId);

    if (!user) {
        return res.status(404).json({ error: "User not found" });
    }

    res.status(200).json(user);
});

app.post('/login', (req, res) => {
    const { id, password } = req.body; 
    const user = users.find(u => u.id === parseInt(id) && u.password === password);
    
    if (!user) {
        return res.status(401).json({ error: "Invalid login or password" });
    }

    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });

    res.status(200).json({ message: "Login successful", token: token });
});

app.use((req, res) => {
    res.status(404).json({ error: "Resource not found" });
});

app.use(function (err, req, res, ) {
    res.status(500).json({ error: "Internal server error" });
});

if(require.main === module) {
    app.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
}

module.exports = app;