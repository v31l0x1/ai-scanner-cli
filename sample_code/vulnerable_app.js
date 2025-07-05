const express = require('express');
const { exec } = require('child_process');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(express.json());

// Information Exposure - X-Powered-By header
// This exposes framework information to potential attackers

app.get('/user/:id', (req, res) => {
    const userId = req.params.id;

    // Cross-site Scripting (XSS) vulnerability
    // Unsanitized input directly rendered in response
    res.send(`<h1>User Profile for ${userId}</h1>`);
});

// SQL Injection vulnerability
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const db = new sqlite3.Database(':memory:');

    // Vulnerable SQL query - user input directly interpolated
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.get(query, (err, row) => {
        if (row) {
            res.json({ success: true, user: row });
        } else {
            res.json({ success: false });
        }
    });
});

// Command Injection vulnerability
app.post('/execute', (req, res) => {
    const command = req.body.command;

    // Dangerous - executes user input as system command
    exec(command, (error, stdout, stderr) => {
        if (error) {
            res.status(500).send(error.message);
        } else {
            res.send(stdout);
        }
    });
});

// File Upload XSS vulnerability
app.post('/upload', (req, res) => {
    const filename = req.body.filename;

    // Another XSS vulnerability - file name not sanitized
    res.send(`<p>File uploaded: ${filename}</p>`);
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
