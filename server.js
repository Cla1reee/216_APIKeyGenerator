require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(express.json());

// Konfigurasi Database
const dbConfig = {
    host: 'localhost',
    user: 'root', 
    password: '', 
    database: 'api_mgmt_db'
};

const JWT_SECRET = 'rahasia_negara'; 

// --- MIDDLEWARE ---

// Verifikasi Token JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Cek Role Admin
const verifyAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: "Akses ditolak. Hanya Admin." });
    next();
};

// --- ROUTES AUTH ---

// Register
app.post('/register', async (req, res) => {
    try {
        const { username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const connection = await mysql.createConnection(dbConfig);
        
        // Default role mahasiswa jika tidak diisi, admin harus diset manual atau lewat db
        const userRole = role === 'admin' ? 'admin' : 'mahasiswa'; 

        await connection.execute(
            'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
            [username, hashedPassword, userRole]
        );
        await connection.end();
        res.status(201).json({ message: 'User berhasil didaftarkan' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Login
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT * FROM users WHERE username = ?', [username]);
        await connection.end();

        if (rows.length === 0) return res.status(400).json({ message: 'User tidak ditemukan' });

        const user = rows[0];
        if (await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
            res.json({ token, role: user.role, username: user.username });
        } else {
            res.status(403).json({ message: 'Password salah' });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// --- ROUTES API MANAGEMENT ---

// Generate API Key (Mahasiswa Only)
app.post('/api/generate', authenticateToken, async (req, res) => {
    try {
        const newKey = `KEY-${uuidv4()}`;
        const connection = await mysql.createConnection(dbConfig);
        await connection.execute(
            'INSERT INTO api_keys (user_id, api_key) VALUES (?, ?)',
            [req.user.id, newKey]
        );
        await connection.end();
        res.json({ message: 'API Key berhasil dibuat', key: newKey });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get My Keys (Mahasiswa: Lihat key sendiri)
app.get('/api/my-keys', authenticateToken, async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT * FROM api_keys WHERE user_id = ?', [req.user.id]);
        await connection.end();
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get All Keys (Admin: Lihat semua key & pemiliknya)
app.get('/api/admin/all-keys', authenticateToken, verifyAdmin, async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute(`
            SELECT api_keys.*, users.username 
            FROM api_keys 
            JOIN users ON api_keys.user_id = users.id
        `);
        await connection.end();
        res.json(rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Revoke Key (Bisa dilakukan Admin atau Pemilik Key)
app.post('/api/revoke', authenticateToken, async (req, res) => {
    const { key_id } = req.body;
    try {
        const connection = await mysql.createConnection(dbConfig);
        
        let query = '';
        let params = [];

        if (req.user.role === 'admin') {
            query = 'UPDATE api_keys SET status = "revoked" WHERE id = ?';
            params = [key_id];
        } else {
            query = 'UPDATE api_keys SET status = "revoked" WHERE id = ? AND user_id = ?';
            params = [key_id, req.user.id];
        }

        const [result] = await connection.execute(query, params);
        await connection.end();

        if (result.affectedRows === 0) return res.status(404).json({ message: 'Key tidak ditemukan atau akses ditolak' });
        res.json({ message: 'API Key berhasil dicabut (revoked)' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/admin/delete-key/:id', authenticateToken, verifyAdmin, async (req, res) => {
    const keyId = req.params.id;
    try {
        const connection = await mysql.createConnection(dbConfig);
        
        // Hapus row dari tabel api_keys
        const [result] = await connection.execute('DELETE FROM api_keys WHERE id = ?', [keyId]);
        await connection.end();

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Key tidak ditemukan' });
        }

        res.json({ message: 'API Key berhasil dihapus permanen dari database' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.listen(3000, () => {
    console.log('Server berjalan di port 3000');
});