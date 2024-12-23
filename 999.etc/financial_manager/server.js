// server.js
const express = require('express');
const { Pool } = require('pg'); // PostgreSQL 클라이언트
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어 설정
app.use(express.json()); // JSON 형식의 요청 본문을 파싱

// PostgreSQL 데이터베이스 연결 설정
const pool = new Pool({
    user: 'yeon_admin',           // PostgreSQL 사용자 이름
    host: 'localhost',            // 데이터베이스 호스트 (로컬)
    database: 'postgres',         // 데이터베이스 이름
    password: 'yeon',             // 데이터베이스 비밀번호
    port: 5432,                   // PostgreSQL 포트
});

// 사용자 등록 API
app.post('/api/users/register', async (req, res) => {
    const { username, birth_date, email, phone_number, role, creator } = req.body;

    try {
        const result = await pool.query(
            'INSERT INTO users (username, birth_date, email, phone_number, role, creator, created_at) VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING *',
            [username, birth_date, email, phone_number, role, creator]
        );
        res.status(201).json(result.rows[0]); // 생성된 사용자 정보 반환
    } catch (error) {
        console.error('Error registering user:', error.message); // 에러 메시지 로그
        res.status(500).json({ error: 'Database error', details: error.message }); // 에러 세부정보 반환
    }
});

// 계정 등록 API
app.post('/api/user_accounts/register', async (req, res) => {
    const { user_id, username, password, created_by } = req.body;

    try {
        // 사용자 ID가 유저 테이블에 존재하는지 확인
        const userResult = await pool.query('SELECT * FROM users WHERE user_id = $1', [user_id]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        const hashedPassword = await bcrypt.hash(password, 10); // 비밀번호 해시화
        const role = userResult.rows[0].role || 'user'; // 사용자의 역할 가져오기 (기본값 'user')

        const result = await pool.query(
            'INSERT INTO user_accounts (user_id, username, password, role, created_at, created_by) VALUES ($1, $2, $3, $4, NOW(), $5) RETURNING *',
            [user_id, username, hashedPassword, role, created_by]
        );

        res.status(201).json(result.rows[0]); // 생성된 계정 정보 반환
    } catch (error) {
        console.error('Error registering account:', error.message); // 에러 메시지 로그
        res.status(500).json({ error: 'Database error', details: error.message }); // 에러 세부정보 반환
    }
});


// 로그인 API
app.post('/api/user_accounts/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM user_accounts WHERE username = $1', [username]);
        const account = result.rows[0];

        if (account && await bcrypt.compare(password, account.password)) {
            const token = jwt.sign({ user_id: account.user_id, role: account.role }, 'your_jwt_secret', { expiresIn: '1h' });
            res.json({ token });
        } else {
            res.status(401).json({ message: 'Invalid credentials' });
        }
    } catch (error) {
        console.error('Error logging in:', error.message); // 에러 메시지 로그
        res.status(500).json({ error: 'Database error', details: error.message }); // 에러 세부정보 반환
    }
});

// 데이터베이스 연결 테스트 API
app.get('/api/test-connection', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW()');
        res.json({ message: 'Database connection successful', time: result.rows[0].now });
    } catch (error) {
        console.error('Database connection error:', error.message); // 에러 메시지 로그
        res.status(500).json({ error: 'Database connection failed', details: error.message }); // 에러 세부정보 반환
    }
});

// 서버 시작
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});