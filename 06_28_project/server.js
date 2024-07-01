const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const sha256 = require('sha256');
const mysql = require('mysql2');
const crypto = require('crypto');

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({
  secret: '아무거나 넣으시오',
  resave: false,
  saveUninitialized: true
}));

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '1234',
  database: 'assetdb'
});

db.connect((err) => {
  if (err) throw err;
  console.log('DB 연결 완료');
});

app.set('view engine', 'ejs');
app.use(express.static('public'));

app.listen(8080, () => {
  console.log('8080 서버 대기중');
});

// index 페이지 라우트
app.get('/', (req, res) => {
  res.render('index', { user: req.session.user });
});

// 로그아웃 기능 버튼 클릭시 -> session id 없앰
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.clearCookie('uid');
  res.redirect('/');
});

// 회원가입 페이지 라우트
app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  const { username, password, name } = req.body;
  
  // 사용자가 존재하는지 확인
  const checkUserQuery = 'SELECT * FROM user WHERE username = ?';
  db.query(checkUserQuery, [username], (err, results) => {
    if (err) throw err;

    if (results.length > 0) {
      // 이미 사용자가 존재하면 에러 메시지
      res.render('register', { data: { msg: 'ID가 중복되었습니다.' } });
    } else {
      // 새 사용자를 추가
      const generateSalt = (length = 16) => {
        const crypto = require('crypto');
        return crypto.randomBytes(length).toString("hex");
      };

      const salt = generateSalt();
      const hashedPassword = sha256(password + salt);
      const role = 'guest'; // 기본 값은 guest로 설정

      const insertUserQuery = 'INSERT INTO user (username, password, name, role) VALUES (?, ?, ?, ?)';
      db.query(insertUserQuery, [username, hashedPassword, name, role], (err, result) => {
        if (err) throw err;

        if (result) {
          console.log("회원가입 성공");

          const insertSaltQuery = 'INSERT INTO usersalt (userid, salt) VALUES (?, ?)';
          db.query(insertSaltQuery, [result.insertId, salt], (err, rows, fields) => {
            if (err) throw err;

            console.log("salt 저장 성공");
            res.redirect('/login');
          });
        } else {
          console.log("회원가입 실패");
          res.render('register', { data: { msg: '회원가입 실패' } });
        }
      });
    }
  });
});

app.get('/login', (req, res) => {
  res.render('login');
});

// 로그인 처리 라우트
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM user WHERE username = ?';

  db.query(query, [username], (err, results) => {
    if (err) throw err;

    if (results.length > 0) {
      const user = results[0];

      if (user.account_locked) {
        return res.send('로그인 시도 잠금 중입니다. 관리자에게 문의하세요.');
      }

      const saltQuery = 'SELECT salt FROM usersalt WHERE userid = ?';
      db.query(saltQuery, [user.id], (err, rows) => {
        if (err) throw err;

        const salt = rows[0].salt;
        const hashedPassword = sha256(password + salt);

        if (user.password === hashedPassword) {
          // 로그인 성공
          const resetAttemptsQuery = 'UPDATE user SET login_attempts = 0 WHERE id = ?';
          db.query(resetAttemptsQuery, [user.id], (err) => {
            if (err) throw err;

            req.session.user = user;
            res.cookie('uid', username);
            res.redirect('/');
          });
        } else {
          // 로그인 실패
          const loginAttempts = user.login_attempts + 1;
          let accountLocked = false;

          if (loginAttempts >= 5) {
            accountLocked = true;
          }

          const updateAttemptsQuery = 'UPDATE user SET login_attempts = ?, account_locked = ? WHERE id = ?';
          db.query(updateAttemptsQuery, [loginAttempts, accountLocked, user.id], (err) => {
            if (err) throw err;
            res.render('login', { msg: 'Invalid username or password. Please try again.' });
          });
        }
      });
    } else {
      res.render('login', { msg: 'Invalid username or password. Please try again.' });
    }
  });
});

// 관리자 페이지 라우트
app.get('/admin', (req, res) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.redirect('/');
  }

  const userQuery = 'SELECT * FROM user';
  const requestQuery = 'SELECT requests.*, user.username FROM requests JOIN user ON requests.user_id = user.id';
  
  db.query(userQuery, (err, users) => {
    if (err) throw err;
    
    db.query(requestQuery, (err, requests) => {
      if (err) throw err;
      res.render('admin', { users: users, requests: requests });
    });
  });
});

app.post('/admin/unlock', (req, res) => {
  const userId = req.body.user_id;

  const query = 'UPDATE user SET login_attempts = 0, account_locked = FALSE WHERE id = ?';
  db.query(query, [userId], (err, results) => {
    if (err) throw err;
    res.send({ message: '사용자 계정이 잠금 해제되었습니다.' });
  });
});

app.post('/admin/approve', (req, res) => {
  const requestId = req.body.request_id;

  const getRequestQuery = 'SELECT * FROM requests WHERE id = ?';
  db.query(getRequestQuery, [requestId], (err, results) => {
    if (err) throw err;

    const request = results[0];

    if (request.type === 'edit' || request.type === 'delete' || request.type === 'add') {
      const updateRequestQuery = 'UPDATE requests SET status = "approved" WHERE id = ?';
      db.query(updateRequestQuery, [requestId], (err) => {
        if (err) throw err;
        res.send({ message: '요청이 승인되었습니다.' });
      });
    }
  });
});

app.post('/admin/reject', (req, res) => {
  const requestId = req.body.request_id;

  const updateRequestQuery = 'UPDATE requests SET status = "rejected" WHERE id = ?';
  db.query(updateRequestQuery, [requestId], (err) => {
    if (err) throw err;
    res.send({ message: '요청이 거절되었습니다.' });
  });
});

// 자산관리 페이지 라우트
app.get('/assets', (req, res) => {
  const query = 'SELECT * FROM assets WHERE user_id = ?';
  db.query(query, [req.session.user.id], (err, results) => {
    if (err) throw err;
    res.render('list.ejs', { data: results });
  });
});

// 요청 저장을 위한 데이터베이스 테이블 생성
const createRequestsTableQuery = `
CREATE TABLE IF NOT EXISTS requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    asset_id INT,
    type VARCHAR(50),
    reason TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    name VARCHAR(255),
    asset_type VARCHAR(50),
    value VARCHAR(50),
    risk VARCHAR(11),
    returned VARCHAR(10),
    date DATE,
    FOREIGN KEY (user_id) REFERENCES user(id),
    FOREIGN KEY (asset_id) REFERENCES assets(id)
);
`;

db.query(createRequestsTableQuery, (err) => {
  if (err) throw err;
  console.log('Requests table created or exists already');
});

// 수정 요청 처리
app.post('/request-edit', (req, res) => {
  const { assetId, reason } = req.body;
  const userId = req.session.user.id;

  const query = 'INSERT INTO requests (user_id, asset_id, type, reason) VALUES (?, ?, "edit", ?)';
  db.query(query, [userId, assetId, reason], (err, results) => {
    if (err) throw err;
    res.send({ message: '수정 요청이 전송되었습니다.' });
  });
});

// 삭제 요청 처리
app.post('/request-delete', (req, res) => {
  const { assetId, reason } = req.body;
  const userId = req.session.user.id;

  const query = 'INSERT INTO requests (user_id, asset_id, type, reason) VALUES (?, ?, "delete", ?)';
  db.query(query, [userId, assetId, reason], (err, results) => {
    if (err) throw err;
    res.send({ message: '삭제 요청이 전송되었습니다.' });
  });
});

// 추가 요청 처리
app.post('/request-add', (req, res) => {
  const { name, asset_type, value, risk, returned, date, reason } = req.body;
  const userId = req.session.user.id;

  const query = `
    INSERT INTO requests (user_id, type, reason, name, asset_type, value, risk, returned, date)
    VALUES (?, "add", ?, ?, ?, ?, ?, ?, ?)
  `;
  db.query(query, [userId, reason, name, asset_type, value, risk, returned, date], (err, results) => {
    if (err) throw err;
    res.send({ message: '추가 요청이 전송되었습니다.' });
  });
});

// 사용자가 승인된 요청을 확인하고 처리하는 페이지 라우트
app.get('/pending-requests', (req, res) => {
  const userId = req.session.user.id;

  const query = `
    SELECT * FROM requests
    WHERE user_id = ? AND status = 'approved'
  `;
  db.query(query, [userId], (err, results) => {
    if (err) throw err;

    const assetIds = results.map(r => r.asset_id).filter(id => id !== null);
    if (assetIds.length > 0) {
      const getAssetsQuery = `
        SELECT * FROM assets WHERE id IN (?)
      `;
      db.query(getAssetsQuery, [assetIds], (err, assets) => {
        if (err) throw err;

        const assetsMap = {};
        assets.forEach(asset => {
          assetsMap[asset.id] = asset;
        });

        res.render('pending_requests', { requests: results, assetsMap });
      });
    } else {
      res.render('pending_requests', { requests: results, assetsMap: {} });
    }
  });
});

// 승인된 자산 수정 처리
app.post('/process-edit', (req, res) => {
  const { assetId, name, asset_type, value, risk, returned, date } = req.body;
  const query = `
    UPDATE assets 
    SET name = ?, type = ?, value = ?, risk = ?, returned = ?, date = ?
    WHERE id = ?
  `;
  db.query(query, [name, asset_type, value, risk, returned, date, assetId], (err) => {
    if (err) throw err;
    res.send({ message: '자산 수정이 완료되었습니다.' });
  });
});

// 승인된 자산 삭제 처리
app.post('/process-delete', (req, res) => {
  const { assetId } = req.body;
  const query = 'DELETE FROM assets WHERE id = ?';
  db.query(query, [assetId], (err) => {
    if (err) throw err;
    res.send({ message: '자산 삭제가 완료되었습니다.' });
  });
});

// 승인된 자산 추가 처리
app.post('/process-add', (req, res) => {
  const { name, asset_type, value, risk, returned, date } = req.body;
  const userId = req.session.user.id;
  const query = `
    INSERT INTO assets (user_id, name, type, value, risk, returned, date)
    VALUES (?, ?, ?, ?, ?, ?, ?)  
  `;
  db.query(query, [userId, name, asset_type, value, risk, returned, date], (err) => {
    if (err) throw err;
    res.send({ message: '자산 추가가 완료되었습니다.' });
  });
});
