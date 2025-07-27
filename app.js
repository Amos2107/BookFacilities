const express = require('express');
const mysql = require('mysql2');
const multer = require('multer');
const session = require('express-session');
const flash = require('connect-flash');
const app = express();

// ======= Multer Setup =======
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/images'),
  filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

// ======= MySQL Setup =======
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Republic_C207',
  database: 'c237_rentalfacilities'
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL');
});

// ======= Middleware =======
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

app.use(session({
  secret: 'secret',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } // 1 week
}));
app.use(flash());

// ======= Auth Middleware =======
const checkAuthenticated = (req, res, next) => {
  if (req.session.user) return next();
  req.flash('error', 'Please log in to view this resource');
  res.redirect('/login');
};

const checkAdmin = (req, res, next) => {
  if (req.session.user?.role === 'admin') return next();
  req.flash('error', 'Access denied');
  res.redirect('/dashboard');
};

// ======= Auth Routes =======
app.get('/', (req, res) => {
  const sql = 'SELECT * FROM facilities';
  db.query(sql, (err, results) => {
    if (err) return res.status(500).send('Error retrieving facilities');
    res.render('index', { facilities: results, user: req.session.user, messages: req.flash('success') });
  });
});

app.get('/register', (req, res) => {
  res.render('register', {
    messages: req.flash('error'),
    formData: req.flash('formData')[0]
  });
});

const validateRegistration = (req, res, next) => {
  const { username, email, password, address, contact } = req.body;
  if (!username || !email || !password || !address || !contact) return res.status(400).send('All fields required');
  if (password.length < 6) {
    req.flash('error', 'Password must be 6+ characters');
    req.flash('formData', req.body);
    return res.redirect('/register');
  }
  next();
};

app.post('/register', validateRegistration, (req, res) => {
  const { username, email, password, address, contact } = req.body;
  const role = 'user';
  const sql = 'INSERT INTO users (username, email, password, address, contact, role) VALUES (?, ?, SHA1(?), ?, ?, ?)';
  db.query(sql, [username, email, password, address, contact, role], err => {
    if (err) throw err;
    req.flash('success', 'Registration successful! Please log in.');
    res.redirect('/login');
  });
});

app.get('/login', (req, res) => {
  res.render('login', {
    messages: req.flash('success'),
    errors: req.flash('error')
  });
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    req.flash('error', 'All fields required');
    return res.redirect('/login');
  }

  const sql = 'SELECT * FROM users WHERE email = ? AND password = SHA1(?)';
  db.query(sql, [email, password], (err, results) => {
    if (err) throw err;
    if (results.length > 0) {
      req.session.user = results[0];
      req.flash('success', 'Login successful');
      res.redirect('/dashboard');
    } else {
      req.flash('error', 'Invalid email or password');
      res.redirect('/login');
    }
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/dashboard', checkAuthenticated, (req, res) => {
  res.render('dashboard', { user: req.session.user });
});

app.get('/admin', checkAuthenticated, checkAdmin, (req, res) => {
  res.render('admin', { user: req.session.user });
});

// ======= Facility Routes =======

// View individual facility
app.get('/facilities/:id', (req, res) => {
  const sql = 'SELECT * FROM facilities WHERE facilities_id = ?';
  db.query(sql, [req.params.id], (err, results) => {
    if (err) return res.status(500).send('Error retrieving facility');
    if (results.length > 0) {
      res.render('facilities', { facilities: results[0], user: req.session.user });
    } else {
      res.status(404).send('Facility not found');
    }
  });
});

// Add Facility (Admin only)
app.get('/addFacilities', checkAuthenticated, checkAdmin, (req, res) => {
  res.render('addFacilities', { user: req.session.user });
});

app.post('/addFacilities', checkAuthenticated, checkAdmin, upload.single('image'), (req, res) => {
  const { name, description, location, capacity, facilities_group } = req.body;
  const image = req.file ? req.file.filename : null;
  const sql = 'INSERT INTO facilities (name, description, location, capacity, image, facilities_group) VALUES (?, ?, ?, ?, ?, ?)';
  db.query(sql, [name, description, location, capacity, image, facilities_group], err => {
    if (err) return res.status(500).send('Error adding facility');
    res.redirect('/');
  });
});

// Edit Facility (Admin only)
app.get('/editFacilities/:id', checkAuthenticated, checkAdmin, (req, res) => {
  const sql = 'SELECT * FROM facilities WHERE facilities_id = ?';
  db.query(sql, [req.params.id], (err, results) => {
    if (err) return res.status(500).send('Error retrieving facility');
    if (results.length > 0) {
      res.render('editFacilities', { facilities: results[0], user: req.session.user });
    } else {
      res.status(404).send('Facility not found');
    }
  });
});

app.post('/editFacilities/:id', checkAuthenticated, checkAdmin, upload.single('image'), (req, res) => {
  const { name, description, location, capacity, facilities_group, currentImage } = req.body;
  const image = req.file ? req.file.filename : currentImage;
  const sql = 'UPDATE facilities SET name=?, description=?, location=?, capacity=?, image=?, facilities_group=? WHERE facilities_id=?';
  db.query(sql, [name, description, location, capacity, image, facilities_group, req.params.id], err => {
    if (err) return res.status(500).send('Error updating facility');
    res.redirect('/');
  });
});

app.get('/filter', (req, res) => {
  const { group, keyword } = req.query;

  let sql = 'SELECT * FROM facilities WHERE 1=1';
  const params = [];

  if (group && group !== '') {
    sql += ' AND facilities_group = ?';
    params.push(group);
  }

  if (keyword && keyword.trim() !== '') {
    sql += ' AND name LIKE ?';
    params.push(`%${keyword}%`);
  }

  db.query(sql, params, (error, results) => {
    if (error) {
      console.error('Error filtering facilities:', error);
      return res.status(500).send('Server Error');
    }

    res.render('index', {
      facilities: results,
      user: req.session.user,
      messages: req.flash('success') // Optional: for flash message support
    });
  });
});

app.get('/admin/users', checkAuthenticated, checkAdmin, (req, res) => {
  db.query('SELECT id, username, email, role FROM users', (err, results) => {
    if (err) throw err;
    res.render('viewUsers', {
      users: results,
      messages: {
        success: req.flash('success'),
        error: req.flash('error')
      }
    });
  });
});

app.post('/admin/update-role/:id', checkAuthenticated, checkAdmin, (req, res) => {
  const userId = req.params.id;
  const newRole = req.body.role;

  if (!['user', 'admin'].includes(newRole)) {
    req.flash('error', 'Invalid role selected');
    return res.redirect('/admin/users');
  }

  // Get the current role of the user
  const getUserQuery = 'SELECT role FROM users WHERE id = ?';
  db.query(getUserQuery, [userId], (err, results) => {
    if (err) throw err;

    const currentRole = results[0]?.role;

    // If trying to demote the last admin
    if (currentRole === 'admin' && newRole === 'user') {
      db.query('SELECT COUNT(*) AS adminCount FROM users WHERE role = "admin"', (err, results) => {
        if (err) throw err;

        const adminCount = results[0].adminCount;

        if (adminCount <= 1) {
          req.flash('error', 'You cannot demote the last admin!');
          return res.redirect('/admin/users');
        }

        // Proceed with demotion
        updateUserRole();
      });
    } else {
      updateUserRole(); // No risk, just update
    }

    function updateUserRole() {
      const sql = 'UPDATE users SET role = ? WHERE id = ?';
      db.query(sql, [newRole, userId], (err) => {
        if (err) throw err;
        req.flash('success', 'User role updated successfully');
        res.redirect('/admin/users');
      });
    }
  });
});

app.post('/admin/delete-user/:id', checkAuthenticated, checkAdmin, (req, res) => {
  const userId = req.params.id;

  // Get user to delete
  db.query('SELECT role FROM users WHERE id = ?', [userId], (err, results) => {
    if (err) throw err;

    const userToDelete = results[0];

    if (!userToDelete) {
      req.flash('error', 'User not found');
      return res.redirect('/admin/users');
    }

    // If deleting an admin, check if it's the last one
    if (userToDelete.role === 'admin') {
      db.query('SELECT COUNT(*) AS adminCount FROM users WHERE role = "admin"', (err, results) => {
        if (err) throw err;

        const adminCount = results[0].adminCount;

        if (adminCount <= 1) {
          req.flash('error', 'Cannot delete the last admin!');
          return res.redirect('/admin/users');
        }

        deleteUser(); // Safe to delete
      });
    } else {
      deleteUser();
    }

    function deleteUser() {
      db.query('DELETE FROM users WHERE id = ?', [userId], (err) => {
        if (err) throw err;
        req.flash('success', 'User deleted successfully');
        res.redirect('/admin/users');
      });
    }
  });
});

// Delete Facility (Admin only)
app.get('/deleteFacilities/:id', checkAuthenticated, checkAdmin, (req, res) => {
  const sql = 'DELETE FROM facilities WHERE facilities_id = ?';
  db.query(sql, [req.params.id], err => {
    if (err) return res.status(500).send('Error deleting facility');
    res.redirect('/');
  });
});

// ======= Start Server =======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
