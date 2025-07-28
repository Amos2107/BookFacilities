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
  //host: 'localhost',
  //user: 'root',
  //password: 'Republic_C207',
  //database: 'c237_rentalfacilities'
  host: 'xluryu.h.filess.io',
  port: 61002,
  user: 'C237CA2_deskbroad',
  password: '54818715c15a7e3a31afd66aa17bcbd7d43e4250',
  database: 'C237CA2_deskbroad'
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL');
});

// ======= Middleware =======
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

// ---------- Auth Middleware ----------
function isLoggedIn(req, res, next) {
  if (!req.session.user_id) return res.redirect("/bookings");
  next();
}

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
  res.redirect('/');
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
  const { username, email, password, address, contact, dob_day, dob_month, dob_year, gender } = req.body;
  const dob = `${dob_year}-${dob_month.padStart(2, '0')}-${dob_day.padStart(2, '0')}`;
  const role = 'user';
  const sql = 'INSERT INTO users (username, email, password, address, contact, dob, gender, role) VALUES (?, ?, SHA1(?), ?, ?, ?, ?, ?)';
  db.query(sql, [username, email, password, address, contact, dob, gender, role], err => {
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
      res.redirect('/');
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
  db.query('SELECT user_id, username, email, dob, gender, role FROM users', (err, results) => {
    if (err) throw err;
    res.render('viewUsers', {
      users: results,
      search: '', // ✅ ADD THIS LINE
      messages: req.flash('success').concat(req.flash('error')) // make sure it's a flat array too
    });
  });
});

app.get('/admin/manage-users', checkAuthenticated, checkAdmin, (req, res) => {
  const search = req.query.search || '';

  const sql = `
    SELECT user_id, username, email, dob, gender, role 
    FROM users 
    WHERE username LIKE ? OR email LIKE ?
  `;

  const params = [`%${search}%`, `%${search}%`];

  db.query(sql, params, (err, results) => {
    if (err) throw err;

    res.render('viewUsers', {
      users: results,
      search,
      messages: req.flash('success').concat(req.flash('error')) // ✅ now it's a flat array
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
  const getUserQuery = 'SELECT role FROM users WHERE user_id = ?';
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
      const sql = 'UPDATE users SET role = ? WHERE user_id = ?';
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
  db.query('SELECT role FROM users WHERE user_id = ?', [userId], (err, results) => {
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
      db.query('DELETE FROM users WHERE user_id = ?', [userId], (err) => {
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

// ---------- CREATE BOOKING ----------
app.get("/bookings/create", isLoggedIn, (req, res) => {
  const getFacilities = "SELECT facilities_id, name FROM facilities";
  const getTimeSlots = "SELECT time_slot_id, date FROM time_slots";
  const getRates = `
    SELECT r.price, f.name AS facility_name, t.date AS time_slot
    FROM rates r
    JOIN facilities f ON r.facilities_id = f.facilities_id
    JOIN time_slots t ON r.time_slot_id = t.time_slot_id
    ORDER BY f.name, t.date
  `;

  db.query(getFacilities, (err, facilities) => {
    if (err) return res.status(500).send("Error fetching facilities");
    db.query(getTimeSlots, (err, timeslots) => {
      if (err) return res.status(500).send("Error fetching timeslots");
      db.query(getRates, (err, rates) => {
        if (err) return res.status(500).send("Error fetching rates");

        res.render("createBooking", { facilities, timeslots, rates });
      });
    });
  });
});

app.post("/bookings/create", isLoggedIn, (req, res) => {
  const { facilities_id, time_slot_id, booking_date } = req.body;
  const user_id = req.session.user_id;

  const checkSql = `
    SELECT COUNT(*) AS count FROM bookings
    WHERE facilities_id = ? AND time_slot_id = ? AND booking_date = ?
  `;

  db.query(checkSql, [facilities_id, time_slot_id, booking_date], (err, results) => {
    if (err) return res.status(500).send("DB error");

    if (results[0].count > 0) {
      return res.send("Slot already booked.");
    }

    const insertSql =
      "INSERT INTO bookings (user_id, facilities_id, time_slot_id, booking_date) VALUES (?, ?, ?, ?)";
    db.query(insertSql, [user_id, facilities_id, time_slot_id, booking_date], err => {
      if (err) return res.status(500).send("DB insert error");
      res.redirect("/bookings");
    });
  });
});

// ---------- VIEW BOOKINGS ----------
app.get("/bookings", isLoggedIn, (req, res) => {
  let sql;
  let params = [];

  if (req.session.role === "admin") {
    sql = `
      SELECT b.booking_id, u.username, f.name AS facility_name, t.date AS time_slot, b.booking_date
      FROM bookings b
      JOIN users u ON b.user_id = u.user_id
      JOIN facilities f ON b.facilities_id = f.facilities_id
      JOIN time_slots t ON b.time_slot_id = t.time_slot_id
      ORDER BY b.booking_date DESC
    `;
  } else {
    sql = `
      SELECT b.booking_id, f.name AS facility_name, t.date AS time_slot, b.booking_date
      FROM bookings b
      JOIN facilities f ON b.facilities_id = f.facilities_id
      JOIN time_slots t ON b.time_slot_id = t.time_slot_id
      WHERE b.user_id = ?
      ORDER BY b.booking_date DESC
    `;
    params = [req.session.user_id];
  }

  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).send("DB error");
    res.render("viewBookings", { bookings: results, role: req.session.role });
  });
});

// ---------- EDIT BOOKING ----------
app.get("/bookings/edit/:booking_id", isLoggedIn, (req, res) => {
  const bookingId = req.params.booking_id;

  const sql = "SELECT * FROM bookings WHERE booking_id = ?";
  db.query(sql, [bookingId], (err, results) => {
    if (err) return res.status(500).send("DB error");
    if (results.length === 0) return res.status(404).send("Not found");

    const booking = results[0];

    if (req.session.role !== "admin" && booking.user_id !== req.session.user_id) {
      return res.status(403).send("Not allowed");
    }

    res.render("editBooking", { booking });
  });
});

app.post("/bookings/edit/:booking_id", isLoggedIn, (req, res) => {
  const bookingId = req.params.booking_id;
  const { facilities_id, time_slot_id, booking_date } = req.body;

  let sql, params;
  if (req.session.role === "admin") {
    sql = `
      UPDATE bookings SET facilities_id=?, time_slot_id=?, booking_date=?
      WHERE booking_id=?
    `;
    params = [facilities_id, time_slot_id, booking_date, bookingId];
  } else {
    sql = `
      UPDATE bookings SET facilities_id=?, time_slot_id=?, booking_date=?
      WHERE booking_id=? AND user_id=?
    `;
    params = [facilities_id, time_slot_id, booking_date,
bookingId, req.session.user_id];
  }

  db.query(sql, params, (err, result) => {
    if (err) return res.status(500).send("DB error");
    if (result.affectedRows === 0) return res.status(403).send("Not allowed");
    res.redirect("/bookings");
  });
});

// ---------- DELETE BOOKING ----------
app.post("/bookings/delete/:booking_id", isLoggedIn, (req, res) => {
  const bookingId = req.params.booking_id;

  if (req.session.role === "admin") {
    db.query("DELETE FROM bookings WHERE booking_id = ?", [bookingId], err => {
      if (err) return res.status(500).send("DB error");
      res.redirect("/bookings");
    });
  } else {
    db.query(
      "DELETE FROM bookings WHERE booking_id = ? AND user_id = ?",
      [bookingId, req.session.user_id],
      (err, result) => {
        if (err) return res.status(500).send("DB error");
        if (result.affectedRows === 0) return res.status(403).send("Not allowed");
        res.redirect("/bookings");
      }
    );
  }
});

// ======================
// TIME SLOT ROUTES
// ======================
 
// View all time slots
app.get('/timeslots', checkAuthenticated, (req, res) => {
    const query = `
        SELECT ts.*, f.name AS facility_name
        FROM time_slots ts
        JOIN facilities f ON ts.facilities_id  = f.facilities_id
        ORDER BY ts.date, ts.start_time
    `;
   
    db.query(query, (error, results) => {
        if (error) {
            console.error('Error fetching time slots:', error);
            req.flash('error', 'Failed to load time slots');
            return res.redirect('/');
        }
       
        // Convert is_available from TINYINT to boolean for easier handling
        const timeSlots = results.map(slot => ({
            ...slot,
            is_available: slot.is_available === 1
        }));
       
        res.render('list', {
            timeSlots,
            user: req.session.user,
            messages: req.flash()
        });
    });
});
 
// View available slots for a specific date
app.get('/timeslots/available', checkAuthenticated, (req, res) => {
    const { date, facility_id } = req.query;
   
    let query = `
        SELECT ts.*, f.name
        FROM time_slots ts
        JOIN facilities f ON ts.facilities_id  = f.facilities_id
        WHERE ts.is_available = 1
    `;
   
    const params = [];
   
    if (date) {
        query += ' AND ts.date = ?';
        params.push(date);
    }
   
    if (facility_id) {
        query += ' AND ts.facility_id = ?';
        params.push(facility_id);
    }
   
    query += ' ORDER BY ts.start_time';
   
    db.query(query, params, (error, results) => {
        if (error) {
            console.error('Error fetching available slots:', error);
            req.flash('error', 'Failed to load available slots');
            return res.redirect('/timeslots');
        }
       
        // Get facilities for dropdown
        db.query('SELECT * FROM facilities', (err, facilities) => {
            if (err) {
                console.error('Error fetching facilities:', err);
                facilities = [];
            }
           
            res.render('available', {
                availableSlots: results,
                facilities,
                selectedDate: date,
                selectedFacility: facility_id,
                user: req.session.user,
                messages: req.flash()
            });
        });
    });
});
 
// Add new time slot (admin only)
app.get('/timeslots/add', checkAuthenticated, checkAdmin, (req, res) => {
    db.query('SELECT * FROM facilities', (error, facilities) => {
        if (error) {
            console.error('Error fetching facilities:', error);
            facilities = [];
        }
       
        res.render('add', {
            facilities,
            user: req.session.user,
            messages: req.flash()
        });
    });
});
 
app.post('/timeslots/add', checkAuthenticated, checkAdmin, (req, res) => {
    const { date, start_time, end_time, facilities_id } = req.body;
    const is_available = req.body.is_available ? 1 : 0;
   
    // Basic validation
    if (!date || !start_time || !end_time || !facilities_id) {
        req.flash('error', 'All fields are required');
        return res.redirect('/timeslots/add');
    }
   
    if (start_time >= end_time) {
        req.flash('error', 'End time must be after start time');
        return res.redirect('/timeslots/add');
    }
   
    const query = `
        INSERT INTO time_slots
        (date, start_time, end_time, is_available, facilities_id)
        VALUES (?, ?, ?, ?, ?)
    `;
   
    db.query(query, [date, start_time, end_time, is_available, facilities_id],
    (error, results) => {
        if (error) {
            console.error('Error adding time slot:', error);
            req.flash('error', 'Failed to add time slot');
            return res.redirect('/timeslots/add');
        }
       
        req.flash('success', 'Time slot added successfully');
        res.redirect('/timeslots');
    });
});
 
// Edit time slot (admin only)
app.get('/timeslots/edit/:id', checkAuthenticated, checkAdmin, (req, res) => {
    const slotId = req.params.id;
   
    db.query('SELECT * FROM facilities', (error, facilities) => {
        if (error) {
            console.error('Error fetching facilities:', error);
            facilities = [];
        }
       
        db.query('SELECT * FROM time_slots WHERE time_slot_id = ?', [slotId],
        (err, results) => {
            if (err || results.length === 0) {
                req.flash('error', 'Time slot not found');
                return res.redirect('/timeslots');
            }
           
            const timeSlot = results[0];
            timeSlot.is_available = timeSlot.is_available === 1;
           
            res.render('edit', {
                timeSlot,
                facilities,
                user: req.session.user,
                messages: req.flash()
            });
        });
    });
});
 
app.post('/timeslots/edit/:id', checkAuthenticated, checkAdmin, (req, res) => {
    const slotId = req.params.id;
    const { date, start_time, end_time, facilities_id } = req.body;
    const is_available = req.body.is_available ? 1 : 0;
   
    // Basic validation
    if (!date || !start_time || !end_time || !facilities_id) {
        req.flash('error', 'All fields are required');
        return res.redirect(`/timeslots/edit/${slotId}`);
    }
   
    if (start_time >= end_time) {
        req.flash('error', 'End time must be after start time');
        return res.redirect(`/timeslots/edit/${slotId}`);
    }
   
    const query = `
        UPDATE time_slots
        SET date = ?, start_time = ?, end_time = ?, is_available = ?, facilities_id = ?
        WHERE time_slot_id = ?
    `;
   
    db.query(query, [date, start_time, end_time, is_available, facilities_id, slotId],
    (error, results) => {
        if (error) {
            console.error('Error updating time slot:', error);
            req.flash('error', 'Failed to update time slot');
            return res.redirect(`/timeslots/edit/${slotId}`);
        }
       
        req.flash('success', 'Time slot updated successfully');
        res.redirect('/timeslots');
    });
});
 
// Delete time slot (admin only)
app.get('/timeslots/delete/:id', checkAuthenticated, checkAdmin, (req, res) => {
    const slotId = req.params.id;
   
    db.query('DELETE FROM time_slots WHERE time_slot_id = ?', [slotId],
    (error, results) => {
        if (error) {
            console.error('Error deleting time slot:', error);
            req.flash('error', 'Failed to delete time slot');
        } else {
            req.flash('success', 'Time slot deleted successfully');
        }
       
        res.redirect('/timeslots');
    });
});

app.get('/rates', async (req, res) => {
  try {
    const [rates] = await db.query('SELECT * FROM RatePeriod');
    rates.forEach(rate => {
      rate.rate_amount = Number(rate.rate_amount);
    });
    res.render('rates', { rates });
  } catch (err) {
    res.status(500).send('Database error: ' + err.message);
  }
});

// GET route - renders the update form

app.get('/update/:day_type', async (req, res) => {
  try {
    const day_type = req.params.day_type;
    const [rows] = await db.query('SELECT * FROM RatePeriod WHERE day_type = ?', [day_type]);
    if (rows.length === 0) return res.status(404).send('Rate not found');
    const rate = rows[0];
    res.render('updaterates', { rate });
  } catch (err) {
    res.status(500).send('Database error: ' + err.message);
  }
});

// Handle form submission for ALL rate types
app.post('/update/:period_type', async (req, res) => {
  const { rate_period_id, time_start, time_end, rate_amount } = req.body;

  try {
    await db.query(
      'UPDATE RatePeriod SET time_start = ?, time_end = ?, rate_amount = ? WHERE rate_period_id = ?',
      [time_start, time_end, parseFloat(rate_amount), rate_period_id]
    );
    res.redirect('/rates?success=true'); // Redirect with success flag
  } catch (err) {
    console.error("Update error:", err);
    res.status(500).send("Failed to update. Check server logs.");
  }
});

// View-only route for users
app.get('/viewrates', async (req, res) => {
  try {
    const [rates] = await db.query('SELECT * FROM RatePeriod');
    // Convert rate_amount to numbers
    rates.forEach(rate => {
      rate.rate_amount = Number(rate.rate_amount);
    });
    res.render('viewrates', { rates });
  } catch (err) {
    res.status(500).send('Database error: ' + err.message);
  }
});

// ======= Start Server =======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
