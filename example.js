// Modified index.js from cs361-group16-login-service
// for use with 2fa, and bloom filter in login.

//
// definitions
//

const db = require('./connect.js');
var express = require('express');
const session = require('express-session');
var exphbs = require('express-handlebars');

var app = express()
var port = process.env.PORT || 3001

//
// middleware
//
BLOOM_BASE_URL = 'http://localhost:4001'
TOTP_BASE_URL = 'http://localhost:5050'
app.engine('handlebars', exphbs.engine({
    defaultLayout: null
}))
app.set('view engine', 'handlebars')

// register custom handlebars helpers...
var hbs = exphbs.create({});
hbs.handlebars.registerHelper('ifDefined', function(conditional, options) {
    // returns true if given variable defined, false if not
    if (typeof conditional !== 'undefined') {
        return options.fn(this);
    }
    else {
        return options.inverse(this);
    }
});

app.use(express.static('static'))
app.use(session({
	secret: 'secret',
	resave: true,
	saveUninitialized: true,
    cookie: { }
}));
app.use(function (req, res, next) {
    res.locals.session = req.session;
    //user = req.session.user;
    console.info("Middleware session: "+req.session.username)

    // allow cross-origin access control
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "content-type");

    next();
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

//
// route service
//

// index
// NOTE: this route uses ASYNC syntax to allow it to wait
app.get('/', async (req, res) => {
    // debug 
    try {
        const [dbDebug] = await db.query("SHOW TABLES;");
        console.info(dbDebug);
    }
    catch (err) {
        console.error("Database connection failed");
    }

	if (req.session.loggedin) {
		// Output username
		console.info('Welcome back, ' + req.session.username + '!');
	} else {
		// Not logged in
		console.info('Please login to view this page!');
        //response.end();
	}
    const sessInfo = req.session
    res.render('index', {
        sessInfo
    })
})
app.get('/login', function (req, res) {
    // renders the index page with all posts, and thus all features
    console.log("SERVING LOGIN VIEW")
    res.render('login', {

    })
})

// services
// DATABASE RESET ROUTE
app.post('/reset-database', async function (req, res) {
    try {
        const resetQuery = `EXEC sp_create_lserveDB();`;
        const [queryResult] = await db.query(resetQuery);
        console.info('RESET the database \"lserve\"...');

        res.redirect('/');
    } catch (err) {
        console.error('Outer reset failure:', err.message);
        res.status(500).send('Database reset failed.');
    }
});
//auth:login
app.post('/auth', async (request, response) => {
  console.log("Authorizing...");

  const { username, password, totpCode } = request.body;
  console.log("Attempting login", username, password, totpCode);

  if (!username || !password) {
    return response.send({
      userInfo: 'undefined',
      userID: -1,
      message: "Please enter a username and password!"
    });
  }

  try {
    const [loginResult] = await db.query(
      'CALL lserve.sp_access_user(?, ?);',
      [username, password]
    );

    const [resultUser] = loginResult[0];

    if (typeof resultUser === 'undefined') {
      return response.send({
        userInfo: 'undefined',
        userID: -1,
        message: "Login failure!"
      });
    }

    console.info('[AUTH] DB user:', resultUser);

    const powerLevel = parseInt(resultUser.powerLevel, 10);
    const requiresTotp = powerLevel === 1;   // <-- only 1 requires 2FA

    if (requiresTotp) {
      if (!totpCode) {
        return response.send({
          userInfo: resultUser,
          userID: resultUser.userID,
          message: "TOTP code required for this account.",
          totpRequired: true
        });
      }

      try {
        const totpRes = await fetch(`${TOTP_BASE_URL}/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: totpCode })
        });

        const totpJson = await totpRes.json();
        console.log('[AUTH] TOTP verify response:', totpRes.status, totpJson);

        if (!totpRes.ok || !totpJson.ok) {
          return response.send({
            userInfo: resultUser,
            userID: resultUser.userID,
            message: "TOTP verification service error.",
            totpRequired: true
          });
        }

        if (!totpJson.valid) {
          return response.send({
            userInfo: resultUser,
            userID: resultUser.userID,
            message: "Invalid TOTP code.",
            totpRequired: true
          });
        }
      } catch (e) {
        console.error('[AUTH] Error calling TOTP service:', e);
        return response.send({
          userInfo: resultUser,
          userID: resultUser.userID,
          message: "TOTP service unavailable.",
          totpRequired: true
        });
      }
    }

    request.session.loggedin = true;
    request.session.username = resultUser.username;
    request.session.powerLevel = powerLevel;
    request.session.userID = resultUser.userID;

    return response.send({
      userInfo: resultUser,
      userID: resultUser.userID,
      message: "Login success!",
      totpRequired: requiresTotp
    });

  } catch (err) {
    console.error('[AUTH] Error:', err);
    return response.send({
      userInfo: 'undefined',
      userID: -1,
      message: "Server error during login."
    });
  }
});

//
//added create user and deleted user functionality to use bloom and 2fa
//
app.get('/register', async (req, res) => {
  res.render('register', {
    registerMode: true
  });
});

app.post('/register', async (req, res) => {
  const { username, password, enable2fa } = req.body;

  console.log('[REGISTER] Incoming:', username, password, enable2fa);

  if (!username || !password) {
    return res.render('register', {
      registerMode: true,
      error: 'Username and password are required.'
    });
  }

  const firstname = username;
  const powerLevel = enable2fa === 'yes' ? 1 : 0;

  try {
    try {
      const containsRes = await fetch(
        `${BLOOM_BASE_URL}/bloom/contains?key=${encodeURIComponent(username)}`
      );

      const containsJson = await containsRes.json();
      console.log('[REGISTER] Bloom /bloom/contains response:', containsRes.status, containsJson);

      if (containsRes.ok && containsJson.probablyExists) {
        return res.render('register', {
          registerMode: true,
          error: 'That username probably already exists (Bloom filter).'
        });
      }

    } catch (e) {
      console.error('[REGISTER] Error calling Bloom /bloom/contains:', e);
    }

    const [rows] = await db.query(
      'SELECT 1 FROM lserve.LS_Users WHERE `username` = ? LIMIT 1',
      [username]
    );
    console.log('[REGISTER] DB check rows:', rows);

    if (rows.length > 0) {
      return res.render('register', {
        registerMode: true,
        error: 'That username is already taken (DB).'
      });
    }

    const [insertResult] = await db.query(
      'INSERT INTO lserve.LS_Users (`username`, `firstname`, `password`, `powerLevel`) VALUES (?, ?, ?, ?)',
      [username, firstname, password, powerLevel]
    );
    console.log('[REGISTER] DB insert result:', insertResult);

    try {
      const addRes = await fetch(`${BLOOM_BASE_URL}/bloom/add`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: username })
      });

      const addJson = await addRes.json();
      console.log('[REGISTER] Bloom /bloom/add response:', addRes.status, addJson);

      if (!addRes.ok || !addJson.ok) {
        console.warn('[REGISTER] Bloom add failed, but DB registration succeeded.');
      }
    } catch (e) {
      console.error('[REGISTER] Error calling Bloom /bloom/add:', e);
    }

    return res.render('register', {
      registerMode: true,
      message: 'Account created! You can now log in.'
    });

  } catch (err) {
    console.error('[REGISTER] Error in /register:', err);
    return res.render('register', {
      registerMode: true,
      error: 'Server error while creating account.'
    });
  }
});


app.post('/delete-user', async (req, res) => {
  try {
    console.log('[DELETE-USER] req.body =', req.body);

    const { username } = req.body;

    if (!username) {
      return res.status(400).json({ ok: false, error: 'username is required' });
    }

    console.log('[DELETE-USER] Deleting user with username =', username);

    // Delete from DB by username
    const [result] = await db.query(
      'DELETE FROM lserve.LS_Users WHERE username = ?',
      [username]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ ok: false, error: 'User not found' });
    }

    // Tell Bloom service to delete username
    try {
      const bloomRes = await fetch(`${BLOOM_BASE_URL}/bloom/delete`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key: username })
      });

      const bloomJson = await bloomRes.json();
      console.log('[DELETE-USER] Bloom /bloom/delete response:', bloomRes.status, bloomJson);

      if (!bloomRes.ok || !bloomJson.ok) {
        console.warn('[DELETE-USER] Bloom deletion failed, but DB deletion succeeded.');
      }
    } catch (e) {
      console.error('[DELETE-USER] Error calling Bloom service:', e);
    }

    return res.json({ ok: true, message: 'User deleted from DB (and Bloom updated if possible).' });

  } catch (err) {
    console.error('[DELETE-USER] Error:', err);
    return res.status(500).json({ ok: false, error: 'Server error while deleting user' });
  }
});

app.listen(port, function () {
  console.log("== Server is listening on port", port);
});
