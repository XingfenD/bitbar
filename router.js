import express from 'express';
import sqlite from 'sqlite';

import { asyncMiddleware } from './utils/asyncMiddleware';
import sleep from './utils/sleep';
import { generateRandomness, HMAC, KDF, checkPassword } from './utils/crypto';

const router = express.Router();
const dbPromise = sqlite.open('./db/database.sqlite')

function is_xss_safe(html) {
  const allowedTagsRegex = /^<b>|<\/b>|<u>|<\/u>|<i>|<\/i>|<h[1-6]>|<\/h[1-6]>|<p>|<\/p>$/;
  const tokens = html.match(/<[^>]+>|[^<]+/g);

  for (let token of tokens) {
      if (token.startsWith('<') && !allowedTagsRegex.test(token)) {
          return false;
      }
  }

  return true;
}

function generateToken(secretKey, validDuration = 600) {  /* the default valid duration is 10 mins */
  const randomness = generateRandomness();
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = `${randomness}.${timestamp}.${validDuration}`;
  const signature = HMAC(secretKey, payload);
  const token = `${payload}.${signature}`;
  return token;
}

function checkToken(req, token, secretKey) {
  const [payload, signature] = token.split(".");
  const [randomness, timestamp, validDuration] = payload.split(".");
  const currentTimestamp = Math.floor(Date.now() / 1000);

  if (currentTimestamp - parseInt(timestamp) > parseInt(validDuration)) {
    return false;
  }

  const expectedSignature = HMAC(secretKey, payload);
  if (signature !== expectedSignature) {
    return false;
  }

  if (req.session.token[secretKey] !== token) {
    return false;
  }

  return true;
}

function render(req, res, next, page, title, errorMsg = false, result = null, isSensitive = false) {
  let csrfToken = null;
  if (isSensitive) {
    csrfToken = generateToken(page);
    req.session.token[page] = csrfToken;
  }
  res.render(
    'layout/template', {
      page,
      title,
      loggedIn: req.session.loggedIn,
      account: req.session.account,
      errorMsg,
      result,
      csrfToken,
    }
  );
}


router.get('/', (req, res, next) => {
  render(req, res, next, 'index', 'Bitbar Home', false, null, true);
});


router.post('/set_profile', asyncMiddleware(async (req, res, next) => {
  req.session.account.profile = req.body.new_profile;
  const db = await dbPromise;
  console.log(!is_xss_safe(req.body.new_profile));
  if(!is_xss_safe(req.body.new_profile)) {
    console.log("XSS detected!");
    render(req, res, next, 'index', 'Bitbar Home', 'XSS detected!');
    return;
  }

  if (!checkToken(req, req.body.csrfToken, 'index')) {
    render(req, res, next, 'index', 'Bitbar Home', 'Invalid CSRF token or token has expired!', null, true);
    return;
  }
  console.log(req.body.new_profile);
  const query = `UPDATE Users SET profile = ? WHERE username = ?`;
  const result = await db.run(query, [req.body.new_profile, req.session.account.username]);
  render(req, res, next, 'index', 'Bitbar Home');

}));


router.get('/login', (req, res, next) => {
  render(req, res, next, 'login/form', 'Login');
});


router.get('/get_login', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  const query = `SELECT * FROM Users WHERE username = ?`;
  const result = await db.get(query, [req.query.username]);
  if(result) { // if this username actually exists
    if(checkPassword(req.query.password, result)) { // if password is valid
      await sleep(2000);
      req.session.loggedIn = true;
      req.session.account = result;
      render(req, res, next, 'login/success', 'Bitbar Home');
      return;
    }
  }
  render(req, res, next, 'login/form', 'Login', 'This username and password combination does not exist!');
}));


router.get('/register', (req, res, next) => {
  render(req, res, next, 'register/form', 'Register', false, null, true);
});


router.post('/post_register', asyncMiddleware(async (req, res, next) => {
  const db = await dbPromise;
  if (!is_xss_safe(req.body.username)) {
    render(req, res, next, 'register/form', 'Register', 'Unsafe username!');
    return;
  }

  if (!checkToken(req, req.body.csrfToken, 'Register')) {
    render(req, res, next, 'register/form', 'Register', 'Invalid CSRF token or token has expired!', null, true);
    return;
  }

  let query = `SELECT * FROM Users WHERE username = ?`;
  let result = await db.get(query, [req.body.username]);
  if(result) { // query returns results
    if(result.username === req.body.username) { // if username exists
      render(req, res, next, 'register/form', 'Register', 'This username already exists!');
      return;
    }
  }
  const salt = generateRandomness();
  const hashedPassword = KDF(req.body.password, salt);
  console.log(hashedPassword);
  console.log(salt);
  query = `INSERT INTO Users(username, hashedPassword, salt, profile, bitbars) VALUES(?, ?, ?, ?, ?)`;
  await db.run(query, [req.body.username, hashedPassword, salt, '', 100]);
  req.session.loggedIn = true;
  req.session.account = {
    username: req.body.username,
    hashedPassword,
    salt,
    profile: '',
    bitbars: 100,
  };
  render(req, res, next,'register/success', 'Bitbar Home');
}));


router.get('/close', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  const db = await dbPromise;
  // 修改为参数化查询
  const query = `DELETE FROM Users WHERE username = ?`;
  await db.run(query, [req.session.account.username]);
  req.session.loggedIn = false;
  req.session.account = {};
  render(req, res, next, 'index', 'Bitbar Home', 'Deleted account successfully!');
}));


router.get('/logout', (req, res, next) => {
  req.session.loggedIn = false;
  req.session.account = {};
  render(req, res, next, 'index', 'Bitbar Home', 'Logged out successfully!');
});


router.get('/profile', asyncMiddleware(async (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if (req.query.username == null) { // visitor did not make query, show them their own profile
    render(req, res, next, 'profile/view', 'View Profile', false, req.session.account);
    return;
  }

  if (!is_xss_safe(req.query.username)) {
    render(req, res, next, 'profile/view', 'View Profile', 'Unsafe username!', req.session.account);
    return;
  }

  const db = await dbPromise;
  // 修改为参数化查询
  const query = `SELECT * FROM Users WHERE username = ?`;
  let result;
  try {
    result = await db.get(query, [req.query.username]);
  } catch(err) {
    result = false;
  }
  if(result) { // if user exists
    render(req, res, next, 'profile/view', 'View Profile', false, result);
  }
  else { // user does not exist
    render(req, res, next, 'profile/view', 'View Profile', `${req.query.username} does not exist!`, req.session.account);
  }
}));


router.get('/transfer', (req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };
  render(req, res, next, 'transfer/form', 'Transfer Bitbars', false, {receiver:null, amount:null}, true);
});


router.post('/post_transfer', asyncMiddleware(async(req, res, next) => {
  if(req.session.loggedIn == false) {
    render(req, res, next, 'login/form', 'Login', 'You must be logged in to use this feature!');
    return;
  };

  if(req.body.destination_username === req.session.account.username) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'You cannot send money to yourself!', {receiver:null, amount:null}, true);
    return;
  }

  if(!is_xss_safe(req.body.destination_username)) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Unsafe username!', {receiver:null, amount:null}, true);
    return;
  }

  if(!checkToken(req, req.body.csrfToken, 'transfer/form')) {
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Invalid CSRF token or token has expired!', {receiver:null, amount:null}, true);
    return;
  }

  const db = await dbPromise;

  let query = `SELECT * FROM Users WHERE username = ?`;
  const receiver = await db.get(query, [req.body.destination_username]);
  if(receiver) { // if user exists
    const amount = parseInt(req.body.quantity);
    if(Number.isNaN(amount) || amount > req.session.account.bitbars || amount < 1) {
      render(req, res, next, 'transfer/form', 'Transfer Bitbars', 'Invalid transfer amount!', {receiver:null, amount:null}, true);
      return;
    }

    req.session.account.bitbars -= amount;

    query = `UPDATE Users SET bitbars = ? WHERE username = ?`;
    await db.run(query, [req.session.account.bitbars, req.session.account.username]);
    const receiverNewBal = receiver.bitbars + amount;

    query = `UPDATE Users SET bitbars = ? WHERE username = ?`;
    await db.run(query, [receiverNewBal, receiver.username]);
    render(req, res, next, 'transfer/success', 'Transfer Complete', false, {receiver, amount});
  } else { // user does not exist
    let q = req.body.destination_username;
    if (q == null) q = '';

    let oldQ;
    while (q !== oldQ) {
      oldQ = q;
      q = q.replace(/script|SCRIPT|img|IMG/g, '');
    }
    render(req, res, next, 'transfer/form', 'Transfer Bitbars', `User ${q} does not exist!`, {receiver:null, amount:null}, true);
  }
}));


router.get('/steal_cookie', (req, res, next) => {
  let stolenCookie = req.query.cookie;
  console.log('\n\n' + stolenCookie + '\n\n');
  render(req, res, next, 'theft/view_stolen_cookie', 'Cookie Stolen!', false, stolenCookie);
});

router.get('/steal_password', (req, res, next) => {
  let password = req.query.password;
  let timeElapsed = req.query.timeElapsed;
  console.log(`\n\nPassword: ${req.query.password}, time elapsed: ${req.query.timeElapsed}\n\n`);
  res.end();
});


module.exports = router;
