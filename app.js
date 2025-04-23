import createError from 'http-errors';
import express from 'express';
import path from 'path';
import cookieSession from 'cookie-session';
import logger from 'morgan';
import { HMAC } from './utils/crypto';
import router from'./router';

const app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// adjust CORS policy (DO NOT CHANGE)
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "null");
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});

const HMAC_SECRET = 'your-secret-key-here';

// set lax cookie policies (DO NOT CHANGE)
app.use(cookieSession({
  name: 'session',
  maxAge: 24 * 60 * 60 * 1000, // 24 hours
  signed: true,
  sameSite: false,
  httpOnly: false,
  secret: HMAC_SECRET
}));

// initialize session if necessary
app.use((req, res, next) => {
  console.log('Request URL:', req.url);
  if(req.session.loggedIn == undefined) {
    req.session.loggedIn = false;
    req.session.account = {};
    req.session.token = {};
  }
  next();
});

app.use((req, res, next) => {
  /* verify the cookie signature */
  if (req.session && req.session._hmac) {
    const signature = HMAC(HMAC_SECRET, JSON.stringify(req.session.account));
    console.log('Received Session Signature:', signature);
    console.log('Stored Session Signature:', req.session._hmac);
    if (signature !== req.session._hmac) {
      /* invalid cookie destroy the session*/
      req.session = null;
      return res.status(403).send('Session tampering detected');
    }
  }

  next();
});

app.use(router);

app.use((req, res, next) => { /* update the signiture before sending the response */
  console.log('Updating session signature');
  if (req.session) {
    const signature = HMAC(HMAC_SECRET, JSON.stringify(req.session.account));
    console.log('Generated signature', signature);
    req.session._hmac = signature;
  }
  next();
});


// catch 404 and forward to error handler
app.use((req, res, next) => {
  next(createError(404));
});

// error handler
app.use((err, req, res, next) => {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('pages/error');
});

module.exports = app;
