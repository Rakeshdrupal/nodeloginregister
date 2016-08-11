var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var partials = require('express-partials');
var session = require('express-session');
var ejs = require('ejs');
var connectAssets = require('connect-assets');
var csrf = require('lusca').csrf();
var linkify = require("html-linkify");
var _ = require('lodash');
var  methodOverride = require('method-override');
var  MongoStore = require('connect-mongo/es5')({ session: session });
var mongoose = require('mongoose');
var passport = require('passport');
var flash = require('express-flash');
var  expressValidator = require('express-validator');
var  Site = require('./models/Site');
var app = express();

var hour = 3600000,
    day = hour * 24,
    week = day * 7;

var config = {
  app: require('./config/app'),
  secrets: require('./config/secrets')
};

/**
 * CSRF URL whitelist
 */
var csrfExclude = [];


/**
 * Connect to MongoDB
 */
mongoose.connect(config.secrets.db);
mongoose.connection.on('error', function() {
  console.error('MongoDB Connection Error. Make sure MongoDB is running.');
});

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.engine('ejs', ejs.__express);
partials.register('.ejs', ejs);

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(partials());
app.use(expressValidator());
app.use(methodOverride());
app.use(cookieParser());
app.use(session({
  resave: true,
  saveUninitialized: true,
  secret: config.secrets.sessionSecret,
  store: new MongoStore({
    url: config.secrets.db,
    auto_reconnect: true
  }),
  cookie: {
    maxAge: 4 * week
  }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(connectAssets({
  paths: [path.join(__dirname, 'public/css'), path.join(__dirname, 'public/js')],
  helperContext: app.locals,
  compress: false
}));
app.use(function(req, res, next) {
  // CSRF protection
  // Skip CSRF protection for white listed URLs
  if (_.contains(csrfExclude, req.path)) return next();
  // Skip CSRF protection for calls to the API (valid API Key required instead)
  if ((/^\/api/).test(req.path)) {
    res.locals._csrf = "undefined";
    return next();
  }
  csrf(req, res, next);
});
app.use(function(req, res, next) {
 //  res.locals.site = 'Rakesh';
  //Set default page title based on configured site name
   res.locals.title = Site.getName();

  // // Expose site config object to all templates
   res.locals.site = Site;

  // // Make user object available in all templates
   res.locals.user = req.user;

  // // Expose path to views
   res.locals.path = req.path;
   res.locals.url = Site.getUrl(req) + req.path;
  
  // // Expose linkify (to escape content while making hyperliks work) to all views
   res.locals.linkify = linkify;


  
  // Set req.api to true for requests made via the API
  if ((/^\/api/).test(req.path))
    req.api = true;
  
 next();
});
var routes = {
  auth: require('./routes/auth'),
  user: require('./routes/user'),
};
app.get('/', routes.user.getLogin);
app.get('/login', routes.user.getLogin);
app.post('/login', routes.user.postLogin);
app.get('/logout', routes.user.logout);
app.get('/reset-password', routes.user.getResetPassword);
app.post('/reset-password', routes.user.postResetPassword);
app.get('/change-password/:token', routes.user.getChangePassword);
app.post('/change-password/:token', routes.user.postChangePassword);
app.get('/signup', routes.user.getSignup);
app.post('/signup', routes.user.postSignup);

app.get('/profile', routes.auth.isAuthenticated, routes.user.getAccount);
app.get('/account', routes.auth.isAuthenticated, routes.user.getAccount);
app.get('/account/profile', routes.auth.isAuthenticated, routes.user.getAccount);
app.post('/account/profile', routes.auth.isAuthenticated, routes.user.postUpdateProfile);
app.get('/account/verify', routes.auth.isAuthenticated, routes.user.getAccountVerify);
app.post('/account/verify', routes.auth.isAuthenticated, routes.user.postAccountVerify);
app.get('/account/verify/:token', routes.auth.isAuthenticated, routes.user.getAccountVerifyToken);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  var err = new Error('Not Found');
  err.status = 404;
  next(err);
});

// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
  app.use(function(err, req, res, next) {
    res.status(err.status || 500);
    res.render('error', {
      message: err.message,
      error: err
    });
  });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res, next) {
  res.status(err.status || 500);
  res.render('error', {
    message: err.message,
    error: {}
  });
});


module.exports = app;
