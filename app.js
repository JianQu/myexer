var express = require('express');
var path = require('path');
var favicon = require('serve-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session')
var mongoose = require('mongoose');
var nodemailer = require('nodemailer');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var bcrypt = require('bcrypt-nodejs');
var async = require('async');
var crypto = require('crypto');
var flash = require('express-flash');
var mg = require('nodemailer-mailgun-transport');
var expressValidator = require('express-validator'); 

var routes = require('./routes/index');
var users = require('./routes/users');

var app = express();
var usernm = '';

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// uncomment after placing your favicon in /public
//app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(expressValidator()); 
app.use(cookieParser());
app.set('trust proxy', 1) // trust first proxy
app.use(session({
	secret: 'keyboard cat',
	resave: false,
	saveUninitialized: true,
	cookie: { secure: false }
}))

 // Remember Me middleware
app.use( function (req, res, next) {
	if ( req.method == 'POST' && req.url == '/login' ) {
	console.log('checking remember: ' + req.body.rememberme);
	if ( req.body.rememberme ) {
		req.session.cookie.maxAge = 2592000000; // 2592000000 3*24*60*60*1000 Rememeber 'me' for 3 days
	} else {
		req.session.cookie.expires = false;
	}
	}
	next();
});

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', routes);
app.use('/users', users);


 passport.use(new LocalStrategy(function(username, password, done) {
	User.findOne({ username: username }, function(err, user) {
	if (err) { return done(err); }
	if (!user) { return done(null, false, { message: 'Unknown user: ' + username }); }
	user.comparePassword(password, function(err, isMatch) {
		if (err) return done(err);
		if(isMatch) {
			return done(null, user);
		} else {
			return done(null, false, { message: 'Invalid password' });
		}
	});
	});
}));
// User Schema
var userSchema = new mongoose.Schema({
	username: { type: String, required: true, unique: true },
	email: { type: String, required: true, unique: true },
	password: { type: String, required: true },
	resetPasswordToken: String,
	resetPasswordExpires: Date,
	stat: String
});

// Bcrypt middleware
userSchema.pre('save', function(next) {
	var user = this;
	var SALT_FACTOR = 5;

	if (!user.isModified('password')) return next();

	bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
		if (err) return next(err);

		bcrypt.hash(user.password, salt, null, function(err, hash) {
		if (err) return next(err);
			user.password = hash;
			next();
		});
	});
});


// Password verification
userSchema.methods.comparePassword = function(candidatePassword, cb) {
	bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
		if(err) return cb(err);
		cb(null, isMatch);
	});
};

// Seed a user
var User = mongoose.model('User', userSchema);

mongoose.connect('localhost', 'test');
var db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function callback() {
  console.log('Connected to DB');
});


/*var user = new User({ username: 'Qujian', email: 'qukenn@hotmail.com', password: 'JqPw123,',Stat: 'Y' });
user.save(function(err) {
	if(err) {
	console.log(err);
	} else {
	console.log('user: ' + user.username + " saved.");
	}
});
*/

passport.serializeUser(function(user, done) {
	done(null, user.id);
});

passport.deserializeUser(function(id, done) {
	User.findById(id, function (err, user) {
	done(err, user);
	});
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

app.get('/', ensureAuthenticated,function(req, res){
	console.log('get / : '+ req.sessionID+',' + req.session.cookie.maxAge+','+req.session.cookie.expires);
	res.render('index', { user: req.user });
}); 




app.get('/login', function(req, res){
	res.render('login', { user: req.user, message: req.session.messages });
	console.log('get login : '+ req.sessionID+',' + req.session.cookie.maxAge+','+req.session.cookie.expires);
});

app.post('/login', passport.authenticate('local', { failureRedirect: '/login', failureFlash: true }),
	function(req, res) {
		if (!req.user) { 
			user = req.user
			return res.redirect('login', { user: req.user })
		}
		else {
			return res.render('index', { user: req.user });
		}
});

app.get('/account', ensureAuthenticated, function(req, res){
	res.render('account', { user: req.user });
});

app.get('/about', function(req, res, next) {
	res.render('about', {user: req.user });
});

app.get('/signup', function(req, res) {
	res.render('signup', {
	user: req.user
	});
});

app.post('/signup', function(req, res) {
	console.log('signup: ' + req.body.username);
	req.assert('username', 'Userame is required').notEmpty();
	req.assert('email', 'Email is required').isEmail();  
	req.assert('password', 'Password is required').notEmpty();
	req.assert('confirm', 'Confirm Password is required').notEmpty();
	req.assert('confirm', 'Passwords do not match').equals(req.body.password);
	var errs; 
	var errors = req.validationErrors();
	if (errors) {
		var emsg='' ;
		for (error in errors){
			emsg = emsg + errors[error].msg +'\n';
			console.log('signup: ' + errors[error].msg);
	 	}
		return res.render('signup', {
		title: 'Singup',
		message: 'You Got Errors',
		errors: errors ,
		usernm : req.body.username,
		emails : req.body.email
		});
	}
	else {
		User.findOne({ username: req.body.username }, function(err, user) {
			if (user) {
				console.log('signup verify in db 1: ' + req.body.username);
				req.flash('error', 'The username already exists!');
				return res.render('signup', {
					title: 'Singup',
					message: 'You Got Errors',
					errors: errors ,
					usernm : req.body.username,
					emails : req.body.email
				});
			}
			else{
				User.findOne({ email: req.body.email }, function(err, user2) {
					if (user2) {
						console.log('signup verify in db 2: ' + req.body.email);
						req.flash('error', 'The email already exists!');
						return res.render('signup', {
							title: 'Singup',
							message: 'You Got Errors',
							errors: errors ,
							usernm : req.body.username,
							emails : req.body.email
							});
					}
					else{
						async.waterfall([
							function(done) {
								crypto.randomBytes(20, function(err, buf) {
								var token = buf.toString('hex');
						 	done(err, token);
      								});
							},
							function(token, done) {
								var user = new User({
									username: req.body.username,
									email: req.body.email,
									password: req.body.password,
									resetPasswordToken: token,
									resetPasswordExpires: Date.now() + 3600000, // 1 hour
									stat: 'V'
								});
								user.save(function(err) {
								done(err, token, user);
								});
							},
							function(token, user, done) {
								var auth = {
									auth: {
									api_key: 'key-601fe705a0e1f1fd52b2c47e41944657',
									domain: 'sandboxc3948ded61b1416bb6164e4e28ec46ac.mailgun.org'
									}
								} 

								var nodemailerMailgun = nodemailer.createTransport(mg(auth));
								
								nodemailerMailgun.sendMail({
									from: 'register@mytestapp.com',
									to: req.body.email ,
									subject:'MyApp Registration confirmation',
									text: 'Welcome! Thanks for singing up, Please following this link to active you account\n\n' +
										'http://' + req.headers.host + '/confirm/' + token + '\n\n\n\n' +
										'Thanks!',
								}, function (err, info) {
									if (err) {
										console.log('Error: ' + err);
									}
									else {
										req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
										console.log('Response: ' + info);
									}
									done(err, 'done');
								});	
						}	 
						], function(err) {
							res.redirect('/login');
						});
					} 
				});
			}
		});
	}; 
});


app.get('/logout', function(req, res){
	req.logout();
	res.redirect('/');
});

app.get('/forgot', function(req, res) {
	res.render('forgot', {
	user: req.user
	});
}); 

app.get('/resend', function(req, res) {
	res.render('resend', {
	user: req.user
	});
});

app.post('/resend', function(req, res, next) {
	async.waterfall([
		function(done) {
			crypto.randomBytes(20, function(err, buf) {
			var token = buf.toString('hex');
			done(err, token);
			});
		},
	function(token, done) {
		User.findOne({ email: req.body.email }, function(err, user) {
		if (!user) {
			req.flash('error', 'No account with that email address exists.');
			return res.redirect('/forgot');
		}

		user.resetPasswordToken = token;
		user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
	
		user.save(function(err) {
			done(err, token, user);
			});
		});
	},

	function(token, user, done) {
	// This is your API key that you retrieve from www.mailgun.com/cp (free up to 10K monthly emails)
		var auth = {
			auth: {
				api_key: 'key-601fe705a0e1f1fd52b2c47e41944657',
				domain: 'sandboxc3948ded61b1416bb6164e4e28ec46ac.mailgun.org'
			}
		} 

		var nodemailerMailgun = nodemailer.createTransport(mg(auth));

		nodemailerMailgun.sendMail({
		from: 'register@mytestapp.com',
			to: user.email ,
			subject:'MyApp Registration confirmation',
			text: 'Welcome! Thanks for singing up, Please following this link to active you account\n\n' +
			'http://' + req.headers.host + '/confirm/' + token + '\n\n\n\n' +
			'Thanks!',
		}, function (err, info) {
			if (err) {
				console.log('Error: ' + err);
			}
			else {
				req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
				console.log('Response: ' + info);
			}
			done(err, 'done');
		});	
	}
	], function(err) {
		if (err) return next(err);
		res.redirect('/login');
		});
});

app.post('/forgot', function(req, res, next) {
	async.waterfall([
		function(done) {
		crypto.randomBytes(20, function(err, buf) {
			var token = buf.toString('hex');
			done(err, token);
			});
		},
	function(token, done) {
		User.findOne({ email: req.body.email }, function(err, user) {
			if (!user) {
				req.flash('error', 'No account with that email address exists.');
				return res.redirect('/forgot');
			}

			user.resetPasswordToken = token;
			user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

			user.save(function(err) {
				done(err, token, user);
			});
		});
	},

	function(token, user, done) {
	// This is your API key that you retrieve from www.mailgun.com/cp (free up to 10K monthly emails)
	var auth = {
		auth: {
			api_key: 'key-601fe705a0e1f1fd52b2c47e41944657',
			domain: 'sandboxc3948ded61b1416bb6164e4e28ec46ac.mailgun.org'
		}
	} 

	var nodemailerMailgun = nodemailer.createTransport(mg(auth));

	nodemailerMailgun.sendMail({
		from: 'passwordreset@mytestapp.com',
		to: user.email ,
		subject:'MyApp Password Reset',
		text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
		'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
		'http://' + req.headers.host + '/reset/' + token + '\n\n' +
		'If you did not request this, please ignore this email and your password will remain unchanged.\n',
	}, function (err, info) {
		if (err) {
			console.log('Error: ' + err);
		}
		else {
			req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
			console.log('Response: ' + info);
		}
		done(err, 'done');
	});	
	}
	], function(err) {
		if (err) return next(err);
			res.redirect('/forgot');
	});
});


app.get('/reset/:token', function(req, res) {
	User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
	if (!user) {
		req.flash('error', 'Password reset token is invalid or has expired.');
		return res.redirect('/forgot');
	}
	res.render('reset', {
		user: req.user
		});
	});
});

app.post('/reset/:token', function(req, res) {
	req.assert('password', 'Password is required').notEmpty();
	req.assert('confirm', 'Confirm Password is required').notEmpty();
	req.assert('confirm', 'Passwords do not match').equals(req.body.password);
	
	var errors = req.validationErrors();
	if (errors) {
		return res.render('reset', {
			title: 'Reset',
			message: 'You Got Errors',
			errors: errors
		});
	}; 
	async.waterfall([
		function(done) {
			User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
			if (!user) {
				req.flash('error', 'Password reset token is invalid or has expired.');
				return res.redirect('back');
			}

			user.password = req.body.password;
			user.resetPasswordToken = undefined;
			user.resetPasswordExpires = undefined;

			user.save(function(err) {
				req.logIn(user, function(err) {
					done(err, user);
				});
			});
			});
		},
		function(user, done) {
			var auth = {
				auth: {
				api_key: 'key-601fe705a0e1f1fd52b2c47e41944657',
				domain: 'sandboxc3948ded61b1416bb6164e4e28ec46ac.mailgun.org'
				}
			}
			var nodemailerMailgun = nodemailer.createTransport(mg(auth)); 
			nodemailerMailgun.sendMail({
				from: 'passwordreset@mytestapp.com',
				to: user.email ,
				subject: 'Your password has been changed',
				text: 'Hello,\n\n' +
				'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n',
			}, function (err, info) {
				if (err) {
					console.log('Error: ' + err);
				}
				else {
					req.flash('success', 'Success! Your password has been changed.');
					console.log('Response: ' + info);
				}
				done(err, 'done');
			});	
		}
	], function(err) {
		res.redirect('/login');
	});
});

app.get('/confirm/:token', function(req, res) {
	User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
		if (!user) {
			req.flash('error', 'Confirmation token is invalid or has expired.');
			return res.redirect('/login');
		}
		else{
			user.resetPasswordToken = undefined;
			user.resetPasswordExpires = undefined;
			user.stat = 'Y';
			console.log('confirm1: ' + user.username);
			user.save(function(err) {
				req.logIn(user, function(err) {
					done(err, user);
				});
			})
		console.log('confirm2: ' + user.username);
		req.flash('success', 'you email have been verified! You can login now!')
		}
		res.redirect('/login');
	});
});


// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
	if (req.isAuthenticated()) { return next(); }
	res.redirect('/login')
}

module.exports = app;