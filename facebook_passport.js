var express = require('express');
var fs = require('fs');
var session = require('express-session');
var MySqlStore = require('express-mysql-session')(session);
var bodyParser = require('body-parser');
var mysql = require('mysql');
var bkdf2Password = require('pbkdf2-password');
var hasher = bkdf2Password();
var passport = require('passport')
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var app  = express();
var client = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '811442',
  database: 'o2'
});
app.use(bodyParser.urlencoded({ extended : false }));
app.use(session({
  secret : '4323423dffdsfsadfa',
  resave : false,
  saveUninitialized : true,
  store : new MySqlStore({
    host : 'localhost',
    port : 3306,
    user : 'root',
    password : '811442',
    database : 'o2'
  })
}));
app.listen(9000, function(){
  console.log("Server running!");
});
app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/logout', function(req, res){
  req.logout();
  req.session.save(function(){
    res.redirect('/welcome');
  });
});

app.get('/welcome', function(req, res){
  if(req.user && req.user.displayName){
    res.send(`
        <h1>Hello, ${req.user.displayName}</h1>
        <a href="/auth/logout">logout</a>
      `);
  } else {
    res.send(`
    <h1>Welcome</h1>
    <ul>
      <li><a href="/auth/login">Login</a></li>
      <li><a href="/auth/register">Register</a></li>
    </ul>
    `);
  };
});

passport.serializeUser(function(user, done) {
  console.log('serializeUser',user)
  done(null, user.authId);
});


passport.deserializeUser(function(id, done) {
  console.log('deserializeUser', id);
  for(var i = 0; i < users.length; i++){
    var user = users[i];
    if(user.authId == id){
      return done(null, user);
    }
  }
});

passport.use(new LocalStrategy(
  function(username, password, done){
    var uname = username;
    var pwd = password;
    for(var i = 0; i < users.length; i++){
      var user = users[i];
      if(uname == user.username){
        return hasher({password:pwd, salt:user.salt}, function(err, pass, salt, hash){
          if(hash == user.password){
            done(null, user);
          } else {
            done(null, false);
          }
        });
      }
    }
    done(null, false);
  }
));

app.post('/auth/login', passport.authenticate(
    'local',
    {
      successRedirect: '/welcome',
      failureRedirect: '/auth/login',
      failureFlash: false
    }
  )
);

passport.use(new FacebookStrategy({
    clientID: '1531139130317013',
    clientSecret:'b48e17926eb42245aa4ee489f9f916d0',
    callbackURL: "/auth/facebook/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    var authId = 'fackebook:'+profile.id;
    for(var i=0; i < users.length; i++){
      var user = users[i];
      if(user.authId == authId){
        return done(null, user);
      }
    }
    var newuser = {
      'authId':authId,
      'displayName':profile.displayName
    };
    users.push(newuser);
    done(null, newuser);
  }
));


app.get('/auth/facebook', passport.authenticate(
  'facebook'
  )
);

app.get('/auth/facebook/callback', passport.authenticate(
  'facebook', {
    successRedirect: '/welcome',
    failureRedirect: '/auth/login'
    }
  )
);

app.get('/auth/login', function(req, res){
  var output = `
  <h1>Login</h1>
  <form action="/auth/login" method="post">
    <p>
      <input type="text" name="username" placeholder="username">
    </p>
    <p>
      <input type="text" name="password" placeholder="password">
    </p>
    <p>
      <input type="submit" value="SEND">
    </p>
  </form>
  <a href="/auth/facebook">facebook</a>
  `
  res.send(output);
});
var users = [
  {
  authId: 'local:rangyu',
  username : 'rangyu',
  password : 'vPNeIFCbVXpEptFXeAU4oM68PoRXc2MXukrlEpZ2Ou+MZ7CRzzc+ov5+WGxkIyoCo9b5NssRSkbPyzq6wnhCAgmiSM6ns3GMLFdblKyZd293fD6evS3yuicNYCWEto9hb2omro+9tuFalmTxF89LJS0jQLNFmdQrWDIcMpR6SXM=', 
  salt : 'rkfj3CAHJrZGrtIt7ILgEFGykNdGj4kCqgVhCZtKjKqQYb4KVtltf+bfPWBslS/pE20zsrKhn552EsMr5dLjxQ==',
  displayName : 'Rangyu'
  }
];
app.post('/auth/register', function(req, res){
  hasher({password:req.body.password}, function(err, pass, salt, hash){
    var user = {
      authId:'local:'+req.body.username,
      username : req.body.username,
      password : hash,
      salt : salt,
      displayName : req.body.displayName
    };
    users.push(user);
    req.login(user, function(err){
      req.session.save(function(){
        res.redirect('/welcome');
      });
    });
  });
});

app.get('/auth/register', function(req, res){
  var output = `
  <h1>Register</h1>
  <form action="/auth/register" method="post">
    <p>
      <input type="text" name="username" placeholder="username">
    </p>
    <p>
      <input type="text" name="password" placeholder="password">
    </p>
    <p>
      <input type="text" name="displayName" placeholder="displayName">
    </p>
    <p>
      <input type="submit" value="SEND">
    </p>
  </form>
  `
  res.send(output);
});
