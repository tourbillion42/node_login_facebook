var express = require('express');
var fs = require('fs');
var session = require('express-session');
var MySqlStore = require('express-mysql-session')(session);
var bodyParser = require('body-parser');
var bkdf2Password = require('pbkdf2-password'); //암호화 모듈
var hasher = bkdf2Password(); //암호화 모듈
var passport = require('passport')
var LocalStrategy = require('passport-local').Strategy;
var app  = express();
var mysql = require('mysql');
var conn = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '811442',
  database: 'o2'
});
conn.connect();
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
app.use(passport.session()); // 반드시 session 설정뒤에 입력

app.get('/auth/logout', function(req, res){
  req.logout();  // passport의 logout() 메소드 사용
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

passport.serializeUser(function(user, done) {  // done user값을 가지고 와서 serializeUse의 callback을 실행
  done(null, user.authId); // 위에 user에서 가지고 온 정보를 session에 저장
});

// serializeUser를 통해 처음 login한 user값의 session을 확인하고 다음부터 접속 할때는 deserializeUser의 callback을 실행
passport.deserializeUser(function(id, done) { // id값은 위의 user.username 값이다 (session 데이터의 값)
  var sql = 'SELECT * FROM users WHERE authId =?';
  conn.query(sql, [id], function(err, results){
    if(err){
      console.log(err);
      done('There is no user.');
    } else {
      done(null, results[0]);
    }
  });
});

passport.use(new LocalStrategy(
  function(username, password, done){ // form에서 전달된 username, password 사용 고정값
    var uname = username; //위의 username 사용
    var pwd = password; //위의 password 사용
    var sql = 'SELECT * FROM users WHERE authId=?';
    conn.query(sql, ['local:'+uname], function(err, results){
      if(err){
        return done('There is no user.');
      }
      var user = results[0];
      return hasher({password:pwd, salt:user.salt}, function(err, pass, salt, hash){
        if(hash == user.password){
          done(null, user); // login에 성공했을때, user값을 가지고 serializeUser로 이동
        } else {
          done(null, false, { message : 'Id를 확인하세요'});  // login에 실패 했을때 false
        }
      });
    });
  }
));
app.post('/auth/login', passport.authenticate(
    'local',  // local Strategy 실행 ex) facebook strategy일 경우 facebook 이라고 명시
    {
      successRedirect: '/welcome',   // login 성공시
      failureRedirect: '/auth/login', // login 실패시
      failureFlash: false
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
  `
  res.send(output);
});

app.post('/auth/register', function(req, res){
  hasher({password:req.body.password}, function(err, pass, salt, hash){
    var user = {
      authId : 'local:'+req.body.username,
      username : req.body.username,
      password : hash,
      salt : salt,
      displayName : req.body.displayName
    };
    var sql = "INSERT INTO users SET ?";
    conn.query(sql, user, function(err, result){
      if(err){
        console.log(err);
        res.status(500);
      } else {
        req.login(user, function(err){  // passport의 login 메소드 사용
          req.session.save(function(){
            res.redirect('/welcome');
          });
        });
      }
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
