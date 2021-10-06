
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const mysql      = require('mysql');
const dbconfig   = require('../dbaccount/dbaccount.js');
const connection = mysql.createConnection(dbconfig);

connection.connect(function(err){
  if(err) {                                     // or restarting (takes a while sometimes).
    console.log('error when connecting to db:', err);
    setTimeout(handleDisconnect, 2000); // We introduce a delay before attempting to reconnect,
  }     
});

// main page( index - if not logged in go to log in page directly)
router.get('/', function(req, res, next) {
  res.redirect('/index');
});
router.get('/index', function(req, res, next) {
  let idnum = req.session.idn
  // if(req.session.user){
  console.log(req.session.user, idnum)
  var sql = 'SELECT DATE_FORMAT(now(), "%M") as month, alligner,sum(cost) as total FROM finance.account where userid = ? and DATE_FORMAT(time, "%Y-%m") = date_format(now(), "%Y-%m") group by alligner order by alligner;'+
  'SELECT sum(if(income=1, cost, -cost)) as total from finance.account where userid = ?;' + 
  'SELECT sum(if(income=1, cost, -cost)) as total, sum(if(income=1, cost, 0)) as income, sum(if(income=0, cost, 0)) as outcome from finance.account where userid = ? and DATE_FORMAT(time, "%Y-%m") = date_format(now(), "%Y-%m");'
  connection.query(sql, [idnum,idnum,idnum], function (error, results, fields) {
    res.render('main/index', {result1:results[0], result2:results[1], result3:results[2], name:req.session.user});
  });
});

// Login
router.get('/login', function(req, res, next) {
  res.render('main/login/login');
});
router.post('/login', function(req, res, next) {
  let rb = req.body
  let inpw = rb.pw
  const sql = 'SELECT * FROM nodedb.account where id = ?'
  const params = [rb.id];
  console.log(rb.id, inpw);
  connection.query(sql,params,function (err, results, fields) {
    if(err){
      console.log(err);
    }else{
      crypto.pbkdf2(inpw, results[0].salt, 100000, 64, 'sha512', (err, key) => {
        if (key.toString('base64') === results[0].password, results[0].permission >= 1){
          req.session.idname = rb.id;
          req.session.idn = results[0].number;
          req.session.user = results[0].name;
          req.session.permission = results[0].permission;
          req.session.save();
          res.redirect('/index');  
        }
        else{
          console.log("Wrong PW", key.toString('base64'), results[0].password)
          res.redirect('/login')
        }
      });
    }
  });
});
router.get('/logout', function(req, res, next){
    console.log('/process/loginout 라우팅 함수호출 됨');
    if (req.session.user) {
        console.log('로그아웃 처리');
        req.session.destroy(
            function (err) {
                if (err) {
                    console.log('세션 삭제시 에러');
                    return;
                }
                console.log('세션 삭제 성공');
                //파일 지정시 제일 앞에 / 를 붙여야 root 즉 public 안에서부터 찾게 된다
                res.redirect('/index');
            }
        );          //세션정보 삭제
    } else {
        console.log('Not Loged in');
        res.redirect('/Login');
    }
})

router.get('/account', function(req, res, next){
  if(req.session.user){
    res.render('main/login/account', {name:req.session.user, id:req.session.idname, permission:req.session.permission});
  }else{
    res.redirect('login')
  }
});

router.get('/register', function(req, res, next) {
  res.render('main/login/register');
});
router.post('/register', function(req, res, next){
  let rb = req.body
  let inpw = rb.pw
  crypto.randomBytes(32, function(err, buf) {
    crypto.pbkdf2(inpw, buf.toString('base64'), 100000, 64, 'sha512', (err, key) => {
      const sql = 'INSERT into nodedb.account(id, password, name, salt)VALUES(?, ?, ?, ?)'
      const params = [rb.id, key.toString('base64'), rb.name, buf.toString('base64')];
      connection.query(sql, params, function(err, result, next){
        if(err){
          console.log(err);
        }
        else{
          res.redirect('/index')
        }
      })
    });
  });
});

router.get('/sex', function(req, res, next){
  res.redirect('https://www.naver.com');
});
router.get('/namu', function(req, res, next){
  res.redirect('https://namu.wiki');
});

// Others
router.get('/sitemap', function(req, res, next) {
  if(req.session.user){
    res.render('main/sitemap', {name:req.session.user });
  }else{
    res.redirect('login')
  }
});

module.exports = router;
