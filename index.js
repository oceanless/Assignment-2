require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");
const { render } = require("express/lib/response");

const expireTime = 1 * 60 * 60 * 1000;

var users = [];

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONDODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
  mongoUrl:
  `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
      secret: mongodb_session_secret
    }
})

app.set('view engine', 'ejs');

app.use(session({
  secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
  }
))

function isAdmin(req) {
  if (req.session.user_type == "admin") {
    return true;
  }
  return false;
}

function adminValidation(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403)
    res.render("403");
    return;
  } else {
    next();
  }
}

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}

app.get('/', (req,res) => {
  if (!req.session.authenticated) {
    res.render("index");
  } else {
    res.render("main", {
      username: req.session.username,
    });
  }
});

app.get("/nosql-injection", sessionValidation, async (req, res) => {
  var username = req.query.user;

  if (!username) {
    res.send(
      `
      <h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>
      `
    );
    return;
  }
  console.log("user: " + username);

  const schema = Joi.string().max(20).required();
  const validationResult = schema.validate(username);

  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    res.send(
      "<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>"
    );
    return;
  }

  const result = await userCollection
    .find({ email: email })
    .project({ email: 1, password: 1, username: 1, _id: 1 })
    .toArray();

  console.log(result);

  res.send(`<h1>Hello ${username}</h1>`);
});


app.get('/signup', (req, res) => {
  res.render("signup");
});

app.get('/login', (req, res) => {
  res.render("login");
});
  

app.post('/submitInfo', async (req,res) => {
  var username = req.body.username;
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.object(
    {
      username: Joi.string().required(),
      email: Joi.string().required(),
      password: Joi.string().max(20).required()
    });
  
  const validationResult = schema.validate({username, email, password});
  if (validationResult.error != null) {
      console.log(validationResult.error);
      res.redirect("/signup");
      return;
  }
  
  if (!username) {
    res.render("signup_error", { error: "Name"});
    return;
  } 
  if (!email) {
    res.render("signup_error", { error: "Email"});
    return;
  } 
  if (!password) {
    res.render("signup_error", { error: "Password"});
    return;
  } 

  var hashedPassword = await bcrypt.hash(password, saltRounds);

  await userCollection.insertOne({username: username, email: email, password: hashedPassword, user_type: "user",});
  console.log("Inserted user");

  req.session.authenticated = true;
  req.session.username = username;
  req.session.cookie.maxAge = expireTime;

  res.redirect("/members");
})

app.post('/loginSubmit', async (req, res) => {
  var email = req.body.email;
  var password = req.body.password;

  const schema = Joi.string().required();
  const validationResult = schema.validate(email);
  if (validationResult.error != null) {
    console.log(validationResult.error);
    res.redirect("/login");
    return;
  }

  const result = await userCollection.find({ email: email }).project({ username: 1, email: 1, password: 1, user_type:1, _id: 1 }).toArray();

  console.log(result);
  if (result.length != 1) {
    res.render("login_error");
    return;
  }
  if (await bcrypt.compare(password, result[0].password)) {
    console.log("correct password");
    req.session.authenticated = true;
    req.session.username = result[0].username;
    req.session.user_type = result[0].user_type;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;
    res.redirect('/members');
    return;
  }
  else {
    res.render("login_error");
    return;
  }
});

app.get('/loggedIn', (req,res) => {
  if (!req.session.authenticated) {
    res.render("login");
  } else {
    res.render("members");
  }
})

app.get('/members', (req,res) => {
  if (!req.session.authenticated) {
    res.render("index");
  } else {
    var username = req.session.username;
    res.render("members", {
      username: username,
    })
  }
})

app.get('/admin', sessionValidation, adminValidation, async(req, res) => {
  const result = await userCollection.find().project({ username: 1, user_type: 1 }).toArray();
  res.render("admin", {
    users: result,
    username: req.session.username,
  });
});

app.get("/promote/:username", async (req, res) => {
  var username = req.params.username;
    await userCollection.findOneAndUpdate(
      { username: username },
      { $set: { user_type: "admin" } }
    );
    res.redirect("/admin");
});

app.get("/demote/:username", async (req, res) => {
  var username = req.params.username;
    await userCollection.findOneAndUpdate(
      { username: username },
      { $set: { user_type: "user" } }
    );
    res.redirect("/admin");
    console.log(err);
    res.send("Error promoting user");
});

app.get('/logout', (req,res) => {
  req.session.destroy();
  res.redirect('/');
})

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
  res.status(404);
  res.render("404");
})

app.listen(port, () => {
  console.log("Listening on port " + port);
})


