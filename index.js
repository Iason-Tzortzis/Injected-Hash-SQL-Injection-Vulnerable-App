//Dependencies
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const cookieParser = require("cookie-parser");
var jwt = require("jsonwebtoken");
const ejsMate = require("ejs-mate");
const bcrypt = require("bcrypt");
const Str_Random = require("./generate_random_string.js");
require("dotenv").config({
  path: "/.env",
});
require("dotenv/config");

//App Setup
app.use(cookieParser());
app.use(express.urlencoded());
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "/views"));
app.engine("ejs", ejsMate);
app.use(express.static(path.join(__dirname, "static")));
app.use(bodyParser.urlencoded({ extended: true }));

//Generate secret key to sign the JWT tokens
const SECRET_KEY = String(Str_Random(32));
const port = process.env.PORT || 8000;

//hash provided string using bcrypt
function hash(string) {
  const salt = bcrypt.genSaltSync();
  const hashedString = bcrypt.hashSync(string, salt);
  return hashedString;
}

//Declare Database
const db = new sqlite3.Database(
  path.join(__dirname, "injected-hash-sql-injection.db"),
  function (error) {
    if (error) {
      return console.error(error.message);
    } else {
      console.log("Connection with Database has been established.");
    }
  }
);

//Create the tables for the users
function createTable() {
  db.exec(`
    DROP TABLE IF EXISTS users;
    CREATE TABLE users
    (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
    );
`);
}

//Insert a user account
function insertRow(username, password) {
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [
    username,
    password,
  ]);
  console.log("Data Inserted Successfully.");
}

//Setup database
function setupdb() {
  createTable();
  insertRow("Angel_Mendoza", hash(Str_Random(8)));
  insertRow("Theodore_Alletez", hash(Str_Random(8)));
  insertRow("Lucas_Allen", hash(Str_Random(8)));
  console.log("Database successfully initialized");
}

//Start database
setupdb();

//Routes
app.get("/", async function (req, res) {
  try {
    return res.render("login");
  } catch (e) {
    return res.send("Error 404");
  }
});

app.post("/", async function (req, res, next) {
  try {
    //Obtain inputted credentials from request body
    let username = req.body.username;
    let password = req.body.password;

    //Check if user exists with provided username
    const result = await new Promise(async function (res, rej) {
      db.get(
        `SELECT * FROM users WHERE username='${username}'`,
        function (e, r) {
          if (e) {
            rej(e.message);
          } else {
            res(r);
          }
        }
      );
    }).catch(function (e) {
      return res.redirect("forbidden");
    });

    //If user record found with provided username check if the provided password is the same with the one stored in the db
    if (result) {
      bcrypt.compare(password, result.password, function (err, isLoggedin) {
        //if passwords match generate JWT token and redirect to home page
        if (isLoggedin) {
          let token_data = {
            username: result.username,
          };
          token = jwt.sign(token_data, SECRET_KEY, { expiresIn: "1h" });
          res.cookie("JWT", token);
          return res.redirect("/home");
        } else {
          return res.send("Invalid credentials submitted");
        }
      });
    } else {
      return res.send("Invalid credentials submitted");
    }
  } catch (e) {
    next();
  }
});

app.get("/home", function (req, res) {
  try {
    try {
      //Get token from the request object
      token = req.cookies.JWT;

      //if no token is found in the request object redirect to login page
      if (!token) {
        return res.redirect("/");
      }

      //Check if JWT token is valid
      var data = jwt.verify(token, SECRET_KEY);
    } catch (err) {
      return res.send("Missing valid JWT token");
    }

    //If token is valid render home page
    if (data) {
      return res.render("home");
    } else {
      res.send("Missing valid JWT token");
    }
  } catch (err) {
    res.send("Error 404");
  }
});

app.get("/forbidden", function (req, res) {
  return res.render("forbidden");
});

app.get("/logout", function (req, res) {
  res.clearCookie("JWT");
  return res.redirect("/");
});

app.get("*", function (req, res) {
  return res.redirect("/");
});

//Start App
app.listen(port, function () {
  console.log(`Serving on Port ${port}`);
});
