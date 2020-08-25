require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const router = express.Router();
const app = express();
const { body, validationResult } = require("express-validator");
const exphbs = require("express-handlebars");
const sql = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const PORT = process.env.PORT;
const { uuid } = require("uuidv4");
const session = require("express-session");

//Layout Engine
app.engine("handlebars", exphbs({ defaultLayout: "main" }));
app.set("view engine", "handlebars");

const time = 600000 * 4;
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: time },
  })
);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.listen(PORT, () => {
  console.log("Server auf Port '" + PORT + "' gestartet");
});

/**
 *
 *
 *  --------------
 *  Express Router
 *  --------------
 *
 *
 */

//Startseite
router.get("/", (req, res, next) => {
  sql.query("SELECT COUNT(id) AS total from user", (err, results, fields) => {
    if (err) {
      res.status(503).render("error");
    } else {
      res.render("index", {
        counter: results[0].total,
        session: req.session.userId ? true : false,
      });
    }
  });
});

//Secret Seite
router.get("/secret", authentification, async (req, res) => {
  await sql.query("SELECT * FROM user", (err, result, fields) => {
    if (err) {
      res.status(500).render("error", {
        code: [5, 0, 0],
        text: "Fehler in der Datenbank",
      });
    } else {
      res.status(200).render("secret", {
        result: result,
      });
    }
  });
});

//Registrieren Seite
router.get("/register", (req, res) => {
  return res.render("register");
});

//Logout Funktion
router.get("/logout", logout);

//Login Seite
router.get("/login", (req, res) => {
  return res.render("login");
});

//Abwicklung vom registrieren
router.post("/handleregister", async (req, res) => {
  body("username").isString().notEmpty().trim().escape();
  body("email").escape().isEmail().normalizeEmail().notEmpty();
  body("password").escape().trim().notEmpty();
  body("repeatpassword").escape().trim().notEmpty();

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(422).render("error", {
      code: [4, 2, 2],
      text: "Fehler beim Registrieren",
      err: errors,
    });
  } else {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;
    const repeatpassword = req.body.repeatpassword;

    if (password === repeatpassword) {
      await sql.query(
        "SELECT COUNT(*) AS total FROM user WHERE username = ? OR email = ?",
        [username, email],
        (err, result, fields) => {
          if (err) {
            res.status(500).render("error", {
              code: [5, 0, 0],
              text: "Fehler beim registrieren",
            });
          } else {
            if (result[0].total >= 1) {
              res.status(200).render("error", {
                code: [4, 0, 3],
                text:
                  "Es existiert bereits ein Benutzer mit diesem Benutzername oder dieser Email",
              });
            } else {
              //Bcrypt als Passwort Verschlüsslung
              bcrypt.hash(password, 10, (err, hash) => {
                if (err) {
                  res.status(422).render("error", {
                    code: 422,
                    text: "Fehler beim verschlüsseln",
                    err: err,
                  });
                }
                sql.query(
                  "INSERT INTO user (uuid, username, email, password) VALUES ('" +
                    uuid() +
                    "', '" +
                    username +
                    "', '" +
                    email +
                    "', '" +
                    hash +
                    "')",
                  (err, result) => {
                    if (err) {
                      res.status(403).render("error", {
                        code: [4, 0, 3],
                        text: "Ungültige Eingabe",
                        err: err,
                      });
                    } else {
                      console.log("Benutzer registriert");
                      res.redirect("/");
                    }
                  }
                );
              });
            }
          }
        }
      );
    } else {
      res.status(403).render("error", {
        code: [4, 0, 4],
        text: "Deine Passwörter müssen übereinander stimmen",
      });
    }
  }
});

//Abwicklung vom Login Prozess
router.post("/handlelogin", async (req, res) => {
  body("input").isString().notEmpty().trim().escape();
  body("password").escape().trim().notEmpty();

  const errors = validationResult(req);
  const input = req.body.input;
  const passwords = req.body.password;

  if (errors != "" || input != "" || password != "") {
    await sql.query(
      "SELECT username, password, uuid FROM user WHERE username = ? OR email = ? LIMIT 1",
      [input, input],
      (err, results, fields) => {
        if (err) {
          res.render("error", {
            code: [5, 0, 0],
            text: "Fehler beim validieren des Benutzers!",
          });
        } else if (results.length < 1) {
          res.render("error", {
            code: [4, 0, 4],
            text:
              "Es wurde kein Benutzer mit dieser Email oder diesem Benutzernamen gefunden!",
          });
        } else {
          console.log(passwords);
          bcrypt.compare(passwords, results[0].password, (err, result) => {
            if (err) {
              res.status(500).render("error", {
                code: [5, 0, 0],
                text: "Fehler beim validieren des Passwortes",
              });
            }

            if (result === true) {
              req.session.userId = results[0].uuid;
              res.redirect("/secret");
            } else {
              res.status(500).render("error", {
                code: [4, 0, 4],
                text: "Falsches Passwort",
              });
            }
          });
        }
      }
    );
  } else {
    res.status(403).render("error", {
      code: [4, 0, 3],
      text: "Es darf kein Feld leer sein",
    });
  }
});

app.use("/", router);

/**
 *
 *
 *  Funktionen
 *
 *
 */

function authentification(req, res, next) {
  if (!req.session.userId) {
    res.status(403).render("error", {
      code: [4, 0, 3],
      text: "Du bist für diese Seite nicht authorisiert",
    });
  } else {
    next();
  }
}

function logout(req, res, next) {
  req.session.destroy((err) => {
    if (err) {
      return res.redirect("/");
    }
    res.redirect("/");
  });
}
