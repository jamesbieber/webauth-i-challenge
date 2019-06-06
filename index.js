const express = require("express");
const bcrypt = require("bcryptjs");

const userModel = require("./users/users-model");

const server = express();

server.use(express.json());

function authorize(req, res, next) {
  const username = req.headers["x-username"];
  const password = req.headers["x-password"];

  if (!username || !password) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  userModel
    .findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        next();
      } else {
        res.status(401).json({ message: "Invalid credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
}

server.get("/api/users", authorize, (req, res) => {
  userModel
    .find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  userModel
    .findBy({ username })
    .first()
    .then(user => {
      const isValidPass = bcrypt.compareSync(password, user.password);
      if (user && isValidPass) {
        res.status(200).json({ message: `Welcome ${user.username}` });
      } else {
        res.status(401).json({ message: "Invalid credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post("/api/register", (req, res) => {
  let user = req.body;

  if (!user.username || !user.password) {
    return res.status(500).json({ message: "Needs username and password" });
  }

  const hash = bcrypt.hashSync(user.password, 12);
  user.password = hash;

  userModel
    .add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`\n **Running on port ${port}**\n`));
