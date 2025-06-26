const express = require('express');
const fs = require('fs');
const app = express();
const { Client } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
require('dotenv').config();

app.use(express.json());
const con = new Client({
  host: process.env.HOST,
  user: process.env.USER2,
  port: process.env.PORT,
  password: process.env.PASSWORD,
  database: process.env.DATABASE
});

con.connect().then(() => console.log("connected"));

app.get('/', verifyAccessToken, (request, response) => {

  fs.readFile('./home.html', 'utf8', (err, html) => {
    if (err) {
      response.status(500).send('error 404 not found')
    }
    response.send(html)

  });

});

app.get('/:id', verifyAccessToken, async (req, res) => {

  try {
    const { id } = req.params;
    const data = await con.query("SELECT * FROM users WHERE id=$1", [id]);
    if (data.rows[0].username == req.user.name)
      res.json(data.rows[0]);
    else {
      return res.sendStatus(401)
    }
  }
  catch (err) {
    console.log(err.message);
  }
});


app.post('/signup', async (req, res) => {
  try {
    const { username, password, email, birth } = req.body;

    if (!username || !password || !email || !birth) {
      return res.status(400).json({ error: "All fields are required" });
    }
    const hashedPassword = await bcrypt.hash(password, 10)
    const user = await con.query(
      "INSERT INTO users (username, password, email, birth) VALUES ($1, $2, $3, $4) RETURNING *",
      [username, hashedPassword, email, birth]
    );
  } catch (err) {
    console.error(err.message);
    res.status(500).json({ error: "Server error" });
  }
});

app.post('/login', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;
  const check = await con.query("SELECT * FROM users WHERE username=$1", [username]);
  console.log("here")
  if (check.rows[0].username == username) {
    if (await bcrypt.compare(password, check.rows[0].password)) {
      const user = { name: username };
      const token = jwt.sign(user, process.env.TOKEN_SECERT);
      res.json({ accessToken: token })
    }
    else return res.status(400).send("passowrd or username is wrong")

  }
  else return res.status(400).send("passowrd or username is wrong")

})

app.delete('/logout',(req,res)=>{

})

function verifyAccessToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (token == null) {
    return res.sendStatus(401);
  }
  jwt.verify(token, process.env.TOKEN_SECERT, (err, user) => {
    if (err) return res.sendStatus(403)
      
    req.user = user;
    next();
  })
}


app.listen(process.env.port || 3000, () => console.log('http://localhost:3000'))