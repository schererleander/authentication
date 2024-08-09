const express = require("express")
const { v4: uuid } = require('uuid')
const path = require("path")
const mariadb = require("mariadb")
const bcrypt = require('bcrypt');

const app = express()
const port = 80
app.use(express.urlencoded({ extended: true}))

const con = mariadb.createPool({
  host: "127.0.0.1",
  user: "root",
  password: "root",
  database: "db1"
})

app.use(express.static("src"));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "src", "/password.html"))
})

app.post("/api/password/register", async (req, res) => {
  try {
    const {email, password} = req.body

    if(!password || !email) {
        return res.status(200).send("Invalid credentials")
    }

    const [existingUsers] = await con.query(
        "SELECT * FROM users WHERE email = ?", [email]
    )
    if(existingUsers != null) {
      return res.status(200).send("User already exists")
    }
    const UUID = uuid()
    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    await con.query(
      "INSERT INTO users (UUID, email, password, salt) VALUES(?,?,?,?)",
      [UUID, email, hashedPassword, salt]
    )
    return res.status(201).send("User registered successfully")
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
})

app.post("/api/password/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(401).send("Invalid credentials");
    }

    const [users] = await con.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (users == null) {
      return res.status(200).send("User does not exist");
    }
    const passwordMatch = bcrypt.compareSync(password, users.password);

    if (!passwordMatch) {
      return res.status(200).send("Invalid credentials");
    }

    return res.status(200).send("User signed in successfully");
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`)
})

app.get("/user/:uuid", async (req, res) => {
  try {
  const UUID = req.params.uuid
  const [user] = await con.query(
    "SELECT email FROM users WHERE UUID = ?",
    [UUID]
  )
  res.status(200).send(user)
  } catch (error) {
    console.error(error)
    return res.status(500).send("Server error")
  }
})