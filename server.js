require("dotenv").config();
const express = require("express");
const cors = require("cors");
const passport = require("passport");
const passportSetup = require("./passport");
const session = require('express-session');
const dbConnect = require("./db");


const app = express();
app.use(express.json());
dbConnect();


app.use(session({
    secret: 'laksh',
    resave: false,
    saveUninitialized: false
}));

app.use(
    cors({
        origin: "http://localhost:3000",
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true,
    })
);

passportSetup()

app.use(passport.initialize());
app.use(passport.session());

app.use("/auth", require("./routes/auth"));

const port = process.env.PORT || 8000;
app.listen(port, () => console.log("Listening on port " + port));