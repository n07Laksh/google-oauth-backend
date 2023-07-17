const mongoose = require('mongoose');
const mongoURI = "mongodb://localhost:27017/Google-oauth20"

function dbConnect(){
    mongoose.connect(mongoURI);
    console.log("database connected");
}

module.exports = dbConnect;