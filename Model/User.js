const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const User = new Schema({
    name:{
        type:String,
    },
    email:{
        type:String,
        require:true,
    },
    password:{
        type:String,
    },
    googleId:{
        type:String,
    },
    picture: String,
});

module.exports = mongoose.model("user", User);