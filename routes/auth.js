const router = require("express").Router();
const passport = require("passport");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const User = require("../Model/User");
const getUser = require("../middleware/getUser");
const { body, validationResult } = require('express-validator');

const secretKey = process.env.SECRET_KEY; // secret key for jwtoken authentication

// fetching the user 
router.get("/login/success", async (req, res) => {
  try {
    const jwtoken = req.header("jwt-token");
    if (jwtoken) {
      const data = jwt.verify(jwtoken, secretKey)
      let user = await User.findById(data.user.id).select("-picture");

      if (!user) {
        return res.status(500).json({ error: true, message: "Internal server error" })
      }

      let { googleId, password, ...userCopy } = user.toObject();

      if (googleId && password) {
        user = userCopy;
      }

      const response = { error: false, message: `Welcome Again ${user.name}`, user: user };

      return res.status(200).json(response);

    } else {
      // if using google oauth0 then get req.user from google
      if (req.user) {
        // data for jwtoken authentication
        const data = {
          user: {
            id: req.user._id
          }
        }
        const jwtoken = jwt.sign(data, secretKey); //creating jwtoken for user
        return res.status(200).json({
          error: false,
          message: "Logged in successfully",
          user: req.user,
          jwtoken: jwtoken, // send jwtoken for future use to the user
        });
      } else {
        return res.status(400).json({
          error: true,
          message: "Not Authorized",
        });
      }
    }
  } catch (error) {
    console.log("/login/success", error);
  }
});


// response if google oauth0 is failed to authenticate
router.get("/login/failed", (req, res) => {
  res.status(401).json({
    error: true,
    message: "Login failed",
  });
});

// the callback url of google oauth0
router.get("/google/callback",
  passport.authenticate("google", {
    successRedirect: process.env.CLIENT_URL, // if user found then redirect to the client url
    failureRedirect: "/login/failed", // if user failed then redirect /login/failed auth.
  })
);

// authenticate google useing passport  
router.get("/google", passport.authenticate("google", ["profile", "email"]));

// logout middleware of google oauth0  
router.get("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect(`${process.env.CLIENT_URL}login`);// redirect to a specific route when user logged out successfully
  });
  // res.redirect('http://localhost:3000/login');
});


// creating user with user body method POST method auth/user/createuser login not-required
router.post("/user/createuser", [
  body("name", "Use the correct Name").isLength({ min: 1 }),
  body("email", "Use the correct Email").isEmail(),
  body("password", "Password Length must be 8 or above").isLength({ min: 8 }),
], async (req, res) => {
  const result = validationResult(req);
  if (!result.isEmpty()) {
    return res.status(400).json({ error: result.array() })
  }
  try {
    let user = await User.findOne({ email: req.body.email }); // find user from database

    // if user available
    if (user) {
      return res.status(500).json({ error: true, message: "User Already Exists Plsease login" });
    }

    const salt = await bcrypt.genSalt(10); // creating the hashed password for security of password
    const password = await bcrypt.hash(req.body.password, salt);

    // saving user in database if user not exists yet
    user = await User.create({
      name: req.body.name,
      email: req.body.email,
      password: password, // sending the hashed password to the database
    });

    // data for jwt token authentication
    const data = {
      user: {
        id: user._id
      }
    }

    const jwtoken = jwt.sign(data, secretKey); // creating jwt token for user

    return res.status(200).json({
      error: false,
      message: "Welcome to oauth application",
      jwtoken: jwtoken,// sending the jwt token to the user
    });
  } catch (error) {
    console.log(error);
  }
});



// getting user with user body method POST auth/user/createuser login not-required
router.post("/user/login",[
  body("email","Use the correct email").isEmail(),
  body("password","Atleast 8 caracter").isLength({ min: 8 }),
], async (req, res) => {

    try {
      const result = validationResult(req);
      if (!result.isEmpty()) {
        return res.status(400).json({ error: result.array() });
      }

      let user = await User.findOne({ email: req.body.email }); // searching for user

      let jwtoken;
      if (user) {
        // data for jwt token
        const data = {
          user: {
            id: user._id
          }
        }

        jwtoken = jwt.sign(data, secretKey); // crea  ting jwt token for user
      }

      if (!user) {
        return res
          .status(400)
          .json({ error: true, message: "Please use the correct Credentials." });
      }
      else {

        const hash = await bcrypt.compare(req.body.password, user.password); // hashing the password if req.body.password is mathch with database hased password then return true else false

        // if hash is true
        if (hash) {
          return res
            .status(200)
            .json({
              error: false,
              message: "Welcome Again",
              jwtoken: jwtoken,
            });
        } else {
          return res
            .status(400)
            .json({
              error: true,
              message: "Please use the correct Credehehentials.",
            });
        }
      }
    } catch (error) {
      console.log(error);
    }
  });

// multer middleware for handling files upload 

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "./upload");
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname + Date.now() + ".jpg");
  }
});

const upload = multer({ storage: storage }).single("picture");

// Upload profile picture in the database (POST /auth/user/uploadpicture, login required)
router.post('/user/uploadpicture', getUser, upload, async (req, res) => {
  try {
    const userId = req.userId.id // getting the user id from the getUser middleware

    const user = await User.findById(userId); // getting the user using id from the jwt-token id
    if (!user) return res.status(400).json({ error: true, message: "Please use the correct Credehehentials" });

    // for deleting the old profile image
    if (user.picture) {
      if (fs.existsSync(user.picture)) {
        fs.unlink(user.picture, (err) => {
          if (err) {
            return res.status(400).json({ error: true, message: "Error Deleting file", err: err });
          }
        });
      }
    }

    const uploadImage = await User.findByIdAndUpdate(userId, { picture: req.file.path }, { new: true }).select("-name -password -email -_id");
    if (!uploadImage) {
      return res.status(500).json({ error: true, message: "User not found" });
    }
    return res.status(200).json({ error: false, message: "Successfully uploaded" });

  } catch (error) {
    console.log("error ", error)
  }
});

// getting the profile image and send to the client using post method /user/getprofilepicture login required
router.get("/user/getprofilepicture", getUser, async (req, res) => {
  try {
    const userId = req.userId.id;

    const user = await User.findById(userId).select("-password -name -_id -email -__v");
    if (!user) return res.status(500).json({ "error": true, message: "User Not Found" });

    if (user.picture && user.picture.includes("upload")) {
      // Construct the full path to the image file
      const filePath = path.resolve(user.picture);
      // Return the image file to the client
      return res.sendFile(filePath);
    }

    return res.status(200).json({ blobFile: false, picture: user.picture });

  } catch (error) {
    console.log(error)
    return res.status(500).json({ "error": error, message: "Use the correct credentials" })
  }
})

// update the password if user sign in with google oauth method POST /auth/user/updatepassword login required
router.post("/user/updatepassword", getUser, async (req, res) => {
  try {
    const userId = req.userId.id;
    const salt = await bcrypt.genSalt(10)
    const password = await bcrypt.hash(req.body.password, salt)

    const user = await User.findByIdAndUpdate(userId, { password: password }, { new: true });

    if (!user) {
      return res.status(400).json({ error: true, message: "User Not Found" });
    }

    return res.status(200).json({ error: false, message: "Password updated Success" })
  } catch (error) {
    res.status(500).json({ error: true, message: "Internal Server Error" })
  }

})

module.exports = router;
