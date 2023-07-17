const GoogleStrategy = require("passport-google-oauth20").Strategy;
const passport = require("passport");
const User = require("./Model/User");

const passportSetup = () => {
  passport.use(
    // google strategy for google oauth0 
    new GoogleStrategy(
      {
        clientID: process.env.CLIENT_ID, // id from Google Cloud Platform
        clientSecret: process.env.CLIENT_SECRET, // secret from Google Cloud Platform
        callbackURL: "/auth/google/callback", // callback URL when logged in with google account
        scope: ["profile", "email"], // request profile and email from google account using goggle oauth
      },
      async function (accessToken, refreshToken, profile, callback) {
        try {
          const googleData = profile._json;
          let user = await User.findOne({ email: googleData.email }); // serching user in db 

          // if user already in db then return the db user object
          if (user) {
            return callback(null, user);
          } 
          // else create the new user object in db using google data
          else {
            let newUser = new User({
              googleId: googleData.sub,
              name: googleData.name,
              email: googleData.email,
              picture: googleData.picture,
            });

            newUser.save();

            return callback(null, newUser);
          }
        } catch (error) {
          return callback(err);
        }
      }
    )
  );


  passport.serializeUser((user, done) => {
    done(null, user.id); // Saving only the user's ID in the session for deserialize User 
  });


  passport.deserializeUser(async (id, done) => {
    try {
      let user = await User.findById(id);
      if (user) {
        done(null, user); // send user get from database matching 
      }
    } catch (error) {
      console.log("error", error);
    }
  });
};


module.exports = passportSetup;
