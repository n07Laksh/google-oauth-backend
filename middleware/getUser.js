const jwt = require("jsonwebtoken");

const secretKey = process.env.SECRET_KEY;


const getUser = (req,res,next) => {

    const jwtoken = req.header("jwt-token");
    if(!jwtoken) return res.status(400).json({err:true, message:"Please use the valid token"})

    try {
        // parsing the token and getting the user
        const data = jwt.verify(jwtoken, secretKey);
        req.userId = data.user;
        next();
    } catch (error) {
        return res.status(400).json({error:true, message:"Authenticate using correct credentials"});
    }
    
};

module.exports = getUser;