const router = require("express").Router();
const User = require("../models/User");
const CryptoJS = require("crypto-js");
const jwt = require("jsonwebtoken");
const { google } = require("googleapis");
const nodemailer = require("nodemailer");
const { OAuth2Client } = require('google-auth-library');

//REGISTER
const createTransporter = async () => {
  const oauth2Client = new OAuth2Client(
      process.env.GOOGLE_MAIL_CLIENT_ID,
      process.env.GOOGLE_MAIL_CLIENT_SECRET,
      "https://developers.google.com/oauthplayground"  
  ); 
  
  oauth2Client.setCredentials({
      refresh_token: process.env.GOOGLE_MAIL_REFRESH_TOKEN
  });

  const accessToken = await new Promise((resolve, reject) => {
      oauth2Client.getAccessToken((err, token) => {
        if (err) {
          reject("Failed to create access token :(");
        }
        resolve(token);
      });
  });

  const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        type: "OAuth2",
        user: process.env.GOOGLE_EMAIL,
        accessToken,
        clientId: process.env.GOOGLE_MAIL_CLIENT_ID,
        clientSecret: process.env.GOOGLE_MAIL_CLIENT_SECRET,
        refreshToken: process.env.GOOGLE_MAIL_REFRESH_TOKEN
      }
  });

  return transporter;
};


const sendEmail = async (emailOptions) => {
  try {
      let emailTransporter = await createTransporter();
      await emailTransporter.sendMail(emailOptions);  
  } catch (error) {
      console.log(error);
  }
};

router.post('/register', async (req, res) => {
  const { username, email, password} = req.body;
  if (!username || !email || !password) {
    return res.status(422).json({ error: "Please filled the form properly" })
  }
  const userExist = await User.findOne({ email: email });
  try {
    if (userExist) {
      return res.status(201).json({ message: "User already exisit." })
    }
    else {

      const data = new User({
        username: req.body.username,
        email: req.body.email,
        password: CryptoJS.AES.encrypt(
          req.body.password,
          process.env.PASS_SEC
        ).toString(),
        accountVerified: false,
      });

      await data.save();

      const newUser = await User.findOne({ email: email });

      let token = await newUser.generateAuthToken();

      const url = `http://localhost:5000/api/auth/verify/${token}`


      sendEmail({
        subject: "Verify Account",
        from: process.env.GOOGLE_EMAIL,
        to: email,
        text: "I am sending an email from nodemailer!",
        html: `Click <a href = '${url}'>here</a> to confirm your email.`
      });

      res.status(201).json({ message: `An Email has been sent to your account : ${email} please verify` });
    }

  } catch (error) {
    res.status(500).send(error.message);
    console.log(error);
  }
});


router.get('/verify/:token', async(req, res)=>{
  const {token} = req.params
 
  if(!token){
      return res.status(4222).send({message: "Token not found"});
  }

  try{
  
      let payload = jwt.verify(token, process.env.ACCESS_TOKEN_KEY); 
  
      const user = await User.findOne({ _id: payload._id }).exec();
      if (!user) {
         return res.status(404).send({ 
            message: "User does not  exists" 
         });
      }
     
      user.accountVerified = true;
      await user.save();
      return res.status(200).send({
            message: "Account Verified"
      });
   } catch (err) {
      return res.status(500).send(err);
   }
  
}); 

//LOGIN

router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ username: req.body.username, accountVerified: true });
    !user && res.status(401).json("User does not exist or account not verified.");

    const hashedPassword = CryptoJS.AES.decrypt(
      user.password,
      process.env.PASS_SEC
    );
    const OriginalPassword = hashedPassword.toString(CryptoJS.enc.Utf8);

    OriginalPassword !== req.body.password &&
      res.status(401).json("Wrong credentials!");

    const accessToken = jwt.sign(
      {
        id: user._id,
        isAdmin: user.isAdmin,
      },
      process.env.JWT_SEC,
      { expiresIn: "3d" }
    );

    const { password, ...others } = user._doc;

    res.status(200).json({ ...others, accessToken });
  } catch (err) {
    res.status(500).json(err);
  }
});



module.exports = router;
