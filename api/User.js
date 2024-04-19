const express = require("express");
const router = express.Router();

// mongodb user model
const User = require("./../models/User");

// mongodb user Verification model
const UserVerification = require("./../models/UserVerification");

// mongodb user otp Verification model
const UserOtpVerification = require("./../models/UserOtpVerification");

//email handler
const nodermailer = require("nodemailer");

//unique string(Uid)
const { v4: uuidv4 } = require("uuid");

//environment variables
require("dotenv").config();

//path for static verified page
const path = require("path");

//nodemailer
let transporter = nodermailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  },
});

//testing
transporter.verify((error, success) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Ready for message");
    console.log(success);
  }
});

// Password handlers
const bcrypt = require("bcrypt");
const { error } = require("console");

// For Signup Part
router.post("/signup", (req, res) => {
  let { name, email, password } = req.body;
  name = name.trim();
  email = email.trim();
  password = password.trim();
  if (name == "" || email == "" || password == "") {
    res.json({
      status: "Failed",
      message: "Empty input fields!",
    });
  } else if (!/^[a-zA-Z ]*$/.test(name)) {
    res.json({
      status: "Failed",
      message: "Invalid name entered!",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    res.json({
      status: "Failed",
      message: "Invalid email entered!",
    });
  } else if (password.length < 8) {
    res.json({
      status: "Failed",
      message: "Password is too short!",
    });
  } else {
    // checking if user already exists
    User.find({ email })
      .then((result) => {
        if (result.length) {
          // The user already exists
          res.json({
            status: "Failed",
            message: "User with the provided email already exists!",
          });
        } else {
          // try to create a new user

          // password handling
          const saltRounds = 10;
          bcrypt
            .hash(password, saltRounds)
            .then((hashedPassword) => {
              const newUser = new User({
                name,
                email,
                password: hashedPassword,
                verified: false,
              });
              newUser
                .save()
                .then((result) => {
                  //handle account verification
                  //sendVerificationEmail(result, res);
                  sendOtpVerificationEmail(result, res);
                })
                .catch((err) => {
                  console.log(err);
                  res.json({
                    status: "Failed",
                    message: "An error occurred while saving user account!",
                  });
                });
            })
            .catch((err) => {
              res.json({
                status: "Failed",
                message: "An error occurred while hashing password!",
              });
            });
        }
      })
      .catch((err) => {
        console.error(err);
        res.json({
          status: "Failed",
          message: "An error occurred while checking for existing user!",
        });
      });
  }
});

//send otp verification email
const sendOtpVerificationEmail = async ({ _id, email }, res) => {
  try {
    const otp = `${Math.floor(1000 + Math.random() * 9000)}`;

    //mail options
    const mailOptions = {
      from: process.env.AUTH_EMAIL,
      to: email,
      subject: "Verify Your Email",
      html: `<p>Enter <b>${otp}</b> to verify your email .</p>
      <p>This otp <b>expires in 1 hours</b></p>`,
    };

    // hash the otp

    const saltRounds = 10;
    const hashedOtp = await bcrypt.hash(otp, saltRounds);
    const newOtpVerification = await new UserOtpVerification({
      userId: _id,
      otp: hashedOtp,
      createdAt: Date.now(),
      expiresAt: Date.now() + 3600000,
    });

    // save otp record
    await newOtpVerification.save();
    await transporter.sendMail(mailOptions);
    res.json({
      status: "Pending",
      message: "Verificaiton otp sent",
      data: {
        userId: _id,
        email,
      },
    });
  } catch (error) {
    res.json({
      status: "Failed",
      message: error.message,
    });
  }
};

//verify otp
router.post("/verifyOtp", async (req, res) => {
  try {
    let { userId, otp } = req.body;
    if (!userId || !otp) {
      throw Error("Empty Otp details are not allowed");
    } else {
      const UserOtpverificationRecords = await UserOtpVerification.find({
        userId,
      });
      if (UserOtpverificationRecords.length <= 0) {
        //no record found
        throw new Error(
          "Account record doesn't exist or has been already verified."
        );
      } else {
        //otp record exists
        const { expiresAt } = UserOtpverificationRecords[0];
        const hashedOtp = UserOtpverificationRecords[0].otp;

        if (expiresAt < Date.now()) {
          //user otp record has expired
          await UserOtpVerification.deleteMany({ userId });
          throw new Error("Code has expired.Try again.");
        } else {
          const validOtp = await bcrypt.compare(otp, hashedOtp);

          if (!validOtp) {
            //entered otp is wrong
            throw new Error("Invaild otp. Try again");
          } else {
            //success
            await User.updateOne({ _id: userId }, { verified: true });
            await UserOtpVerification.deleteMany({ userId });
            res.json({
              status: "Verified",
              message: `User email verified Successfully.`,
            });
          }
        }
      }
    }
  } catch (error) {
    res.json({
      status: "Failed",
      message: error.message,
    });
  }
});

//resend verification
router.post("/resendOtpVerificationCode", async (req, res) => {
  try {
    let { userId, email } = req.body;

    if (!userId || !email) {
      throw Error("Empty user details are not allowed");
    } else {
      //delete existing records and resend
      await UserOtpVerification.deleteMany({ userId });
      sendOtpVerificationEmail({ _id: userId, email }, res);
    }
  } catch (error) {
    res.json({
      status: "Failed",
      message: error.message,
    });
  }
});

// Signin
router.post("/signin", (req, res) => {
  // Implement signin logic here
  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (email == "" || password == "") {
    res.json({
      status: "Failed",
      message: "Credentials Field Empty!",
    });
  } else {
    //check if existing User
    User.find({ email })
      .then((data) => {
        if (data.length) {
          //User exists

          //check if user is verified
          if (!data[0].verified) {
            res.json({
              status: "FAILED!!",
              message: "Email hasn't been verified yet. Check your email.",
            });
          } else {
            const hashedPassword = data[0].password;
            bcrypt
              .compare(password, hashedPassword)
              .then((result) => {
                if (result) {
                  // Password Matches
                  // Generate JWT token
                  const token = jwt.sign(
                    { userId: data[0]._id },
                    process.env.JWT_SECRET,
                    { expiresIn: "1h" }
                  );

                  res.json({
                    status: "SUCCESS!",
                    message: "Signin Successful",
                    token: token, // Send JWT token to the client
                    data: data,
                  });
                } else {
                  res.json({
                    status: "FAILED!!",
                    message: "Entered Invalid Password",
                  });
                }
              })
              .catch((err) => {
                res.json({
                  status: "FAILED",
                  message: "An Error Occured while comparing passwords",
                });
              });
          }
        } else {
          res.json({
            status: "FAILED",
            message: "Invalid Credentials Entered",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "FAILED",
          message: "An Error Occured while checking for existing user",
        });
      });
  }
});

// Middleware function to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    return res.status(403).json({ message: "No token provided." });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Failed to authenticate token." });
    }
    req.userId = decoded.userId;
    next();
  });
};

// GET request endpoint to retrieve user information
router.get("/user", verifyToken, (req, res) => {
  // Find user by userId obtained from the decoded token
  User.findById(req.userId)
    .then((user) => {
      if (!user) {
        return res.status(404).json({ message: "User not found." });
      }
      res.json({ status: "SUCCESS", data: user });
    })
    .catch((err) => {
      res
        .status(500)
        .json({ status: "FAILED", message: "Internal Server Error." });
    });
});

module.exports = router;
