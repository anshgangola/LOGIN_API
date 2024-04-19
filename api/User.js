const express = require("express");
const router = express.Router();

// mongoose user model
const User = require("./../models/User");

// Password handlers
const bcrypt = require("bcrypt");

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
              });
              newUser
                .save()
                .then((result) => {
                  res.json({
                    status: "Success!",
                    message: "Signup successful!",
                    data: result,
                  });
                })
                .catch((err) => {
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

          const hashedPassword = data[0].password;
          bcrypt
            .compare(password, hashedPassword)
            .then((result) => {
              if (result) {
                // Password Matches
                res.json({
                  status: "SUCCESS!",
                  message: "Signin Successful",
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

module.exports = router;
