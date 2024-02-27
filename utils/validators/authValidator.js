const { check } = require("express-validator");
const slugify = require("slugify");
const validatorMiddleware = require("../../middlewares/validatorMiddleware");
const User = require("../../models/userModel");

exports.signupValidator = [
  check("username")
    .custom((name, { req }) => (req.body.slug = slugify(name)))
    .notEmpty()
    .withMessage("username Required")
    .isLength({ min: 3 })
    .withMessage("Too short user name"),

  check("email")
    .notEmpty()
    .withMessage("email Required")
    .isEmail()
    .withMessage("invalid email address")
    .toLowerCase()
    .custom((val) =>
      User.findOne({ email: val }).then((email) => {
        if (email) {
          throw new Error("E-mail already exists");
        }
      })
    ),
  check("password")
    .notEmpty()
    .withMessage("Password Required")
    .isLength({ min: 8 })
    .withMessage("Too short password"),

  check("confirmPassword")
    .notEmpty()
    .withMessage("confirm Password required")
    .custom((val, { req }) => {
      if (val != req.body.password) {
        throw new Error("password Confirmation not match password");
      }
      return true;
    }),
  validatorMiddleware,
];

exports.loginValidator = [
  check("email")
    .notEmpty()
    .withMessage("email reauired")
    .isEmail()
    .withMessage("invalid email address"),
  check("password")
    .notEmpty()
    .withMessage("Password required")
    .isLength({ min: 8 })
    .withMessage("Too short password"),
  validatorMiddleware,
];
exports.forgotPasswordValidator = [
  check("email")
    .notEmpty()
    .withMessage("Email Reauired")
    .isEmail()
    .withMessage("Please enter a valid email address"),
  validatorMiddleware,
];

exports.verifyPassResetCodeValidator = [
  check("resetCode")
    .notEmpty()
    .withMessage("Reset code required")
    .isLength({ min: 6 })
    .withMessage("reset code must be 6 numbers")
    .isLength({ max: 6 })
    .withMessage("reset code must be 6 numbers"),
  validatorMiddleware,
];

exports.resetPasswordValidator = [
  check("email")
    .notEmpty()
    .withMessage("Email Reauired")
    .isEmail()
    .withMessage("Please enter a valid email address"),
  check("newPassword")
    .notEmpty()
    .withMessage("new Password required")
    .isLength({ min: 8 })
    .withMessage("Too short password"),
  validatorMiddleware,
];
