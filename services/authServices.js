const crypto = require("crypto");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const ApiError = require("../utils/ApiError");
const UserAuthorization = require("../utils/UserAuthorization");
const sendEmail = require("../utils/sendEmail");
const createToken = require("../utils/createToken");

const User = require("../models/userModel");

// @desc    User Register,login with Google
// @route   POST /api/v1/auth/google
// @access  Public
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      passReqToCallback: true,
    },
    asyncHandler(async (req, accessToken, refreshToken, profile, done) => {
      // Find a user by google.id or email in the database
      let existingUser = await User.findOne({
        $or: [{ "google.id": profile.id }, { email: profile.emails[0].value }],
      });

      console.log("profile", profile);

      if (existingUser) {
        // Check if the user has logged in with Google before
        if (!existingUser.google || !existingUser.google.id) {
          // The user exists by email but hasn't logged in with Google before, so update the record
          await User.updateOne(
            { _id: existingUser._id }, // filter
            {
              // update
              $set: {
                "google.id": profile.id,
                "google.email": profile.emails[0].value,
                isOAuthUser: true,
              },
            }
          );
          // After update, it's a good idea to refresh the existingUser object if you plan to use it right after
          existingUser = await User.findById(existingUser._id);
        }
        // Generate a JWT for the (possibly updated) existing user
        const token = createToken(existingUser._id);
        return done(null, { user: existingUser, token }); // Include token in the user object
      }
      // No user exists by Google ID or email, create a new user
      const newUser = await User.create({
        username: profile.displayName,
        email: profile.emails[0].value,
        google: {
          id: profile.id,
          email: profile.emails[0].value,
        },
        isOAuthUser: true,
      });
      const token = createToken(newUser._id);
      done(null, { user: newUser, token }); // Include token in the user object
    })
  )
);

// @desc    User Register
// @route   POST /api/v1/auth/signup
// @access  Public
exports.signup = asyncHandler(async (req, res, next) => {
  // 1- create user
  const user = await User.create({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password,
  });
  // 2- Creat token
  const token = createToken(user._id);
  res.status(201).json({ data: user, token });
});

// @desc    User Login
// @route   POST /api/v1/auth/login
// @access  Public
exports.login = asyncHandler(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user.password) {
    return next(new ApiError("incorrect password or email", 401));
  }
  if (!user || !bcrypt.compareSync(req.body.password, user.password)) {
    return next(new ApiError("Incorrect email or password", 401));
  }

  const token = createToken(user._id);
  res.status(200).json({ data: user, token });
});

// @desc  make sure the user is logged in
exports.protect = asyncHandler(async (req, res, next) => {
  const userAuthorization = new UserAuthorization();

  const token = userAuthorization.getToken(req.headers.authorization);
  const decoded = userAuthorization.tokenVerifcation(token);
  const currentUser = await userAuthorization.checkCurrentUserExist(decoded);
  userAuthorization.checkCurrentUserIsActive(currentUser);
  userAuthorization.checkUserChangeHisPasswordAfterTokenCreated(
    currentUser,
    decoded
  );

  req.user = currentUser;
  next();
});

//@desc  Authorization (User Permissions)
exports.allowTo = (...roles) =>
  asyncHandler(async (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new ApiError("you are not allowed to access this router", 403)
      );
    }
    next();
  });

// @desc    Forgot password
// @route   POST /api/v1/auth/forgotpassword
// @access  Public
exports.forgotPassword = asyncHandler(async (req, res, next) => {
  //1) Get user by email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(
      new ApiError(`No user for this email : ${req.body.email}`, 404)
    );
  }
  //2) If user exists, Generate hash rest random 6 digits.
  const resetCode = Math.floor(100000 + Math.random() * 900000).toString();

  const hashResetCode = crypto
    .createHash("sha256")
    .update(resetCode)
    .digest("hex");

  // Save hashedRestCode in db
  user.passwordResetCode = hashResetCode;
  user.passwordResetExpires = Date.now() + 10 * 60 * 1000;
  user.passwordResetVerified = false;

  await user.save();

  const message = `Hi ${user.username},
   \n We received a request to reset the passwrd on your E-shop Account .
    \n ${resetCode} \n Enter this code to complete the reset.
    \n Thanks for helping us keep your account secure.
     \n  the E-webstite Team`;

  // 3-Send reset code via email
  try {
    await sendEmail({
      email: user.email,
      subject: "Your Password Reset Code (Valid For 10 min)",
      message,
    });
  } catch (err) {
    user.passwordResetCode = undefined;
    user.passwordResetExpires = undefined;
    user.passwordResetVerified = undefined;

    await user.save();
    return next(new ApiError("There is an error in sending email", 500));
  }
  res
    .status(200)
    .json({ status: "Success", message: "Reset Code send to email " });
});

// @desc    verify Password Reset Code
// @route   POST /api/v1/auth/verifyResetCode
// @access  Public
exports.verifyPassResetCode = asyncHandler(async (req, res, next) => {
  // 1- Get user baed on reset code
  const hashResetCode = crypto
    .createHash("sha256")
    .update(req.body.resetCode.toString())
    .digest("hex");

  const user = await User.findOne({
    passwordResetCode: hashResetCode,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new ApiError("Reset Code invalid or expired", 422));
  }
  //2) resetcode valid
  user.passwordResetVerified = true;
  await user.save();

  res.status(200).json({
    status: "success",
  });
});

// @desc     Reset Password
// @route   PUT /api/v1/auth/resetPassword
// @access  Public
exports.resetPassword = asyncHandler(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(
      new ApiError(`No user for this email : ${req.body.email}`, 404)
    );
  }
  if (!user.passwordResetVerified) {
    return next(new ApiError("Reset code not verified", 400));
  }
  user.password = req.body.newPassword;
  user.passwordResetCode = undefined;
  user.passwordResetExpires = undefined;
  user.passwordResetVerified = undefined;

  await user.save();

  //3) if every thing is okay, generate token
  const token = createToken(user._id);
  res.status(200).json({ token });
});
