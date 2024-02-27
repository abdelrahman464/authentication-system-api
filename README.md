<div align="center">

# Authentication System

A robust authentication system API for web applications, featuring secure user registration, login, and password management.

</div>

## Introduction

The Authentication System is designed to integrate seamlessly with any web application, providing a secure and efficient way to handle user authentication. This API supports essential features such as user registration, login, and password reset, ensuring all passwords are encrypted using advanced hashing algorithms for maximum security.

## Technologies Used

This project is built using the following technologies and tools:

- **Node.js**: A JavaScript runtime built on Chrome's V8 JavaScript engine.
- **Express**: A minimal and flexible Node.js web application framework.
- **MongoDB**: A NoSQL database for modern applications.
- **Mongoose**: An elegant MongoDB object modeling for Node.js.
- **bcryptjs**: A library to help you hash passwords securely.
- **express-rate-limit**: Basic rate-limiting middleware for Express.
- **Passport**: Simple, unobtrusive authentication for Node.js.
- **dotenv**: Loads environment variables from a `.env` file into `process.env`.
- **express-async-handler**: Middleware to handle exceptions inside of async express routes and pass them to your express error handlers.
- **express-validator**: Middleware that wraps validator.js validator and sanitizer functions.
- **jsonwebtoken**: Implementation of JSON Web Tokens.
- **morgan**: HTTP request logger middleware for node.js.
- **nodemailer**: Easy as cake e-mail sending from your Node.js applications.
- **slugify**: A JavaScript slugify library with Unicode support.

## Features

This project includes several key features:

- **User Registration**: Sign up using an email and password or through Google. Ensures email validity and password security.
- **User Login**: Sign in using email and password or Google. Incorporates security checks and rate limiting to prevent brute-force attacks.
- **Password Reset**: Offers a secure process for resetting forgotten passwords, including email verification and code validation.

## Installation Steps

Follow these steps to set up the project:

1. **Install Node.js**:
   ```
   npm init
   ```
2. **Install Dependencies**:

   - Express: `npm install express`
   - Mongoose: `npm install mongoose`
   - bcryptjs: `npm install bcryptjs`
   - And so on for each listed technology.

3. **Google Authentication Setup**:
   - Visit Google Developer Console to create a project.
   - Enable the "Google+ API" and create OAuth client ID credentials.
   - Configure the redirect URIs as needed.

## Contributing

Contributions are welcome! If you'd like to contribute, please fork the repository and submit a pull request.

## Contact

For questions or feedback, feel free to reach out at [apdomedo6@gmail.com].
