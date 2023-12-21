const mongoose = require('mongoose');
const validator = require('validator');
// Name , email , photo , password , passwordConfirm

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please tell us Your name!'],
  },
  email: {
    type: String,
    required: [true, 'Please Provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid Email!'],
  },
  photo: String,
  password: {
    type: String,
    required: true,
    minlength: [8, 'Password must atleast have 8 cahracters'],
  },
  confirmPassword: {
    type: String,
    required: [true, 'Please Provide a password'],
  },
});

const User = mongoose.model('User', userSchema);
module.exports = User;
