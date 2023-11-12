const express = require('express');
const userRouter = express.Router();
const userController = require('./../controller/userController');
const { signUp, login, protect } = require('../controller/authController');

const { GetAllUsers, getUser, DeleteUser, UpdateUser, CreateUser } =
	userController;

userRouter.post('/signup', signUp);
userRouter.post('/login', login);
// Routes for the User resource

userRouter.use(protect);

// Route to get a list of all users
userRouter.get('/', GetAllUsers);

// Route to get a single user by id
userRouter.get('/:id', getUser);

// Route to update a user by id
userRouter.patch('/:id', UpdateUser);

// Route to delete a user by id
userRouter.delete('/:id', DeleteUser);

//route to create users
userRouter.post('/', CreateUser);

//signUp user

module.exports = userRouter;
