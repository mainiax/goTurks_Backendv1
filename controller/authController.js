const catchAsync = require('../utils/catchAsync');
const User = require('../model/userModel');
const jwt = require('jsonwebtoken');
const AppError = require('../utils/appError');
const { promisify } = require('util');

const signToken = (id) => {
	return jwt.sign({ id }, process.env.JWT_SECRET, {
		expiresIn: process.env.JWT_EXPIRES_IN,
	});
};

const createSendToken = (user, statusCode, res) => {
	//remove password from output

	const token = signToken(user._id);

	res.status(statusCode).json({
		status: 'success',
		token,
		data: { user },
	});
};

exports.signUp = catchAsync(async (req, res, next) => {
	const newUser = await User.create({
		name: req.body.name,
		email: req.body.email,
		password: req.body.password,
		passwordConfirm: req.body.passwordConfirm,
	});

	createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async function (req, res, next) {
	const { email, password } = req.body;

	if (!email || !password)
		return next(new AppError('Please provide email and password', 400));
	const user = await User.findOne({ email }).select('+password');
	console.log(user);
	if (!user || !(await user.correctPassword(password, user.password))) {
		return next(new AppError('incorrect email or password', 401));
	}

	createSendToken(user, 200, res);
});
exports.protect = catchAsync(async (req, res, next) => {
	let token;
	if (
		req.headers.authorization &&
		req.headers.authorization.startsWith('Bearer')
	) {
		token = req.headers.authorization.split(' ')[1];
	}
	if (!token) {
		return next(
			new AppError('You are not logged in, please login to get access'),
			401
		);
	}
	const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
	const mainUser = await User.findById(decoded.id);

	if (!mainUser) {
		return next(
			new AppError('The user belonging to this token does not exist', 401)
		);
	}

	if (mainUser.changedPasswordAfterTokenIssue(decoded.iat)) {
		return next(
			new AppError('User recently changed password! please log in again', 401)
		);
	}
	req.user = mainUser;

	next();
});
