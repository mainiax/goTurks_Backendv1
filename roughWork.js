const nodemailer = require('nodemailer');
const sendEmail = async (options) => {
	//1 create a trnsporter
	const transporter = nodemailer.createTransport({
		host: process.env.EMAIL_HOST,
		port: process.env.EMAIL_PORT,
		auth: {
			user: process.env.EMAIL_USERNAME,
			pass: process.env.EMAIL_PASSWORD,
		},
	});
	//2 define the email options
	const mailOptions = {
		from: 'Mainiax Mainiax <hell@jonas.io>',
		to: options.email,
		subject: options.subject,
		text: options.message,
	};

	await transporter.sendMail(mailOptions);
};
module.exports = sendEmail;
const { promisify } = require('util');
const User = require('./../model/userModel');
const catchAsync = require('../utils/catchAsync');
const jwt = require('jsonwebtoken');
const AppError = require('../utils/appError');

const sendEmail = require('./../utils/email');
const crypto = require('crypto');

const signToken = (id) => {
	return jwt.sign({ id }, process.env.JWT_SECRET, {
		expiresIn: process.env.JWT_EXPIRES_IN,
	});
};
const createSendToken = (user, statusCode, res) => {
	const token = signToken(user._id);
	const cookieOptions = {
		expires: new Date(
			Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
		),
		secure: true,
		httpOnly: true,
	};
	if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;
	res.cookie('jwt', token, cookieOptions);
	//remove password from output
	user.password = undefined;
	res.status(statusCode).json({
		status: 'success',
		token,
		user,
	});
};
exports.signUp = catchAsync(async (req, res, next) => {
	// const newUser = await User.create({
	//   name: req.body.name,
	//   email: req.body.email,

	//   password: req.body.password,
	//   passwordConfirm: req.body.passwordConfirm,
	//   passwordChangedAt: req.body.passwordChangedAt,
	// });
	const newUser = await User.create(req.body);

	createSendToken(newUser, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
	const { email, password } = req.body;
	////////////////////////////////////
	if (!email || !password) {
		next(new AppError('Please provide email and password', 400));
	}
	///////////////////////////////////

	const user = await User.findOne({ email }).select('+password');

	if (!user || !(await user.correctPassword(password, user.password))) {
		return next(new AppError('Incorrect email or password'), 400);
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
			new AppError('You are not logged in, please login to get access')
		);
	}

	//2 verification token
	const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

	//3check if user still exist
	const freshUser = await User.findById(decoded.id);
	if (!freshUser)
		return next(
			new AppError('The user belonging to this token does not exist', 401)
		);
	//check if user changed password after the token was issued
	if (freshUser.changedPasswordAfter(decoded.iat))
		return next(new AppError('user recently changed password', 401));
	//grant access to protected route
	req.user = freshUser;
	next();
});
//restriction by role
exports.restrictTo = (...roles) => {
	return (req, res, next) => {
		if (!roles.includes(req.user.role)) {
			return next(
				new AppError('You do not have permission to perform this action', 403)
			);
		}
		next();
	};
};
exports.ForgotPassword = catchAsync(async (req, res, next) => {
	//get user based on posted email
	const user = await User.findOne({ email: req.body.email });
	if (!user) {
		return next(new AppError('There is no user with the email address', 404));
	}
	//generate random token
	const resetToken = user.createPasswordResetToken();
	await user.save({ validateBeforeSave: false });

	//send it to user email
	const resetUrl = `${req.protocol}://${req.get(
		'host'
	)}/api/v1/users/resetPassword/${resetToken}`;
	const message = `Forgot your password? submit a patch request with your new password and passwordconfirm to:${resetUrl}\n if you didn't forget your password please ignore this`;
	try {
		await sendEmail({
			email: user.email,
			subject: 'your password reset token (valid for 10 min)',
			message,
		});
		res.status(200).json({
			status: 'success',
			message: 'Token sent to email',
		});
	} catch (err) {
		user.passwordResetToken = undefined;
		user.passwordResetExpires = undefined;
		await user.save({ validateBeforeSave: false });
		return next(
			new AppError('There was an error sending the mail try again later', 500)
		);
	}
});
exports.resetPassword = catchAsync(async (req, res, next) => {
	//1) get user based on the token
	console.log(req.params.token);
	const hashedToken = crypto
		.createHash('sha256')
		.update(req.params.token)
		.digest('hex');
	//find the user for token and checking if it has not expired
	const user = await User.findOne({
		passwordResetToken: hashedToken,
		passwordResetExpires: { $gt: Date.now() },
	});
	//2) if token has not expired and there is user set the new password
	if (!user) {
		return next(new AppError('Token is invalid or has expired', 400));
	}
	//updating the user password
	user.password = req.body.password;
	user.passwordConfirm = req.body.passwordConfirm;
	user.passwordResetToken = undefined;
	user.passwordResetExpires = undefined;
	await user.save();
	//3)update changePasswordAt property for the user

	//4) log user in send jwt
	createSendToken(user, 200, res);
});
exports.updatePassword = catchAsync(async (req, res, next) => {
	// 1) Get user from collection
	const user = await User.findById(req.user.id).select('+password');

	// 2) Check if POSTed current password is correct
	if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
		return next(new AppError('Your current password is wrong.', 401));
	}

	// 3) If so, update password
	user.password = req.body.password;
	user.passwordConfirm = req.body.passwordConfirm;
	await user.save();
	// User.findByIdAndUpdate will NOT work as intended!

	// 4) Log user in, send JWT
	createSendToken(user, 200, res);
});
///creating schema
const crypto = require('crypto');
const mongoose = require('mongoose');
const slugify = require('slugify');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const userSchema = new mongoose.Schema({
	name: {
		type: String,
		required: [true, 'A user must have a name'],
	},
	email: {
		type: String,
		required: [true, 'A User must have an email'],
		unique: true,
		lowercase: true,
		validate: [validator.isEmail, 'Please provide a valid email'],
	},
	photo: String,
	password: {
		type: String,
		required: [true, 'please provide a password'],
		minlength: 8,
		select: false,
	},
	role: {
		type: String,
		enum: ['user', 'guide', 'lead-guide', 'admin'],
		default: 'user',
	},
	passwordConfirm: {
		type: String,
		required: [true, 'Please confirm password'],
		validate: {
			//this only works on save
			validator: function (el) {
				return el === this.password;
			},
			message: 'passwords are not the same',
		},
	},
	active: {
		type: Boolean,
		default: true,
		select: false,
	},
	passwordChangedAt: Date,
	passwordResetToken: String,
	passwordResetExpires: Date,
});

userSchema.pre('save', async function (next) {
	//only run this function if password was actually mdofified
	if (!this.isModified('password')) return next();
	//hash the password with cost of 12
	this.password = await bcrypt.hash(this.password, 12);
	//delete confirmed password
	this.passwordConfirm = undefined;
	next();
});
//to update password time stamp after it has been reset
userSchema.pre('save', function (next) {
	if (!this.isModified('password') || this.isNew) return next();
	//update happening here
	this.passwordChangedAt = Date.now() - 2000;
	next();
});
userSchema.methods.correctPassword = async function (
	candidatePassword,
	userPassword
) {
	return bcrypt.compare(candidatePassword, userPassword);
};
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
	if (this.passwordChangedAt) {
		const changedTimestamp = parseInt(
			this.passwordChangedAt.getTime() / 1000,
			10
		);

		return JWTTimestamp < changedTimestamp;
	}

	// False means NOT changed
	return false;
};
userSchema.pre(/^find/, function (next) {
	//this points to the current query
	this.find({ active: { $ne: false } });
	next();
});
//password reset functionality
userSchema.methods.createPasswordResetToken = function () {
	const resetToken = crypto.randomBytes(32).toString('hex');
	this.passwordResetToken = crypto
		.createHash('sha256')
		.update(resetToken)
		.digest('hex');
	console.log({ resetToken }, this.passwordResetToken);
	this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
	return resetToken;
};

const UserModel = mongoose.model('User1', userSchema);
module.exports = UserModel;
