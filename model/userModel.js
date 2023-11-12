const mongoose = require('mongoose');
const slugify = require('slugify');
const validator = require('validator');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
	name: {
		type: String,
		required: [true, 'Please tell us your name!'],
	},
	email: {
		type: String,
		required: [true, 'Please provide your email'],
		unique: true,
		lowercase: true,
		validate: [validator.isEmail, 'Please provide a valid email'],
	},
	// photo: String,
	role: {
		type: String,
		enum: ['user', 'guide', 'lead-guide', 'admin'],
		default: 'user',
	},
	password: {
		type: String,
		required: [true, 'Please provide a password'],
		minlength: 8,
		select: false,
	},
	passwordConfirm: {
		type: String,
		required: [true, 'Please confirm your password'],
		validate: {
			// This only works on CREATE and SAVE!!!
			validator: function (el) {
				return el === this.password;
			},
			message: 'Passwords are not the same!',
		},
	},
	createdAt: {
		type: Date,
		default: Date.now(),
		select: false,
	},
	passwordChangedAt: Date,
});
//hashPassword after save
userSchema.pre('save', async function (next) {
	if (!this.isModified('password')) return next();
	this.password = await bcrypt.hash(this.password, 12);
	this.passwordConfirm = undefined;
	next();
});

userSchema.methods.correctPassword = async function (
	candidatePassword,
	userPassword
) {
	return await bcrypt.compare(candidatePassword, userPassword);
};
userSchema.methods.changedPasswordAfterTokenIssue = function (JWTTimeStamp) {
	if (this.passwordChangedAt) {
		const changedTimestamp = parseInt(
			this.passwordChangedAt.getTime() / 1000,
			10
		);
		return JWTTimeStamp < changedTimestamp;
	}
	return false;
};
const UserModel = mongoose.model('Users_v1', userSchema);

module.exports = UserModel;
