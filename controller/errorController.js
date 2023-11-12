const AppError = require('../utils/appError');

const handleCastErrorDB = (err) => {
	const message = `Invalid ${err.path}:${err.value}.`;
	return new AppError(message, 400);
};
const handleDuplicatefieldsDB = (err) => {
	const value = err.errmsg.match(/(["'])(\\?.)*?\1/);
	console.log(value);

	const message = `Duplicate field value: ${value}. Please use another value!`;
	return new AppError(message, 400);
};
const handleValidationErrorDb = (err) => {
	const errors = Object.values(err.errors).map((el) => el.message);

	const message = `invalid input data ${errors.join('. ')}`;
	return new AppError(message, 400);
};

const sendErrorDev = (err, res) => {
	res.status(err.statusCode).json({
		status: err.status,
		message: err.message,
		error: err,
		message: err.message,
		stack: err.stack,
	});
};
const sendErrorProduction = (err, res) => {
	if (err?.isOperational) {
		res.status(err.statusCode).json({
			status: err.status,
			message: err.message,
		});
	} else {
		console.error('Error', err);
		res.status(500).json({
			status: 'error',
			message: 'Something went wrong',
		});
	}
};
const handleJwtError = () =>
	new AppError('Invalid token, Please log in again', 401);

const handleJwtExpiredError = () =>
	new AppError('Invalid token, token expired', 401);
module.exports = (err, req, res, next) => {
	if (process.env.NODE_ENV === 'DEVELOPMENT') {
		err.statusCode = err.statusCode || 500;
		err.status = err.status || 'error';
		sendErrorDev(err, res);
	} else if (process.env.NODE_ENV === 'production') {
		let error = { ...err };
		if (error.name === 'CastError') error = handleCastErrorDB(err);
		if (error.code === 11000) error = handleDuplicatefieldsDB(err);
		if (error.name === 'validationError') error = handleValidationErrorDb(err);
		if (error.name === 'JsonWebTokenError') error = handleJwtError(err);
		if (error.name === 'TokenExpiredError') error = handleJwtExpiredError(err);
		sendErrorProduction(error, res);
	}
};
