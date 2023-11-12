const catchAsync = require('../utils/catchAsync');
const APIFeatures = require('../utils/apiFeatures');
const AppError = require('./../utils/appError');
exports.createOne = (Model) =>
	catchAsync(async (req, res, next) => {
		const doc = await Model.create(req.body);
		res.status(201).json({
			status: 'success',
			data: {
				data: doc,
			},
		});
	});

exports.GetAll = (Model) =>
	catchAsync(async (req, res, next) => {
		const features = new APIFeatures(Model.find(), req.query)
			.filter()
			.sort()
			.limitFields()
			.paginate();
		const doc = await features.query;

		// SEND RESPONSE
		res.status(200).json({
			status: 'success',
			results: doc.length,
			data: {
				doc,
			},
		});
	});
exports.getOne = (Model, popOptions) =>
	catchAsync(async (req, res, next) => {
		console.log(req.params.id);
		let query = await Model.findById(req.params.id);
		if (popOptions) query = query.populate(popOptions);
		const doc = await query;

		if (!doc) {
			console.log('No doc found');
			return next(new AppError('no doc found with that id', 404));
		}
		res.status(200).json({
			status: 'success',
			data: {
				doc,
			},
		});
	});

exports.UpdateOne = (Model) =>
	catchAsync(async (req, res, next) => {
		const doc = await Model.findByIdAndUpdate(req.params.id, req.body, {
			new: true,
			runValidators: true,
		});
		if (!doc) {
			return next(new AppError('no doc found with that id', 404));
		}
		res.status(200).json({
			status: 'success',
			data: {
				data: doc,
			},
		});
	});
exports.deleteOne = (Model) =>
	catchAsync(async (req, res, next) => {
		const doc = await Model.findByIdAndDelete(req.params.id);

		if (!doc) {
			return next(new AppError('no document found with that id', 404));
		}
		res.status(200).json({
			status: 'success',
			message: 'Doc has been deleted',
		});
	});
