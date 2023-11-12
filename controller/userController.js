const User = require('../model/userModel');
const AppError = require('../utils/appError');
const factory = require('./handlerFactory');

//do not update passwords with this
exports.UpdateUser = factory.UpdateOne(User);
exports.DeleteUser = factory.deleteOne(User);
exports.getUser = factory.getOne(User);
exports.GetAllUsers = factory.GetAll(User);
exports.CreateUser = factory.createOne(User);
