const express = require('express');
const GlobalError = require('./controller/errorController');
const app = express();
const userRouter = require('./routes/userRoutes');
const AppError = require('./utils/appError');

if (process.env.NODE_ENV == 'development') {
	app.use(morgan('dev'));
}
app.use(express.json());
app.use(express.static(`${__dirname}/public`));

app.use((req, res, next) => {
	console.log('Hello from the middleware 👋');

	next();
});

app.use((req, res, next) => {
	req.requestTime = new Date().toISOString();
	next();
});
app.use('/api/v1/users', userRouter);
app.all('*', (req, res, next) => {
	next(new AppError(`can't find ${req.originalUrl} on this server`, 400));
});
app.use(GlobalError);
module.exports = app;
