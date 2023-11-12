const dotenv = require('dotenv');
dotenv.config({ path: './config.env' });
const app = require('./app');
const mongoose = require('mongoose');

const DB = process.env.DATABASE.replace(
	'<PASSWORD>',
	process.env.DATABASE_PASSWORD
).replace('<DATABASE_NAME>', process.env.DBNAME);

mongoose.set('strictQuery', false);

(async () => {
	try {
		const con = await mongoose.connect(DB, {
			useNewUrlParser: true,
			useUnifiedTopology: true,
		});
		console.log('Database Connected');
		// You can proceed with other operations that depend on the database connection here.
	} catch (error) {
		console.error('Database Connection Error:', error);
		// Handle the error as needed.
	}
})();

const port = process.env.PORT || 3000;

app.listen(port, () => {
	console.log(`app running on port ${port}...`);
});
