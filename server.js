// server.js

'use strict';

const get_app_server = require('./app.js');
const { database_init } = require('./database.js');

const startServer = async () => {
	if (!process.env.SSL_CONTACT_EMAIL) {
		console.error(`[ERROR] The environment variable 'SSL_CONTACT_EMAIL' is not set. Please set it.`);
		process.exit(1);
	}

	try {
		await database_init();
		const app = await get_app_server();

		require('greenlock-express')
			.init({
				packageRoot: __dirname,
				configDir: './greenlock.d',
				cluster: false,
				maintainerEmail: process.env.SSL_CONTACT_EMAIL,
			})
			.serve(app);
	} catch (err) {
		console.error(`[FATAL] Failed to start server:`, err);
		process.exit(1);
	}
};

// Start the server
startServer();