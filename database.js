// database.js (Part 1)

const Sequelize = require('sequelize');
const uuid = require('uuid');

const { get_secure_random_string, get_hashed_password } = require('./utils.js');
const constants = require('./constants.js');

const sequelize = new Sequelize(
	process.env.DATABASE_NAME,
	process.env.DATABASE_USER,
	process.env.DATABASE_PASSWORD,
	{
		host: process.env.DATABASE_HOST,
		dialect: 'postgres',
		benchmark: true,
		logging: process.env.DB_LOGGING === 'true',
		pool: {
			max: 10,
			min: 0,
			acquire: 30000,
			idle: 10000,
		},
		retry: {
			max: 3,
		},
	}
);

const Model = Sequelize.Model;

class Settings extends Model {}
Settings.init({
	id: {
		allowNull: false,
		primaryKey: true,
		type: Sequelize.UUID,
		defaultValue: uuid.v4(),
	},
	key: {
		type: Sequelize.TEXT,
		allowNull: true,
		unique: true,
	},
	value: {
		type: Sequelize.TEXT,
		allowNull: true,
	},
}, {
	sequelize,
	modelName: 'settings',
	indexes: [{
		unique: true,
		fields: ['key'],
		method: 'BTREE',
	}],
});

class PayloadFireResults extends Model {}
PayloadFireResults.init({
	id: {
		allowNull: false,
		primaryKey: true,
		type: Sequelize.UUID,
		defaultValue: uuid.v4(),
	},
	url: {
		type: Sequelize.TEXT,
		allowNull: false,
	},
	ip_address: {
		type: Sequelize.TEXT,
		allowNull: false,
	},
	referer: {
		type: Sequelize.TEXT,
		allowNull: false,
	},
	user_agent: {
		type: Sequelize.TEXT,
		allowNull: false,
	},
	cookies: {
		type: Sequelize.TEXT,
		allowNull: false,
	},
	title: {
		type: Sequelize.TEXT,
		allowNull: false,
	},
	dom: {
		type: Sequelize.TEXT,
		allowNull: false,
	},
	text: {
		type: Sequelize.TEXT,
		allowNull: false,
	},
	origin: {
		type: Sequelize.TEXT,
		allowNull: false,
	},
	screenshot_id: {
		type: Sequelize.TEXT,
		allowNull: true,
	},
	was_iframe: {
		type: Sequelize.BOOLEAN,
		allowNull: false,
	},
	browser_timestamp: {
		type: Sequelize.BIGINT,
		allowNull: false,
	},
}, {
	sequelize,
	modelName: 'payload_fire_results',
	indexes: [
		{ fields: ['url'], method: 'BTREE' },
		{ fields: ['ip_address'], method: 'BTREE' },
		{ fields: ['referer'], method: 'BTREE' },
		{ fields: ['user_agent'], method: 'BTREE' },
		{ fields: ['cookies'], method: 'BTREE' },
		{ fields: ['title'], method: 'BTREE' },
		{ fields: ['origin'], method: 'BTREE' },
		{ fields: ['was_iframe'], method: 'BTREE' },
		{ fields: ['browser_timestamp'], method: 'BTREE' },
	],
});

class CollectedPages extends Model {}
CollectedPages.init({
	id: {
		allowNull: false,
		primaryKey: true,
		type: Sequelize.UUID,
		defaultValue: uuid.v4(),
	},
	uri: {
		type: Sequelize.TEXT,
		allowNull: false,
	},
	html: {
		type: Sequelize.TEXT,
		allowNull: true,
	},
}, {
	sequelize,
	modelName: 'collected_pages',
	indexes: [
		{ fields: ['uri'], method: 'BTREE' },
	],
});

class InjectionRequests extends Model {}
InjectionRequests.init({
	id: {
		allowNull: false,
		primaryKey: true,
		type: Sequelize.UUID,
		defaultValue: uuid.v4(),
	},
	InjectionRequests.init({
	id: {
		allowNull: false,
		primaryKey: true,
		type: Sequelize.UUID,
		defaultValue: uuid.v4()
	},
	request: {
		type: Sequelize.TEXT,
		allowNull: false
	},
	injection_key: {
		type: Sequelize.TEXT,
		allowNull: false
	}
}, {
	sequelize,
	modelName: 'injection_requests',
	indexes: [
		{
			unique: true,
			fields: ['injection_key'],
			method: 'BTREE'
		}
	]
});

async function initialize_configs() {
	const session_secret_setting = await Settings.findOne({
		where: { key: constants.session_secret_key }
	});
	if (session_secret_setting) return;

	console.log(`No session secret set, generating one now...`);

	await Settings.create({
		id: uuid.v4(),
		key: constants.session_secret_key,
		value: get_secure_random_string(64)
	});

	console.log(`Session secret generated successfully!`);
}

async function setup_admin_user(password) {
	const admin_user_password = await Settings.findOne({
		where: { key: constants.ADMIN_PASSWORD_SETTINGS_KEY }
	});
	if (admin_user_password) return false;

	const bcrypt_hash = await get_hashed_password(password);
	await Settings.create({
		id: uuid.v4(),
		key: constants.ADMIN_PASSWORD_SETTINGS_KEY,
		value: bcrypt_hash
	});
	return true;
}

function get_default_user_created_banner(password) {
	return `
============================================================================
 █████╗ ████████╗████████╗███████╗███╗   ██╗████████╗██╗ ██████╗ ███╗   ██╗
██╔══██╗╚══██╔══╝╚══██╔══╝██╔════╝████╗  ██║╚══██╔══╝██║██╔═══██╗████╗  ██║
███████║   ██║      ██║   █████╗  ██╔██╗ ██║   ██║   ██║██║   ██║██╔██╗ ██║
██╔══██║   ██║      ██║   ██╔══╝  ██║╚██╗██║   ██║   ██║██║   ██║██║╚██╗██║
██║  ██║   ██║      ██║   ███████╗██║ ╚████║   ██║   ██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                           
vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
	An admin user (for the admin control panel) has been created
	with the following password:

	PASSWORD: ${password}

	XSS Hunter Express has only one user for the instance. Do not
	share this password with anyone who you don't trust. Save it
	in your password manager and don't change it to anything that
	is bruteforcable.

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
 █████╗ ████████╗████████╗███████╗███╗   ██╗████████╗██╗ ██████╗ ███╗   ██╗
██╔══██╗╚══██╔══╝╚══██╔══╝██╔════╝████╗  ██║╚══██╔══╝██║██╔═══██╗████╗  ██║
███████║   ██║      ██║   █████╗  ██╔██╗ ██║   ██║   ██║██║   ██║██╔██╗ ██║
██╔══██║   ██║      ██║   ██╔══╝  ██║╚██╗██║   ██║   ██║██║   ██║██║╚██╗██║
██║  ██║   ██║      ██║   ███████╗██║ ╚████║   ██║   ██║╚██████╔╝██║ ╚████║
╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                           
============================================================================
`;
}

async function initialize_users() {
	const new_password = get_secure_random_string(32);
	const new_user_created = await setup_admin_user(new_password);

	if (!new_user_created) return;

	const banner_message = get_default_user_created_banner(new_password);
	console.log(banner_message);
}

async function initialize_correlation_api() {
	const existing = await Settings.findOne({
		where: { key: constants.CORRELATION_API_SECRET_SETTINGS_KEY }
	});
	if (existing) return;

	const api_key = get_secure_random_string(64);
	await Settings.create({
		id: uuid.v4(),
		key: constants.CORRELATION_API_SECRET_SETTINGS_KEY,
		value: api_key
	});
}

async function database_init() {
	const force = false;

	await Promise.all([
		Settings.sync({ force }),
		PayloadFireResults.sync({ force }),
		CollectedPages.sync({ force }),
		InjectionRequests.sync({ force })
	]);

	await Promise.all([
		initialize_configs(),
		initialize_users(),
		initialize_correlation_api()
	]);
}

async function update_settings_value(settings_key, new_value) {
	const record = await Settings.findOne({ where: { key: settings_key } });
	if (record) {
		record.value = new_value;
		await record.save();
	} else {
		await Settings.create({
			id: uuid.v4(),
			key: settings_key,
			value: new_value
		});
	}
}

module.exports = {
	sequelize,
	Settings,
	PayloadFireResults,
	CollectedPages,
	InjectionRequests,
	database_init,
	update_settings_value
};