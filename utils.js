// utils.js

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const moment = require('moment');

/**
 * Deep copy of input data
 */
function copy(input_data) {
	return JSON.parse(JSON.stringify(input_data));
}

/**
 * Generate secure random alphanumeric string
 */
function get_secure_random_string(bytes_length = 32) {
	const validChars = 'abcdefghijklmnopqrstuvwxyz0123456789';
	const random = crypto.randomBytes(bytes_length);
	const mapped = Array.from(random).map(x => validChars.charCodeAt(x % validChars.length));
	return String.fromCharCode(...mapped);
}

/**
 * Return bcrypt hash of input password
 */
async function get_hashed_password(password, saltRounds = parseInt(process.env.BCRYPT_ROUNDS || '10')) {
	return bcrypt.hash(password, saltRounds);
}

/**
 * Log with readable timestamp
 */
function logit(input_string) {
	const datetime = moment().format('MMMM Do YYYY, h:mm:ss a');
	const spacer = input_string.startsWith('[') ? '' : ' ';
	console.log(`[${datetime}]${spacer}${input_string.trim()}`);
}

module.exports = {
	copy,
	get_secure_random_string,
	get_hashed_password,
	logit
};