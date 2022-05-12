const express = require("express");
const { auth } = require("express-openid-connect");
const fetch = require("node-fetch");
require("dotenv").config();

const config = {
	authRequired: false,
	auth0Logout: true,
	baseURL: process.env.BASE_URL,
	clientID: process.env.CLIENT_ID,
	issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
	secret: process.env.COOKIE_SECRET,
};

// init app
const app = express();

// auth router attaches /login, /logout, and /callback routes to the baseURL
app.use(auth(config));

// templating
app.set("view engine", "pug");

// modify requiresAuth to support query params on Authorization Request
const requiresAuthWithParam = (req, res, next) => {
	if (!req.oidc.isAuthenticated()) {
		return res.oidc.login({
			authorizationParams: { binding_code: req.query["state"] },
		});
	}
	next();
};

app.get("/", (req, res) => {
	res.send(
		req.oidc.isAuthenticated() ? "Authenticated" : "UnAuthenticated/Logged out"
	);
});

// enforce authentication and post id_token back
app.get("/secure", requiresAuthWithParam, (req, res) => {
	res.render("./views/form-post", {
		continue_endpoint: `https://${process.env.AUTH0_DOMAIN}/continue?state=${req.query.state}`,
		id_token: req.oidc.idToken,
	});
});

// dummy local dev
app.listen(3000, () => {
	console.log(`Example app listening on port 3000`);
});
