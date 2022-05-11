const express = require("express");
const { auth, requiresAuth } = require("express-openid-connect");
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

const app = express();

// auth router attaches /login, /logout, and /callback routes to the baseURL
app.use(auth(config));

// req.isAuthenticated is provided from the auth router
app.get("/", (req, res) => {
	res.send(req.oidc.isAuthenticated() ? "Logged in" : "Logged out");
});

// enforce authentication and post id_token back
app.get("/secure", requiresAuth(), async (req, res) => {
	console.log(`Redirect State: ${req.query.state}`);
	const FormData = require("form-data");
	const form = new FormData();
	form.append("id_token", req.oidc.idToken);
	fetch(
		`https://${process.env.AUTH0_DOMAIN}/continue?state=${req.query.state}`,
		{
			method: "POST",
			body: form,
		}
	);
	res.end();
});

app.listen(3000, () => {
	console.log(`Example app listening on port 3000`);
});
