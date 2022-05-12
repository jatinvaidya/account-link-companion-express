function library(user, context, callback) {
	// link user identity after verifying id token
	const linkUserIdentity = async (idToken) => {
		var ManagementClient = require("auth0@2.39.0").ManagementClient;
		var management = new ManagementClient({
			token: auth0.accessToken,
			domain: auth0.domain,
		});
		var decodedIdToken = await verifyIdToken(idToken);
		console.log(`decodedIdToken: ${decodedIdToken}`);
		var params = {
			user_id: user.user_id, //secondary user_id
			provider: user.identities[0].provider,
		};

		await management
			.linkUsers(decodedIdToken.sub, params)
			.then((user) => {
				console.log(`users linked`);
				context.primaryUser = decodedIdToken.sub;
			})
			.catch((error) => console.error(`oops: ${error}`));
	};

	// verify id token signature and binding code
	const verifyIdToken = async (token) => {
		var jwksClient = require("jwks-rsa@2.0.4");
		var client = jwksClient({
			jwksUri: `https://${auth0.domain}/.well-known/jwks.json`,
		});

		const getKey = (header, cbk) => {
			client.getSigningKey(header.kid, function (err, key) {
				var signingKey = key.publicKey || key.rsaPublicKey;
				console.log(`signingKey: ${signingKey}`);
				cbk(null, signingKey);
			});
		};
		const jwt = require("jsonwebtoken@8.5.0");
		console.log(`verifying IdToken: ${token}`);
		const promisifiedJwtVerify = require("util").promisify(jwt.verify);
		try {
			const decoded = await promisifiedJwtVerify(token, getKey);
			console.log(`[verifyIdToken] decoded: ${JSON.stringify(decoded)}`);

			// verify binding code claim
			// this is to avoid replay or injection type of attacks
			// because the id_token is posted back to rules pipeline via front channel
			// and hence ideally shouldn't be trusted without proper checks in place
			const expectedBindingCode = context.request.query.state;
			const actualBindingCode = decoded["https://example.com/binding_code"];
			if (expectedBindingCode === actualBindingCode) return decoded;
			else callback(new UnauthorizedError("invalid id_token"), user, context);
		} catch (error) {
			callback(new UnauthorizedError("invalid id_token"), user, context);
		}
	};

	// are we in a redirect callback?
	const isRedirectCallback = () => {
		return context.protocol === "redirect-callback";
	};

	// must the currently logged-in account be linked?
	const mustLinkAccountBeforeLogin = () => {
		user.app_metadada = user.app_metadata || {};
		return !!user.app_metadata.link_me && user.identities.length === 1;
	};

	// redirect to the companion app
	const redirectToCompanion = () => {
		context.redirect = {
			url: `https://${configuration.COMPANION_HOST}/secure`,
		};
	};

	// make these util functions available to the pipeline
	global.verifyIdToken = verifyIdToken;
	global.linkUserIdentity = linkUserIdentity;
	global.isRedirectCallback = isRedirectCallback;
	global.mustLinkAccountBeforeLogin = mustLinkAccountBeforeLogin;
	global.redirectToCompanion = redirectToCompanion;
	return callback(null, user, context);
}
