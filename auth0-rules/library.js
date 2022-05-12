function library(user, context, callback) {
	const linkUserIdentity = async (idToken) => {
		var ManagementClient = require("auth0@2.39.0").ManagementClient;
		var management = new ManagementClient({
			token: auth0.accessToken,
			domain: auth0.domain,
		});
		var decodedIdToken = verifyIdToken(idToken);
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

	const verifyIdToken = (token) => {
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
		console.log(`verifying IdToken`);
		return jwt.verify(token, getKey, {}, function (err, decoded) {
			if (!!err) {
				console.log(`err: ${err}`);
				return callback(
					new UnauthorizedError("invalid id_token"),
					user,
					context
				);
			} else {
				// signature is valid, now verify the binding code
				// this will prevent token-replay token-injection kind of attacks
				// this protection is recommended because we are passing the token over the front-channel
				console.log(`decoded.sub: ${decoded}`);
				const expectedBindingCode = context.request.query.state;
				const actualBindingCode = decoded.binding_code;
				if (expectedBindingCode === actualBindingCode) return decoded;
				else
					return callback(
						new UnauthorizedError("invalid id_token"),
						user,
						context
					);
			}
		});
	};

	const isRedirectCallback = () => {
		return context.protocol === "redirect-callback";
	};

	const mustLinkAccountBeforeLogin = () => {
		user.app_metadada = user.app_metadata || {};
		return !!user.app_metadata.link_me && user.identities.length === 1;
	};

	const redirectToCompanion = () => {
		context.redirect = {
			url: `https://${configuration.COMPANION_HOST}/secure`,
		};
	};

	global.verifyIdToken = verifyIdToken;
	global.linkUserIdentity = linkUserIdentity;
	global.isRedirectCallback = isRedirectCallback;
	global.mustLinkAccountBeforeLogin = mustLinkAccountBeforeLogin;
	global.redirectToCompanion = redirectToCompanion;
	return callback(null, user, context);
}
