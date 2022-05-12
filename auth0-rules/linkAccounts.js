async function linkAccounts(user, context, callback) {
	user.app_metadata = user.app_metadata || {};
	if (global.mustLinkAccountBeforeLogin() && !global.isRedirectCallback()) {
		// simulating unverified SingPass identity
		// proceed to link social identity with DB identity
		// do not establish any matching based on email etc.
		// just link to the DB identity user authenticates with.
		global.redirectToCompanion();
	} else if (global.isRedirectCallback()) {
		// resume original authorization request
		// we are expecting id_token in as form post
		context.request.body = context.request.body || {};
		let idToken = context.request.body.id_token;
		if (!!idToken) {
			// verify id_token and link identity
			await global.linkUserIdentity(idToken);
		} else {
			return callback(
				new UnauthorizedError(
					"Account Linking Failed: Missing id_token of Primary Account"
				),
				user,
				context
			);
		}
	} else if (
		context.clientID === configuration.COMPANION_CLIENT_ID &&
		!global.isRedirectCallback()
	) {
		// we are here after authenticating the primary identity (i.e. non SingPass identity)
		// we are expecting a custom query-param called binding_code
		// the value of the binding_code is the redirect state from the redirect to companion-app
		context.request.query = context.request.query || {};
		const bindingCode = context.request.query.binding_code;
		console.log(`enhance id_token with binding_code claim: ${bindingCode}`);
		if (!bindingCode)
			return callback(
				new UnauthorizedError("invalid or no binding code"),
				user,
				context
			);
		context.idToken["https://example.com/binding_code"] = bindingCode;
	}
	return callback(null, user, context);
}
