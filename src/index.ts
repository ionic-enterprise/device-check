import { SignJWT, importPKCS8 } from 'jose';
import { v4 as uuid } from 'uuid';

export interface Env {
	AUTH_KEY: string;
	TEAM_ID: string;
	KEY_ID: string;
}

export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		if (request.method != 'POST') {
			return new Response("", { status: 404 });
		}
		return await validateDeviceCheckToken(request, env);
	},
};

async function validateDeviceCheckToken(request: Request, env: Env): Promise<Response> {
	try {
		const deviceToken = await getDeviceToken(request);
		const isDevelopment = request.url.includes('development');

		if (!deviceToken) {
			return new Response("", { status: 404 });
		}

		let privateKey;
		try {
			privateKey = await importPKCS8(env.AUTH_KEY, 'ES256')
		} catch (e) {
			console.error(`Unable to create private key`, e);
			return new Response("KeyError", { status: 401 });
		}

		const jwt = await new SignJWT({ iss: env.TEAM_ID })
			.setProtectedHeader({ alg: 'ES256', kid: env.KEY_ID, typ: 'JWT' })
			.setIssuedAt()
			.setExpirationTime('12h')
			.sign(privateKey);

			// In production this should be set to false
		const environment = isDevelopment ? "api.development" : "api";
		console.log(`POST https://${environment}.devicecheck.apple.com/v1/validate_device_token`);
		console.log(`Authorization: Bearer ${jwt}`)

		const body = JSON.stringify({
			'device_token': deviceToken, // The Device Token from our Capacitor App
			'transaction_id': uuid(), // A unique transaction id
			'timestamp': Date.now()
		});
		
		// Send the request to Apple
		const res = await fetch(
			`https://${environment}.devicecheck.apple.com/v1/validate_device_token`,
			{
				method: 'POST',
				headers: {
					'Authorization': `Bearer ${jwt}`,
					'Content-Type': `application/json`
				},
				body
			});
		if (res.status == 200) {			
			const data = await res.text();
			console.log(`Success`, data);
			return new Response('Awesome!');
		} else {
			const text = await res.text();
			if (text == 'Missing or badly formatted authorization token') {
               // If you deployed your app to a device with Xcode this error may occur
			   // You need to deploy to testflight and test that way
			}
			console.error(`Failure ${res.status}`, await res.text());
			return new Response("Error", { status: 401 });
		}
	} catch (err) {
		console.error(`Exception`, err);
		return new Response("Error", { status: 401 });
	}
}

async function getDeviceToken(request: Request): Promise<string | undefined> {
	try {
		const body: any = await request.json();
		const deviceToken = body.token;
		if (!deviceToken) {
			return undefined;
		}
		return deviceToken;
	} catch {
		console.error(`Request is missing a JSON body`);
		return undefined;
	}
}