import * as jose from "jose";

const issuer = "https://aabedraba.eu.auth0.com/"; // Auth0 origin.
const audience = "https://kusk-jwt-api"; // Auth0 client id.

export default {
  async fetch(request: Request): Promise<Response> {
    const bearerToken = request.headers.get("Authorization");

    if (bearerToken === null) {
      return new Response("Unauthorized", { status: 401 });
    }

    const token = bearerToken.split(" ")[1];

    const JWKS = jose.createRemoteJWKSet(
      new URL("https://aabedraba.eu.auth0.com/.well-known/jwks.json")
    );

    try {
      const { payload, protectedHeader } = await jose.jwtVerify(token, JWKS, {
        issuer,
        audience,
      });

      return new Response(JSON.stringify({ payload, protectedHeader }));
    } catch (error) {
      return new Response("Unauthorized", { status: 401 });
    }
  },
};
