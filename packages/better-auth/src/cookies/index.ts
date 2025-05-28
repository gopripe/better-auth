import type { CookieOptions } from "better-call";
import { BetterAuthError } from "@better-auth/core/error";
import type { Session, User } from "../types";
import type { BetterAuthOptions } from "@better-auth/core";
import { getDate } from "../utils/date";
import { env, isProduction } from "@better-auth/core/env";
import { base64Url } from "@better-auth/utils/base64";
import { ms } from "ms";
import { createHMAC } from "@better-auth/utils/hmac";
import { safeJSONParse } from "../utils/json";
import { getBaseURL } from "../utils/url";
import { binary } from "@better-auth/utils/binary";
import type {
	BetterAuthCookies,
	GenericEndpointContext,
} from "@better-auth/core";

export function createCookieGetter(options: BetterAuthOptions) {
	const secure =
		options.advanced?.useSecureCookies !== undefined
			? options.advanced?.useSecureCookies
			: options.baseURL !== undefined
				? options.baseURL.startsWith("https://")
					? true
					: false
				: isProduction;
	const secureCookiePrefix = secure ? "__Secure-" : "";
	const crossSubdomainEnabled =
		!!options.advanced?.crossSubDomainCookies?.enabled;
	const domain = crossSubdomainEnabled
		? options.advanced?.crossSubDomainCookies?.domain ||
			(options.baseURL ? new URL(options.baseURL).hostname : undefined)
		: undefined;
	if (crossSubdomainEnabled && !domain) {
		throw new BetterAuthError(
			"baseURL is required when crossSubdomainCookies are enabled",
		);
	}
	function createCookie(
		cookieName: string,
		overrideAttributes: Partial<CookieOptions> = {},
	) {
		const prefix = options.advanced?.cookiePrefix || "better-auth";
		const name =
			options.advanced?.cookies?.[cookieName as "session_token"]?.name ||
			`${prefix}.${cookieName}`;

		const attributes =
			options.advanced?.cookies?.[cookieName as "session_token"]?.attributes;

		return {
			name: `${secureCookiePrefix}${name}`,
			attributes: {
				secure: !!secureCookiePrefix,
				sameSite: "lax",
				path: "/",
				httpOnly: true,
				...(crossSubdomainEnabled ? { domain } : {}),
				...options.advanced?.defaultCookieAttributes,
				...overrideAttributes,
				...attributes,
			} as CookieOptions,
		};
	}
	return createCookie;
}

export function getCookies(options: BetterAuthOptions) {
	const createCookie = createCookieGetter(options);
	const sessionMaxAge = options.session?.expiresIn || ms("7d") / 1000;
	const sessionToken = createCookie("session_token", {
		maxAge: sessionMaxAge,
	});
	const sessionData = createCookie("session_data", {
		maxAge: options.session?.cookieCache?.maxAge || 60 * 5,
	});
	const dontRememberToken = createCookie("dont_remember");
	return {
		sessionToken: {
			name: sessionToken.name,
			options: sessionToken.attributes,
		},
		/**
		 * This cookie is used to store the session data in the cookie
		 * This is useful for when you want to cache the session in the cookie
		 */
		sessionData: {
			name: sessionData.name,
			options: sessionData.attributes,
		},
		dontRememberToken: {
			name: dontRememberToken.name,
			options: dontRememberToken.attributes,
		},
	};
}

export async function setCookieCache(
	ctx: GenericEndpointContext,
	session: {
		session: Session & Record<string, any>;
		user: User;
	},
	dontRememberMe: boolean,
) {
	const shouldStoreSessionDataInCookie =
		ctx.context.options.session?.cookieCache?.enabled;

	if (shouldStoreSessionDataInCookie) {
		const filteredSession = Object.entries(session.session).reduce(
			(acc, [key, value]) => {
				const fieldConfig =
					ctx.context.options.session?.additionalFields?.[key];
				if (!fieldConfig || fieldConfig.returned !== false) {
					acc[key] = value;
				}
				return acc;
			},
			{} as Record<string, any>,
		);

		const sessionData = { session: filteredSession, user: session.user };

		const options = {
			...ctx.context.authCookies.sessionData.options,
			maxAge: dontRememberMe
				? undefined
				: ctx.context.authCookies.sessionData.options.maxAge,
		};

		const expiresAtDate = getDate(options.maxAge || 60, "sec").getTime();
		const data = base64Url.encode(
			JSON.stringify({
				session: sessionData,
				expiresAt: expiresAtDate,
				signature: await createHMAC("SHA-256", "base64urlnopad").sign(
					ctx.context.secret,
					JSON.stringify({
						...sessionData,
						expiresAt: expiresAtDate,
					}),
				),
			}),
			{
				padding: false,
			},
		);
		if (data.length > 4093) {
			ctx.context?.logger?.error(
				`Session data exceeds cookie size limit (${data.length} bytes > 4093 bytes). Consider reducing session data size or disabling cookie cache. Session will not be cached in cookie.`,
			);
			return;
		}
		ctx.setCookie(ctx.context.authCookies.sessionData.name, data, options);
	}
}

export async function setSessionCookie(
	ctx: GenericEndpointContext,
	session: {
		session: Session & Record<string, any>;
		user: User;
	},
	dontRememberMe?: boolean,
	overrides?: Partial<CookieOptions>,
) {
	const dontRememberMeCookie = await ctx.getSignedCookie(
		ctx.context.authCookies.dontRememberToken.name,
		ctx.context.secret,
	);
	// if dontRememberMe is not set, use the cookie value
	dontRememberMe =
		dontRememberMe !== undefined ? dontRememberMe : !!dontRememberMeCookie;

	const options = ctx.context.authCookies.sessionToken.options;
	const maxAge = dontRememberMe
		? undefined
		: ctx.context.sessionConfig.expiresIn;
	await ctx.setSignedCookie(
		ctx.context.authCookies.sessionToken.name,
		session.session.token,
		ctx.context.secret,
		{
			...options,
			maxAge,
			...overrides,
		},
	);

	if (dontRememberMe) {
		await ctx.setSignedCookie(
			ctx.context.authCookies.dontRememberToken.name,
			"true",
			ctx.context.secret,
			ctx.context.authCookies.dontRememberToken.options,
		);
	}
	await setCookieCache(ctx, session, dontRememberMe);
	ctx.context.setNewSession(session);
	/**
	 * If secondary storage is enabled, store the session data in the secondary storage
	 * This is useful if the session got updated and we want to update the session data in the
	 * secondary storage
	 */
	if (ctx.context.options.secondaryStorage) {
		await ctx.context.secondaryStorage?.set(
			session.session.token,
			JSON.stringify({
				user: session.user,
				session: session.session,
			}),
			Math.floor(
				(new Date(session.session.expiresAt).getTime() - Date.now()) / 1000,
			),
		);
	}
}

export function deleteSessionCookie(
	ctx: GenericEndpointContext,
	skipDontRememberMe?: boolean,
) {
	ctx.setCookie(ctx.context.authCookies.sessionToken.name, "", {
		...ctx.context.authCookies.sessionToken.options,
		maxAge: 0,
	});
	ctx.setCookie(ctx.context.authCookies.sessionData.name, "", {
		...ctx.context.authCookies.sessionData.options,
		maxAge: 0,
	});
	if (!skipDontRememberMe) {
		ctx.setCookie(ctx.context.authCookies.dontRememberToken.name, "", {
			...ctx.context.authCookies.dontRememberToken.options,
			maxAge: 0,
		});
	}
}

export function parseCookies(cookieHeader: string) {
	const cookieMap = new Map<string, string>();
	const parsedCookies = parse(cookieHeader);
	
	for (const [key, value] of Object.entries(parsedCookies)) {
		if (value !== undefined) {
			cookieMap.set(key, value);
		}
	}

	return cookieMap;
}

export type EligibleCookies = (string & {}) | (keyof BetterAuthCookies & {});

export const getSessionCookie = (
	request: Request | Headers,
	config?: {
		cookiePrefix?: string;
		cookieName?: string;
		path?: string;
	},
) => {
	if (config?.cookiePrefix) {
		if (config.cookieName) {
			config.cookiePrefix = `${config.cookiePrefix}-`;
		} else {
			config.cookiePrefix = `${config.cookiePrefix}.`;
		}
	}
	const headers = "headers" in request ? request.headers : request;
	const req = request instanceof Request ? request : undefined;
	const url = getBaseURL(req?.url, config?.path, req);
	const cookies = headers.get("cookie");
	if (!cookies) {
		return null;
	}
	const { cookieName = "session_token", cookiePrefix = "better-auth." } =
		config || {};
	const name = `${cookiePrefix}${cookieName}`;
	const secureCookieName = `__Secure-${name}`;
	const parsedCookie = parseCookies(cookies);
	const sessionToken =
		parsedCookie.get(name) || parsedCookie.get(secureCookieName);
	if (sessionToken) {
		return sessionToken;
	}

	return null;
};

export const getCookieCache = async <
	S extends {
		session: Session & Record<string, any>;
		user: User & Record<string, any>;
	},
>(
	request: Request | Headers,
	config?: {
		cookiePrefix?: string;
		cookieName?: string;
		isSecure?: boolean;
		secret?: string;
	},
) => {
	const headers = request instanceof Headers ? request : request.headers;
	const cookies = headers.get("cookie");
	if (!cookies) {
		return null;
	}
	const { cookieName = "session_data", cookiePrefix = "better-auth" } =
		config || {};
	const name =
		config?.isSecure !== undefined
			? config.isSecure
				? `__Secure-${cookiePrefix}.${cookieName}`
				: `${cookiePrefix}.${cookieName}`
			: isProduction
				? `__Secure-${cookiePrefix}.${cookieName}`
				: `${cookiePrefix}.${cookieName}`;
	const parsedCookie = parseCookies(cookies);
	const sessionData = parsedCookie.get(name);
	if (sessionData) {
		const sessionDataPayload = safeJSONParse<{
			session: S;
			expiresAt: number;
			signature: string;
		}>(binary.decode(base64Url.decode(sessionData)));
		if (!sessionDataPayload) {
			return null;
		}
		const secret = config?.secret || env.BETTER_AUTH_SECRET;
		if (!secret) {
			throw new BetterAuthError(
				"getCookieCache requires a secret to be provided. Either pass it as an option or set the BETTER_AUTH_SECRET environment variable",
			);
		}
		const isValid = await createHMAC("SHA-256", "base64urlnopad").verify(
			secret,
			JSON.stringify({
				...sessionDataPayload.session,
				expiresAt: sessionDataPayload.expiresAt,
			}),
			sessionDataPayload.signature,
		);
		if (!isValid) {
			return null;
		}
		return sessionDataPayload.session;
	}
	return null;
};

export * from "./cookie-utils";


/**
 * @source https://github.com/jshttp/cookie
 * @author blakeembrey
 * @license MIT
 */

/**
 * This is a workaround to support ESM-only environments, until `cookie` ships ESM builds.
 * @see https://github.com/jshttp/cookie/issues/211
 */

/**
 * RegExp to match cookie-name in RFC 6265 sec 4.1.1
 * This refers out to the obsoleted definition of token in RFC 2616 sec 2.2
 * which has been replaced by the token definition in RFC 7230 appendix B.
 *
 * cookie-name       = token
 * token             = 1*tchar
 * tchar             = "!" / "#" / "$" / "%" / "&" / "'" /
 *                     "*" / "+" / "-" / "." / "^" / "_" /
 *                     "`" / "|" / "~" / DIGIT / ALPHA
 */
const cookieNameRegExp = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/

/**
 * RegExp to match cookie-value in RFC 6265 sec 4.1.1
 *
 * cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
 * cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
 *                     ; US-ASCII characters excluding CTLs,
 *                     ; whitespace DQUOTE, comma, semicolon,
 *                     ; and backslash
 */
const cookieValueRegExp =
  /^("?)[\u0021\u0023-\u002B\u002D-\u003A\u003C-\u005B\u005D-\u007E]*\1$/

/**
 * RegExp to match domain-value in RFC 6265 sec 4.1.1
 *
 * domain-value      = <subdomain>
 *                     ; defined in [RFC1034], Section 3.5, as
 *                     ; enhanced by [RFC1123], Section 2.1
 * <subdomain>       = <label> | <subdomain> "." <label>
 * <label>           = <let-dig> [ [ <ldh-str> ] <let-dig> ]
 *                     Labels must be 63 characters or less.
 *                     'let-dig' not 'letter' in the first char, per RFC1123
 * <ldh-str>         = <let-dig-hyp> | <let-dig-hyp> <ldh-str>
 * <let-dig-hyp>     = <let-dig> | "-"
 * <let-dig>         = <letter> | <digit>
 * <letter>          = any one of the 52 alphabetic characters A through Z in
 *                     upper case and a through z in lower case
 * <digit>           = any one of the ten digits 0 through 9
 *
 * Keep support for leading dot: https://github.com/jshttp/cookie/issues/173
 *
 * > (Note that a leading %x2E ("."), if present, is ignored even though that
 * character is not permitted, but a trailing %x2E ("."), if present, will
 * cause the user agent to ignore the attribute.)
 */
const domainValueRegExp =
  /^([.]?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)([.][a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i

/**
 * RegExp to match path-value in RFC 6265 sec 4.1.1
 *
 * path-value        = <any CHAR except CTLs or ";">
 * CHAR              = %x01-7F
 *                     ; defined in RFC 5234 appendix B.1
 */
const pathValueRegExp = /^[\u0020-\u003A\u003D-\u007E]*$/

const __toString = Object.prototype.toString

const NullObject = /* @__PURE__ */ (() => {
  const C = function () {}
  C.prototype = Object.create(null)
  return C
})() as unknown as { new (): any }

/**
 * Parse options.
 */
export interface ParseOptions {
  /**
   * Specifies a function that will be used to decode a [cookie-value](https://datatracker.ietf.org/doc/html/rfc6265#section-4.1.1).
   * Since the value of a cookie has a limited character set (and must be a simple string), this function can be used to decode
   * a previously-encoded cookie value into a JavaScript string.
   *
   * The default function is the global `decodeURIComponent`, wrapped in a `try..catch`. If an error
   * is thrown it will return the cookie's original value. If you provide your own encode/decode
   * scheme you must ensure errors are appropriately handled.
   *
   * @default decode
   */
  decode?: (str: string) => string | undefined
}

/**
 * Parse a cookie header.
 *
 * Parse the given cookie header string into an object
 * The object has the various cookies as keys(names) => values
 */
export function parse(
  str: string,
  options?: ParseOptions
): Record<string, string | undefined> {
  const obj: Record<string, string | undefined> = new NullObject()
  const len = str.length
  // RFC 6265 sec 4.1.1, RFC 2616 2.2 defines a cookie name consists of one char minimum, plus '='.
  if (len < 2) return obj

  const dec = options?.decode || decode
  let index = 0

  do {
    const eqIdx = str.indexOf("=", index)
    if (eqIdx === -1) break // No more cookie pairs.

    const colonIdx = str.indexOf(";", index)
    const endIdx = colonIdx === -1 ? len : colonIdx

    if (eqIdx > endIdx) {
      // backtrack on prior semicolon
      index = str.lastIndexOf(";", eqIdx - 1) + 1
      continue
    }

    const keyStartIdx = startIndex(str, index, eqIdx)
    const keyEndIdx = endIndex(str, eqIdx, keyStartIdx)
    const key = str.slice(keyStartIdx, keyEndIdx)

    // only assign once
    if (obj[key] === undefined) {
      let valStartIdx = startIndex(str, eqIdx + 1, endIdx)
      let valEndIdx = endIndex(str, endIdx, valStartIdx)

      const value = dec(str.slice(valStartIdx, valEndIdx))
      obj[key] = value
    }

    index = endIdx + 1
  } while (index < len)

  return obj
}

function startIndex(str: string, index: number, max: number) {
  do {
    const code = str.charCodeAt(index)
    if (code !== 0x20 /*   */ && code !== 0x09 /* \t */) return index
  } while (++index < max)
  return max
}

function endIndex(str: string, index: number, min: number) {
  while (index > min) {
    const code = str.charCodeAt(--index)
    if (code !== 0x20 /*   */ && code !== 0x09 /* \t */) return index + 1
  }
  return min
}

/**
 * Serialize options.
 */
export interface SerializeOptions {
  /**
   * Specifies a function that will be used to encode a [cookie-value](https://datatracker.ietf.org/doc/html/rfc6265#section-4.1.1).
   * Since value of a cookie has a limited character set (and must be a simple string), this function can be used to encode
   * a value into a string suited for a cookie's value, and should mirror `decode` when parsing.
   *
   * @default encodeURIComponent
   */
  encode?: (str: string) => string
  /**
   * Specifies the `number` (in seconds) to be the value for the [`Max-Age` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.2).
   *
   * The [cookie storage model specification](https://tools.ietf.org/html/rfc6265#section-5.3) states that if both `expires` and
   * `maxAge` are set, then `maxAge` takes precedence, but it is possible not all clients by obey this,
   * so if both are set, they should point to the same date and time.
   */
  maxAge?: number
  /**
   * Specifies the `Date` object to be the value for the [`Expires` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.1).
   * When no expiration is set clients consider this a "non-persistent cookie" and delete it the current session is over.
   *
   * The [cookie storage model specification](https://tools.ietf.org/html/rfc6265#section-5.3) states that if both `expires` and
   * `maxAge` are set, then `maxAge` takes precedence, but it is possible not all clients by obey this,
   * so if both are set, they should point to the same date and time.
   */
  expires?: Date
  /**
   * Specifies the value for the [`Domain` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.3).
   * When no domain is set clients consider the cookie to apply to the current domain only.
   */
  domain?: string
  /**
   * Specifies the value for the [`Path` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.4).
   * When no path is set, the path is considered the ["default path"](https://tools.ietf.org/html/rfc6265#section-5.1.4).
   */
  path?: string
  /**
   * Enables the [`HttpOnly` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.6).
   * When enabled, clients will not allow client-side JavaScript to see the cookie in `document.cookie`.
   */
  httpOnly?: boolean
  /**
   * Enables the [`Secure` `Set-Cookie` attribute](https://tools.ietf.org/html/rfc6265#section-5.2.5).
   * When enabled, clients will only send the cookie back if the browser has a HTTPS connection.
   */
  secure?: boolean
  /**
   * Enables the [`Partitioned` `Set-Cookie` attribute](https://tools.ietf.org/html/draft-cutler-httpbis-partitioned-cookies/).
   * When enabled, clients will only send the cookie back when the current domain _and_ top-level domain matches.
   *
   * This is an attribute that has not yet been fully standardized, and may change in the future.
   * This also means clients may ignore this attribute until they understand it. More information
   * about can be found in [the proposal](https://github.com/privacycg/CHIPS).
   */
  partitioned?: boolean
  /**
   * Specifies the value for the [`Priority` `Set-Cookie` attribute](https://tools.ietf.org/html/draft-west-cookie-priority-00#section-4.1).
   *
   * - `'low'` will set the `Priority` attribute to `Low`.
   * - `'medium'` will set the `Priority` attribute to `Medium`, the default priority when not set.
   * - `'high'` will set the `Priority` attribute to `High`.
   *
   * More information about priority levels can be found in [the specification](https://tools.ietf.org/html/draft-west-cookie-priority-00#section-4.1).
   */
  priority?: "low" | "medium" | "high"
  /**
   * Specifies the value for the [`SameSite` `Set-Cookie` attribute](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-09#section-5.4.7).
   *
   * - `true` will set the `SameSite` attribute to `Strict` for strict same site enforcement.
   * - `'lax'` will set the `SameSite` attribute to `Lax` for lax same site enforcement.
   * - `'none'` will set the `SameSite` attribute to `None` for an explicit cross-site cookie.
   * - `'strict'` will set the `SameSite` attribute to `Strict` for strict same site enforcement.
   *
   * More information about enforcement levels can be found in [the specification](https://tools.ietf.org/html/draft-ietf-httpbis-rfc6265bis-09#section-5.4.7).
   */
  sameSite?: boolean | "lax" | "strict" | "none"
}

/**
 * Serialize data into a cookie header.
 *
 * Serialize a name value pair into a cookie string suitable for
 * http headers. An optional options object specifies cookie parameters.
 *
 * serialize('foo', 'bar', { httpOnly: true })
 *   => "foo=bar; httpOnly"
 */
export function serialize(
  name: string,
  val: string,
  options?: SerializeOptions
): string {
  const enc = options?.encode || encodeURIComponent

  if (!cookieNameRegExp.test(name)) {
    throw new TypeError(`argument name is invalid: ${name}`)
  }

  const value = enc(val)

  if (!cookieValueRegExp.test(value)) {
    throw new TypeError(`argument val is invalid: ${val}`)
  }

  let str = name + "=" + value
  if (!options) return str

  if (options.maxAge !== undefined) {
    if (!Number.isInteger(options.maxAge)) {
      throw new TypeError(`option maxAge is invalid: ${options.maxAge}`)
    }

    str += "; Max-Age=" + options.maxAge
  }

  if (options.domain) {
    if (!domainValueRegExp.test(options.domain)) {
      throw new TypeError(`option domain is invalid: ${options.domain}`)
    }

    str += "; Domain=" + options.domain
  }

  if (options.path) {
    if (!pathValueRegExp.test(options.path)) {
      throw new TypeError(`option path is invalid: ${options.path}`)
    }

    str += "; Path=" + options.path
  }

  if (options.expires) {
    if (
      !isDate(options.expires) ||
      !Number.isFinite(options.expires.valueOf())
    ) {
      throw new TypeError(`option expires is invalid: ${options.expires}`)
    }

    str += "; Expires=" + options.expires.toUTCString()
  }

  if (options.httpOnly) {
    str += "; HttpOnly"
  }

  if (options.secure) {
    str += "; Secure"
  }

  if (options.partitioned) {
    str += "; Partitioned"
  }

  if (options.priority) {
    const priority =
      typeof options.priority === "string"
        ? options.priority.toLowerCase()
        : undefined
    switch (priority) {
      case "low":
        str += "; Priority=Low"
        break
      case "medium":
        str += "; Priority=Medium"
        break
      case "high":
        str += "; Priority=High"
        break
      default:
        throw new TypeError(`option priority is invalid: ${options.priority}`)
    }
  }

  if (options.sameSite) {
    const sameSite =
      typeof options.sameSite === "string"
        ? options.sameSite.toLowerCase()
        : options.sameSite
    switch (sameSite) {
      case true:
      case "strict":
        str += "; SameSite=Strict"
        break
      case "lax":
        str += "; SameSite=Lax"
        break
      case "none":
        str += "; SameSite=None"
        break
      default:
        throw new TypeError(`option sameSite is invalid: ${options.sameSite}`)
    }
  }

  return str
}

/**
 * URL-decode string value. Optimized to skip native call when no %.
 */
function decode(str: string): string {
  if (str.indexOf("%") === -1) return str

  try {
    return decodeURIComponent(str)
  } catch (e) {
    return str
  }
}

/**
 * Determine if value is a Date.
 */
function isDate(val: any): val is Date {
  return __toString.call(val) === "[object Date]"
}