/// <reference types="node" />
import { Handler } from 'express';
import { Agent } from 'http';
import { Agent as Agent$1 } from 'https';

/**
 * JSON Web Key ([JWK](https://www.rfc-editor.org/rfc/rfc7517)). "RSA", "EC", "OKP", and "oct" key
 * types are supported.
 */
interface JWK {
  /** JWK "alg" (Algorithm) Parameter. */
  alg?: string
  crv?: string
  d?: string
  dp?: string
  dq?: string
  e?: string
  /** JWK "ext" (Extractable) Parameter. */
  ext?: boolean
  k?: string
  /** JWK "key_ops" (Key Operations) Parameter. */
  key_ops?: string[]
  /** JWK "kid" (Key ID) Parameter. */
  kid?: string
  /** JWK "kty" (Key Type) Parameter. */
  kty?: string
  n?: string
  oth?: Array<{
    d?: string
    r?: string
    t?: string
  }>
  p?: string
  q?: string
  qi?: string
  /** JWK "use" (Public Key Use) Parameter. */
  use?: string
  x?: string
  y?: string
  /** JWK "x5c" (X.509 Certificate Chain) Parameter. */
  x5c?: string[]
  /** JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter. */
  x5t?: string
  /** "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter. */
  'x5t#S256'?: string
  /** JWK "x5u" (X.509 URL) Parameter. */
  x5u?: string

  [propName: string]: unknown
}

interface JoseHeaderParameters {
  /** "kid" (Key ID) Header Parameter. */
  kid?: string

  /** "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter. */
  x5t?: string

  /** "x5c" (X.509 Certificate Chain) Header Parameter. */
  x5c?: string[]

  /** "x5u" (X.509 URL) Header Parameter. */
  x5u?: string

  /** "jku" (JWK Set URL) Header Parameter. */
  jku?: string

  /** "jwk" (JSON Web Key) Header Parameter. */
  jwk?: Pick<JWK, 'kty' | 'crv' | 'x' | 'y' | 'e' | 'n'>

  /** "typ" (Type) Header Parameter. */
  typ?: string

  /** "cty" (Content Type) Header Parameter. */
  cty?: string
}

/** Recognized JWS Header Parameters, any other Header Members may also be present. */
interface JWSHeaderParameters extends JoseHeaderParameters {
  /** JWS "alg" (Algorithm) Header Parameter. */
  alg?: string

  /**
   * This JWS Extension Header Parameter modifies the JWS Payload representation and the JWS Signing
   * Input computation as per [RFC7797](https://www.rfc-editor.org/rfc/rfc7797).
   */
  b64?: boolean

  /** JWS "crit" (Critical) Header Parameter. */
  crit?: string[]

  /** Any other JWS Header member. */
  [propName: string]: unknown
}

/** Recognized JWT Claims Set members, any other members may also be present. */
interface JWTPayload {
  /**
   * JWT Issuer
   *
   * @see [RFC7519#section-4.1.1](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1)
   */
  iss?: string

  /**
   * JWT Subject
   *
   * @see [RFC7519#section-4.1.2](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2)
   */
  sub?: string

  /** JWT Audience [RFC7519#section-4.1.3](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3). */
  aud?: string | string[]

  /**
   * JWT ID
   *
   * @see [RFC7519#section-4.1.7](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7)
   */
  jti?: string

  /**
   * JWT Not Before
   *
   * @see [RFC7519#section-4.1.5](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5)
   */
  nbf?: number

  /**
   * JWT Expiration Time
   *
   * @see [RFC7519#section-4.1.4](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)
   */
  exp?: number

  /**
   * JWT Issued At
   *
   * @see [RFC7519#section-4.1.6](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6)
   */
  iat?: number

  /** Any other JWT Claim Set member. */
  [propName: string]: unknown
}

type FunctionValidator = (value: unknown, claims: JWTPayload, header: JWSHeaderParameters) => Promise<boolean> | boolean;
type Validator = FunctionValidator | string | false | undefined;
interface Validators {
    alg: Validator;
    typ: Validator;
    iss: Validator;
    aud: Validator;
    exp: Validator;
    iat: Validator;
    sub: Validator;
    client_id: Validator;
    jti: Validator;
    [key: string]: Validator;
}

interface JwtVerifierOptions {
    issuerBaseURL?: string;
    audience?: string | string[];
    issuer?: string;
    jwksUri?: string;
    agent?: Agent | Agent$1;
    cooldownDuration?: number;
    timeoutDuration?: number;
    cacheMaxAge?: number;
    validators?: Partial<Validators>;
    clockTolerance?: number;
    maxTokenAge?: number;
    strict?: boolean;
    secret?: string;
    tokenSigningAlg?: string;
}
interface VerifyJwtResult {
    header: JWSHeaderParameters;
    payload: JWTPayload;
    token: string;
}

declare class UnauthorizedError extends Error {
    status: number;
    statusCode: number;
    headers: {
        'WWW-Authenticate': string;
    };
    constructor(message?: string);
}
declare class InvalidRequestError extends UnauthorizedError {
    code: string;
    status: number;
    statusCode: number;
    constructor(message?: string);
}
declare class InvalidTokenError extends UnauthorizedError {
    code: string;
    status: number;
    statusCode: number;
    constructor(message?: string);
}
declare class InsufficientScopeError extends UnauthorizedError {
    code: string;
    status: number;
    statusCode: number;
    constructor(scopes?: string[], message?: string);
}

type JSONPrimitive = string | number | boolean | null;
type ClaimChecker = (payload?: JWTPayload) => void;
type RequiredScopes<R = ClaimChecker> = (scopes: string | string[]) => R;
type ClaimIncludes<R = ClaimChecker> = (claim: string, ...expected: JSONPrimitive[]) => R;
type ClaimEquals<R = ClaimChecker> = (claim: string, expected: JSONPrimitive) => R;
type ClaimCheck<R = ClaimChecker> = (fn: (payload: JWTPayload) => boolean, errMsg?: string) => R;

interface AuthOptions extends JwtVerifierOptions {
    authRequired?: boolean;
}
declare global {
    namespace Express {
        interface Request {
            auth?: VerifyJwtResult;
        }
    }
}
declare const auth: (opts?: AuthOptions) => Handler;
declare const claimCheck: ClaimCheck<Handler>;
declare const claimEquals: ClaimEquals<Handler>;
declare const claimIncludes: ClaimIncludes<Handler>;
declare const requiredScopes: RequiredScopes<Handler>;
declare const scopeIncludesAny: RequiredScopes<Handler>;

export { AuthOptions, VerifyJwtResult as AuthResult, FunctionValidator, InsufficientScopeError, InvalidRequestError, InvalidTokenError, JSONPrimitive, JWSHeaderParameters as JWTHeader, JWTPayload, UnauthorizedError, Validator, Validators, auth, claimCheck, claimEquals, claimIncludes, requiredScopes, scopeIncludesAny };
