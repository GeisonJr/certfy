import * as crypto from 'node:crypto'

/**
 * The reason for revoking a certificate
 * @see https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1
 */
export enum REASON {
	unspecified = 0,
	keyCompromise = 1,
	cACompromise = 2,
	affiliationChanged = 3,
	superseded = 4,
	cessationOfOperation = 5,
	certificateHold = 6,
	// 7 is not used
	removeFromCRL = 8,
	privilegeWithdrawn = 9,
	aACompromise = 10
}

export interface Response<T = any> {
	data: T
	headers: Headers
}

export interface Account {
	data: ACMEAccount
	privateKey: crypto.KeyObject
	publicKey: crypto.KeyObject
	url: string
}

export interface ACMEAccount {
	createdAt: string
	initialIp: string
	key: {
		e: string
		kty: string
		n: string
	}
	status: string
}

export interface Authorization {
	challenges: Challenge[]
	expires: string
	identifier: Identifier
	status: 'invalid' | 'pending' | 'processing' | 'valid'
}

export interface Challenge {
	status: 'pending' | 'valid'
	token: string
	type: 'dns-01' | 'http-01' | 'tls-alpn-01'
	url: string
	validated?: string
	validationRecord?: {
		addressesResolved: string[]
		addressUsed: string
		hostname: string
		port: string
		url: string
	}[]
}

export interface CreateJWS {
	payload: string
	protected: string
	signature: string
}

export interface Directory {
	keyChange: string
	newAccount: string
	newNonce: string
	newOrder: string
	revokeCert: string
}

export interface Identifier {
	type: 'dns'
	value: string
}

export interface Order {
	authorizations: string[]
	certificate?: string
	expires: string
	finalize: string
	identifiers: Identifier[]
	status: 'invalid' | 'pending' | 'processing' | 'valid'
}

export interface Options {
	/**
	 * When staging is set to true, the Let's Encrypt staging environment is used
	 * @default false
	 */
	staging?: boolean
}

export interface ObtainOption {
	/**
	 * The domains to request a certificate for (wildcards are supported)
	 * 
	 * ***The first domain in the array will be used as the folder name***
	 * @example ['example.com', '*.example.com']
	 */
	domains: string[]
	/**
	 * The email address to use for the ACME account
	 * @example ['user@example.com']
	 */
	email?: string[]
}

export interface RenewOptions extends ObtainOption, RevokeOptions {
	/**
	 * Ignore the expiration date and force a renewal
	 * @default false
	 */
	force?: boolean
	/**
	 * Revoke the certificate after renewal
	 */
	revoke?: boolean
}

export interface RevokeOptions {
	/**
	 * The certificate to revoke
	 * @default unspecified - 0
	 */
	reason?: REASON
}

