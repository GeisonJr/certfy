import * as crypto from 'node:crypto'

export interface Response<T = any> {
	data: T
	headers: Headers
}

export interface CreateJWS {
	protected: string
	payload: string
	signature: string
}

export interface ACMEAccount {
	key: {
		kty: string
		n: string
		e: string
	}
	initialIp: string
	createdAt: string
	status: string
}

export interface Account {
	data: ACMEAccount
	url: string
	publicKey: crypto.KeyObject
	privateKey: crypto.KeyObject
}

export interface Directory {
	keyChange: string
	newAccount: string
	newNonce: string
	newOrder: string
	revokeCert: string
}

export interface Order {
	status: 'pending' | 'processing' | 'valid'
	expires: string
	identifiers: {
		type: 'dns'
		value: string
	}[]
	authorizations: string[]
	finalize: string
	certificate?: string
}

export interface Authorization {
	identifier: {
		type: 'dns'
		value: string
	}
	status: 'pending' | 'valid' | 'invalid' | 'processing'
	expires: string
	challenges: Challenge[]
	// certificate?: string
}

export interface Challenge {
	type: 'dns-01' | 'http-01' | 'tls-alpn-01'
	url: string
	status: 'pending' | 'valid'
	token: string
	validated?: string
	validationRecord?: {
		url: string
		hostname: string
		port: string
		addressesResolved: string[]
		addressUsed: string
	}[]
}
