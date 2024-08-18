import { isBuffer, isNull, isString, isUndefined } from '@geisonjr/typefy'
import * as forge from 'node-forge'
import * as crypto from 'node:crypto'
import * as fs from 'node:fs'
import * as http from 'node:http'
import * as path from 'node:path'

import { Account, ACMEAccount, Authorization, Challenge, CreateJWS, Directory, Order, Response } from './types'

/**
 * Class to create a Certificate
 */
export class Certificate {
	private account!: Account
	private challenges: Record<string, string> = {}
	private directory!: Directory
	private nonce: null | string = null
	private server!: http.Server

	constructor() { }

	private async request<T>(url: string, options: RequestInit = {}): Promise<Response<T>> {
		options.method ??= 'GET'
		options.headers = new Headers(options.headers)

		// Set the content type if it is not set and the method is POST
		if (options.method === 'POST' && !options.headers.has('Content-Type'))
			options.headers.set('Content-Type', 'application/jose+json')

		// Execute the request
		const response = await fetch(url, options)

		// Check if the response is ok
		if (!response.ok)
			throw await response.text()

		// Get the content type
		const contentType = response.headers.get('Content-Type') ?? ''

		let data: T

		const isApplicationJSON = /application\/([a-zA-Z]+\+)?json/
		if (isApplicationJSON.test(contentType))
			data = await response.json() as T
		else
			data = await response.text() as T

		// Set the nonce
		this.nonce = response.headers.get('Replay-Nonce')

		return {
			data,
			headers: response.headers
		}
	}

	private async listenChallenge(): Promise<void> {
		return new Promise((resolve, reject) => {
			this.server = http.createServer((req, res) => {
				if (req.method !== 'GET') {
					res.writeHead(405)
					res.end()
					return
				}

				if (req.url?.startsWith('/.well-known/acme-challenge/')) {

					const token = req.url.split('/')[3]
					const keyAuthorization = this.challenges[token]

					if (keyAuthorization) {
						res.writeHead(200, { 'Content-Type': 'text/plain' })
						res.write(keyAuthorization)
						res.end()
						return
					}
				}

				res.writeHead(404)
				res.end()
			})

			this.server.on('error', (error) => {
				reject(error)
			})

			this.server.listen(80, () => {
				resolve()
			})
		})
	}

	private toBase64Url(data: object | string): string {
		if (isBuffer(data))
			return data.toString('base64url')

		if (isString(data))
			return Buffer.from(data).toString('base64url')

		return Buffer.from(JSON.stringify(data)).toString('base64url')
	}

	private createJWK(key: crypto.KeyObject): crypto.JsonWebKey {
		return key.export({ format: 'jwk' })
	}

	private createThumbprint(key: crypto.KeyObject): string {
		const jwk = this.createJWK(key)
		const jwkString = JSON.stringify({
			e: jwk.e,
			kty: jwk.kty,
			n: jwk.n
		})

		return this.toBase64Url(this.hash(jwkString))
	}

	private createPEM(key: crypto.KeyObject | forge.pki.PrivateKey): string {

		if (key instanceof crypto.KeyObject)
			return key.export({
				format: 'pem',
				type: 'pkcs1'
			}) as string

		return forge.pki.privateKeyToPem(key)
	}

	private async createJWS(protect: {
		alg?: 'RS256'
		jwk?: crypto.JsonWebKey
		kid?: string
		nonce?: string
		url?: string
	}, payload: object, privateKey: crypto.KeyObject): Promise<CreateJWS> {
		protect.alg ??= 'RS256'
		protect.nonce ??= await this.getNonce()

		if (isUndefined(protect.jwk) && isUndefined(protect.kid))
			throw new Error('Missing "kid" or "jwk" in the protected header')

		const protectBase64 = this.toBase64Url(protect)
		const payloadBase64 = this.toBase64Url(payload)
		const signature = this.sign(`${protectBase64}.${payloadBase64}`, privateKey)
		const signatureBase64 = this.toBase64Url(signature)

		return {
			protected: protectBase64,
			payload: payloadBase64,
			signature: signatureBase64
		}
	}

	private hash(data: string): Buffer {
		const hash = crypto.createHash('SHA256')
		hash.update(data)
		hash.end()
		return hash.digest()
	}

	private sign(data: string, privateKey: crypto.KeyObject): Buffer {
		const sign = crypto.createSign('SHA256')
		sign.update(data)
		sign.end()
		return sign.sign(privateKey)
	}

	private generateKeyPair(): crypto.KeyPairKeyObjectResult {
		return crypto.generateKeyPairSync('rsa', {
			modulusLength: 2048
		})
	}

	private generateCSR(domains: string[]) {
		const clonedDomains = Object.assign(domains) as string[]

		// Get the common name
		const commonName = clonedDomains.shift()

		// Get the alternative names
		const altNames = clonedDomains

		const { privateKey, publicKey } = forge.pki.rsa.generateKeyPair({ bits: 2048 })
		const csr = forge.pki.createCertificationRequest()

		csr.publicKey = publicKey
		csr.setSubject([
			{
				name: 'commonName',
				value: commonName
			}
		])

		// Set the Subject Alternative Name (SAN) extension
		csr.setAttributes([
			{
				name: 'extensionRequest',
				extensions: [
					{
						name: 'subjectAltName',
						altNames: altNames.map(domain => ({
							type: 2, // DNS type
							value: domain
						}))
					}
				]
			}
		])

		csr.sign(privateKey, forge.md.sha256.create())

		const csrInASN1 = forge.pki.certificationRequestToAsn1(csr)
		const csrInDER = forge.asn1.toDer(csrInASN1).getBytes()

		return {
			csr: this.toBase64Url(Buffer.from(csrInDER, 'binary')),
			privateKey,
			publicKey
		}
	}

	private saveFile(filename: string, data: string): void {
		fs.writeFileSync(path.join(__dirname, filename), data, { encoding: 'utf-8' })
	}

	private async createAccount(email?: string[]): Promise<Account> {

		// Generate a new key pair for the account
		const { privateKey, publicKey } = this.generateKeyPair()

		// Prepare the protected header
		const protect = {
			jwk: this.createJWK(publicKey),
			url: this.directory.newAccount,
		}

		// Prepare the payload
		const payload = {
			termsOfServiceAgreed: true, // Must be true
			contact: email?.map((email) => `mailto:${email}`) ?? []
		}

		// Encrypt the payload and the protected header into a JWS
		const jws = await this.createJWS(protect, payload, privateKey)

		// Register the account
		const response = await this.request<ACMEAccount>(this.directory.newAccount, {
			method: 'POST',
			body: JSON.stringify(jws)
		})

		// Get the account URL
		const accountUrl = response.headers.get('Location') || ''

		// Save account data to a file
		this.saveFile('account.json', JSON.stringify({
			data: response.data,
			url: accountUrl,
			privateKey: this.createPEM(privateKey),
			publicKey: this.createPEM(publicKey)
		}))

		return {
			data: response.data,
			url: accountUrl,
			privateKey,
			publicKey
		}
	}

	private async finalizeOrder(finalizeUrl: string, csr: { csr: string }) {
		const url = finalizeUrl

		// Prepare the protected header
		const protect = {
			kid: this.account.url,
			url
		}

		// Prepare the payload
		const payload = {
			csr: csr.csr // Certificate Signing Request
		}

		// Encrypt the payload and the protected header into a JWS
		const jws = await this.createJWS(protect, payload, this.account.privateKey)

		// Notify the ACME server that the order is ready to be finalized
		const response = await this.request<Order>(url, {
			method: 'POST',
			body: JSON.stringify(jws)
		})

		return response.headers.get('Location') ?? ''
	}

	private async getAccount(email?: string[]) {
		const accountPath = path.join(__dirname, 'account.json')

		// Check if the account file exists, if not create a new account
		if (!fs.existsSync(accountPath)) {
			this.account = await this.createAccount(email)
			return
		}

		// Read account data from file
		const data = fs.readFileSync(accountPath, 'utf-8')

		// Parse the account data
		const account = JSON.parse(data)

		// Restore the private key from the file
		const privateKey = crypto.createPrivateKey({
			key: account.privateKey,
			format: 'pem',
			type: 'pkcs1'
		})

		// Restore the public key from the file
		const publicKey = crypto.createPublicKey({
			key: account.publicKey,
			format: 'pem',
			type: 'pkcs1'
		})

		this.account = {
			...account,
			privateKey,
			publicKey
		}

		return
	}

	private async getAuthorization(authorizationUrl: string) {
		return await this.request<Authorization>(authorizationUrl)
	}

	private async getValidAuthorization(authorizationUrl: string) {
		do {
			const authorization = await this.getAuthorization(authorizationUrl)

			if (authorization.data.status === 'valid')
				break

			if (authorization.data.status === 'invalid')
				throw new Error('Challenge failed ' + JSON.stringify(authorization.data))

			const timeout = Number(authorization.headers.get('Retry-After') ?? 5) * 1000

			await new Promise((resolve) => setTimeout(resolve, timeout))
		} while (true)

		// Remove the token and key authorization
		// delete this.challenges[challenge.token]
	}

	private async getDirectory() {
		if (!isUndefined(this.directory))
			return

		// const api = 'https://acme-v02.api.letsencrypt.org' // Production
		const api = 'https://acme-staging-v02.api.letsencrypt.org' // Staging

		// Prepare the URL to get the directory
		const url = new URL('/directory', api).toString()

		// Request the directory
		const response = await this.request<Directory>(url)

		return this.directory = response.data
	}

	private async getNonce(): Promise<string> {
		// Return the nonce if it is already set
		if (!isNull(this.nonce))
			return this.nonce

		// Request a new nonce
		const response = await this.request<void>(this.directory.newNonce, {
			method: 'HEAD'
		})

		return this.nonce = response.headers.get('Replay-Nonce') as string
	}

	private async createOrder(domains: string[]): Promise<Response<Order>> {
		const url = this.directory.newOrder

		// Prepare the protected header
		const protect = {
			kid: this.account.url,
			url
		}

		// Prepare the payload
		const payload = {
			identifiers: domains.map((domain) => {
				return {
					type: 'dns',
					value: domain
				}
			}),
			// notBefore: new Date().toISOString(),
			// notAfter: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString() // 90 days
		}

		// Encrypt the payload and the protected header into a JWS
		const jws = await this.createJWS(protect, payload, this.account.privateKey)

		// Create the order
		const response = await this.request<Order>(url, {
			method: 'POST',
			body: JSON.stringify(jws)
		})

		return response
	}

	private async getValidOrder(orderUrl: string) {
		do {
			const order = await this.request<Order>(orderUrl)

			if (order.data.status === 'valid') {
				return order.data.certificate ?? ''
			}

			const timeout = Number(order.headers.get('Retry-After') ?? 5) * 1000

			await new Promise((resolve) => setTimeout(resolve, timeout))
		} while (true)
	}

	private async respondChallenges(challenges: Challenge[]) {
		for (const challenge of challenges) {
			if (challenge.type !== 'http-01')
				continue

			await this.respondChallenge(challenge)
		}
	}

	private async respondChallenge(challenge: Challenge) {
		const url = challenge.url

		// Prepare the protected header
		const protect = {
			kid: this.account.url,
			url
		}

		// Prepare the payload
		const payload = {
			// Empty payload
		}

		// Encrypt the payload and the protected header into a JWS
		const jws = await this.createJWS(protect, payload, this.account.privateKey)

		// Notify the ACME server that the challenge is ready to be validated
		await this.request<Challenge>(url, {
			method: 'POST',
			body: JSON.stringify(jws)
		})
	}

	private storeChallenges(authorizations: Authorization[]) {
		for (const authorization of authorizations) {
			this.storeChallenge(authorization)
		}
	}

	private storeChallenge(authorization: Authorization) {
		const challenges = authorization.challenges

		if (!challenges.length)
			throw new Error('Challenges not found')

		// Create the JWK thumbprint
		const thumbprint = this.createThumbprint(this.account.publicKey)

		for (const challenge of challenges) {
			// Register the token and key authorization
			this.challenges[challenge.token] = `${challenge.token}.${thumbprint}`
		}
	}

	private async getCertificate(certificateUrl: string) {
		return (await this.request<string>(certificateUrl)).data
	}

	private saveCertificate(certificate: string, privateKey: forge.pki.PrivateKey) {
		const fullchain = certificate

		// Extract the individual certificates
		const [cert, ...chainParts] = fullchain.split(/(?=-----BEGIN CERTIFICATE-----)/)
		const chain = chainParts.join('')

		// Save the (cert.pem)
		this.saveFile('cert.pem', cert.trim() + '\n')

		// Save the (chain.pem)
		this.saveFile('chain.pem', chain.trim() + '\n')

		// Save the (fullchain.pem)
		this.saveFile('fullchain.pem', fullchain.trim() + '\n')

		// Save the (privkey.pem)
		const privkey = this.createPEM(privateKey)
		this.saveFile('privkey.pem', privkey)
	}

	public async obtainCertificate({
		domains,
		email
	}: {
		domains: string[]
		email?: string[]
	}) {

		await this.getDirectory()
		await this.getAccount(email)

		// Create a new order
		const order = await this.createOrder(domains)

		// Get the authorizations
		const authorizationsPromises = order.data.authorizations.map((url) => this.getAuthorization(url))
		const authorizations = await Promise.all(authorizationsPromises)

		// Prepare the challenges
		this.storeChallenges(authorizations.map(authorization => authorization.data))

		// Start the HTTP server to listen for challenges
		await this.listenChallenge()

		// Notify the ACME server that the challenges are ready to be validated
		const challengesPromises = authorizations.map(authorization => this.respondChallenges(authorization.data.challenges))
		await Promise.all(challengesPromises)

		// Await the challenge be validated
		const validAuthorizationsPromises = order.data.authorizations.map(url => this.getValidAuthorization(url))
		await Promise.all(validAuthorizationsPromises)

		// Stop server
		this.server.close()

		// Generate a CSR
		const csr = this.generateCSR(domains)

		const orderUrl = await this.finalizeOrder(order.data.finalize, csr)

		// Await the certificate be issued
		const certificateUrl = await this.getValidOrder(orderUrl)

		// Get the certificate
		const certificate = await this.getCertificate(certificateUrl)

		// Save the certificate to a file
		this.saveCertificate(certificate, csr.privateKey)
	}

	public async renewCertificate({
		domains,
		email
	}: {
		domains: string[]
		email?: string[]
	}) {
		await this.obtainCertificate({
			domains,
			email
		})
	}

	public async revokeIssuedCertificate(cert: string) {

		await this.getDirectory()
		await this.getAccount()

		// Prepare the protected header
		const protect = {
			kid: this.account.url,
			url: this.directory.revokeCert,
		}

		// Prepare the payload
		const payload = {
			certificate: cert, // Base64 encoded
			reason: 0, // Unspecified
		}

		// Encrypt the payload and the protected header into a JWS
		const jws = await this.createJWS(protect, payload, this.account.privateKey)

		// Revoke the certificate
		await this.request(this.directory.revokeCert, {
			method: 'POST',
			body: JSON.stringify(jws)
		})
	}
}
