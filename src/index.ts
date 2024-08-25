import '@geisonjr/envfy/config'
import { isNull, isUndefined } from '@geisonjr/typefy'
import { generateKeyPairSync, X509Certificate } from 'node:crypto'
import { createServer, Server } from 'node:http'

import { Account, ACMEAccount, Authorization, Challenge, Directory, ObtainOption, Options, Order, REASON, RenewOptions, Response, RevokeOptions } from './types'
import { certificateToDER, createCSR, createJWS, deleteFolder, keyObjectToJWK, keyObjectToPEM, newPrivateKey, newPublicKey, readFile, request, thumbprint, writeFile } from './util'

/**
 * Class to create a Certificate
 */
export class Certificate {
	private account!: Account
	private challenges: Record<string, string> = {}
	private directory!: Directory
	private _domains: string[] = []
	private _email: string[] = []
	private nonce: null | string = null
	private server!: Server
	private staging: boolean = false

	constructor(options: Options = {}) {
		const { staging = false } = options

		this.staging = staging
	}

	get domains() {
		return this._domains
	}

	set domains(domains: string[]) {
		// Check if the domains are already set
		if (this.domains.length)
			return

		// Check if the domains are not empty
		if (!domains.length)
			throw new Error('Domains not found')

		// Remove duplicates
		domains = Array.from(new Set(domains))

		// Check if the domains are valid
		const invalidDomains = domains.filter(domain => !(/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/i).test(domain))
		if (invalidDomains.length)
			throw new Error(`Invalid domains (${invalidDomains.join(', ')})`)

		// Check if the domains are wildcards
		const wildcardDomains = domains.filter(domain => domain.startsWith('*'))
		if (wildcardDomains.length > 0)
			throw new Error(`Wildcards are not supported (${wildcardDomains.join(', ')})`)

		this._domains = domains
	}

	get email() {
		return this._email
	}

	set email(email: string[]) {
		// Check if the email is already set
		if (this.email.length)
			return

		// Check if the email is not empty
		// if (!email.length)
		// 	throw new Error('Email not found')

		// Remove duplicates
		email = Array.from(new Set(email))

		// Check if the email is valid
		for (const e of email)
			if (!/^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]+$/i.test(e))
				throw new Error(`Invalid email ${e}`)

		this._email = email
	}

	private async performRequest<T>(url: string, options: RequestInit = {}) {

		const response = await request<T>(url, options)

		// Set the nonce
		this.nonce = response.headers.get('Replay-Nonce')

		return response
	}

	private async listenChallenge(): Promise<void> {

		return new Promise((resolve, reject) => {
			this.server = createServer((req, res) => {

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

					res.writeHead(404)
					res.end()
					return
				}

				res.writeHead(400)
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

	private async getDirectory(): Promise<Directory> {

		// Return the directory if it is already set
		if (!isUndefined(this.directory))
			return this.directory

		let api = 'https://acme-v02.api.letsencrypt.org' // Production
		if (this.staging)
			api = 'https://acme-staging-v02.api.letsencrypt.org' // Staging

		// Prepare the URL to get the directory
		const url = new URL('/directory', api).toString()

		// Request the directory
		const response = await this.performRequest<Directory>(url)

		return this.directory = response.data
	}

	private async getNonce(): Promise<string> {

		// Return the nonce if it is already set and clear it
		if (!isNull(this.nonce)) {
			const nonce = this.nonce
			this.nonce = null
			return nonce
		}

		// Request a new nonce
		const response = await this.performRequest<void>(this.directory.newNonce, {
			method: 'HEAD'
		})

		return response.headers.get('Replay-Nonce') as string
	}

	private async getAccount(createIfNotExists = true): Promise<Account> {

		// Prepare the account file path
		const data = readFile({
			filename: 'data.json',
			folder: 'account'
		})

		// Check if the account file exists, if not create a new account
		if (!data) {
			if (!createIfNotExists)
				throw new Error('Account not found')

			return this.account = await this.createAccount()
		}

		// Parse the account data
		const account = JSON.parse(data) as Account

		// Restore the private key from the file
		const privateKey = newPrivateKey(account.privateKey as unknown as string)

		// Restore the public key from the file
		const publicKey = newPublicKey(account.publicKey as unknown as string)

		return this.account = {
			...account,
			privateKey,
			publicKey
		}
	}

	private async createAccount(): Promise<Account> {

		// Generate a new key pair for the account
		const { privateKey, publicKey } = generateKeyPairSync('rsa', {
			modulusLength: 2048
		})

		// Prepare the protected header
		const protect = {
			nonce: await this.getNonce(),
			jwk: keyObjectToJWK(publicKey),
			url: this.directory.newAccount,
		}

		// Prepare the payload
		const payload = {
			termsOfServiceAgreed: true, // Must be true
			contact: this.email.map((email) => `mailto:${email}`)
		}

		// Encrypt the payload and the protected header into a JWS
		const jws = await createJWS(protect, payload, privateKey)

		// Register the account
		const response = await this.performRequest<ACMEAccount>(this.directory.newAccount, {
			method: 'POST',
			body: JSON.stringify(jws)
		})

		// Get the account URL
		const accountUrl = response.headers.get('Location') || ''

		// Save account data to a file
		writeFile({
			filename: 'data.json',
			folder: 'account',
			data: JSON.stringify({
				data: response.data,
				url: accountUrl,
				privateKey: keyObjectToPEM(privateKey),
				publicKey: keyObjectToPEM(publicKey)
			})
		})

		return {
			data: response.data,
			url: accountUrl,
			privateKey,
			publicKey
		}
	}

	private async getAuthorization(authorizationUrl: string) {

		return await this.performRequest<Authorization>(authorizationUrl)
	}

	private async getValidAuthorization(authorizationUrl: string) {

		// Poll the authorization status until it is valid
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

	private async createOrder(): Promise<Response<Order>> {

		// Prepare the protected header
		const protect = {
			nonce: await this.getNonce(),
			kid: this.account.url,
			url: this.directory.newOrder
		}

		// Prepare the payload
		const payload = {
			identifiers: this.domains.map((domain) => {
				return {
					type: 'dns',
					value: domain
				}
			})
		}

		// Encrypt the payload and the protected header into a JWS
		const jws = await createJWS(protect, payload, this.account.privateKey)

		// Create the order
		const response = await this.performRequest<Order>(this.directory.newOrder, {
			method: 'POST',
			body: JSON.stringify(jws)
		})

		return response
	}

	private async getValidOrder(orderUrl: string) {

		// Poll the order status until it is valid
		do {
			const order = await this.performRequest<Order>(orderUrl)

			if (order.data.status === 'valid')
				return order.data.certificate ?? ''

			if (order.data.status !== 'processing')
				throw new Error('Order failed ' + JSON.stringify(order.data))

			const timeout = Number(order.headers.get('Retry-After') ?? 5) * 1000

			await new Promise((resolve) => setTimeout(resolve, timeout))
		} while (true)
	}

	private async finalizeOrder(finalizeUrl: string, csr: string): Promise<string> {

		// Prepare the protected header
		const protect = {
			nonce: await this.getNonce(),
			kid: this.account.url,
			url: finalizeUrl
		}

		// Prepare the payload
		const payload = {
			csr // Certificate Signing Request
		}

		// Encrypt the payload and the protected header into a JWS
		const jws = await createJWS(protect, payload, this.account.privateKey)

		// Notify the ACME server that the order is ready to be finalized
		const response = await this.performRequest<Order>(finalizeUrl, {
			method: 'POST',
			body: JSON.stringify(jws)
		})

		return response.headers.get('Location') ?? ''
	}

	private async respondChallenges(challenges: Challenge[]) {

		for (const challenge of challenges) {

			if (challenge.type !== 'http-01')
				continue

			await this.respondChallenge(challenge)
		}
	}

	private async respondChallenge(challenge: Challenge) {

		// Prepare the protected header
		const protect = {
			nonce: await this.getNonce(),
			kid: this.account.url,
			url: challenge.url
		}

		// Prepare the payload
		const payload = {
			// Empty payload
		}

		// Encrypt the payload and the protected header into a JWS
		const jws = await createJWS(protect, payload, this.account.privateKey)

		// Notify the ACME server that the challenge is ready to be validated
		await this.performRequest<Challenge>(challenge.url, {
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
		const fingerprint = thumbprint(this.account.publicKey)

		for (const challenge of challenges) {
			// Register the token and key authorization
			this.challenges[challenge.token] = `${challenge.token}.${fingerprint}`
		}
	}

	private async getCertificate(certificateUrl: string) {
		return (await this.performRequest<string>(certificateUrl)).data
	}

	private saveCertificate(certificate: string, privateKey: string) {

		// Get the fullchain
		const fullchain = certificate

		// Extract the individual certificates
		const [cert, ...chainParts] = fullchain.split(/(?=-----BEGIN CERTIFICATE-----)/)
		const chain = chainParts.join('')


		// Move the old certificate to a new folder
		const files = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem']

		const now = new Date().getTime()
		const oldCertificateFolder = this.domains[0] + '-' + now

		for (const filename of files) {
			const data = readFile({
				filename: filename,
				folder: this.domains[0]
			})

			if (data)
				writeFile({
					filename: filename,
					folder: oldCertificateFolder,
					data
				})
		}

		// Save the new files to the domain folder
		const folder = this.domains[0]

		writeFile({
			filename: 'cert.pem',
			folder,
			data: cert.trim() + '\n'
		})

		writeFile({
			filename: 'chain.pem',
			folder,
			data: chain.trim() + '\n'
		})

		writeFile({
			filename: 'fullchain.pem',
			folder,
			data: fullchain.trim() + '\n'
		})

		writeFile({
			filename: 'privkey.pem',
			folder,
			data: privateKey
		})

		return oldCertificateFolder
	}

	public async obtain(options: ObtainOption) {

		const {
			domains = [],
			email = []
		} = options

		// Set the domains
		this.domains = domains
		this.email = email

		// Get the directory
		await this.getDirectory()

		// Get the account or create a new one
		await this.getAccount()

		// Create a new order
		const order = await this.createOrder()

		// Get the authorizations
		const authorizationsPromises = order.data.authorizations.map((url) => this.getAuthorization(url))
		const authorizations = await Promise.all(authorizationsPromises)

		// Prepare the challenges
		this.storeChallenges(authorizations.map(authorization => authorization.data))

		try {

			// Start the HTTP server to listen for challenges
			await this.listenChallenge()

			// Notify the ACME server that the challenges are ready to be validated
			const challengesPromises = authorizations.map(authorization => this.respondChallenges(authorization.data.challenges))
			await Promise.all(challengesPromises)

			// Await the challenge be validated
			const validAuthorizationsPromises = order.data.authorizations.map(url => this.getValidAuthorization(url))
			await Promise.all(validAuthorizationsPromises)

		} finally {
			// Stop server
			if (!isNull(this.server))
				this.server.close()
		}

		// Generate a CSR
		const csr = createCSR({
			commonName: this.domains[0],
			subjectAltNames: this.domains.slice(1)
		})

		// Finalize the order
		const orderUrl = await this.finalizeOrder(order.data.finalize, csr.csr)

		// Await the certificate be issued
		const certificateUrl = await this.getValidOrder(orderUrl)

		// Get the certificate
		const certificate = await this.getCertificate(certificateUrl)

		// Save the certificate to a file
		return this.saveCertificate(certificate, csr.privateKey)
	}

	/**
	 * Renew a certificate, if the certificate is not expired, it will be revoked and a new one will be obtained
	 */
	public async renew(options: RenewOptions) {

		const {
			domains = [],
			email = [],
			force = false,
			revoke = false,
			reason = REASON.unspecified
		} = options

		// Set the domains
		this.domains = domains
		this.email = email

		// Check if the certificate is expired
		const certObject = new X509Certificate(readFile({
			filename: 'cert.pem',
			folder: this.domains[0]
		}))

		const now = new Date().getTime()
		const notAfter = new Date(certObject.validTo).getTime()

		if (!force && now < notAfter)
			throw new Error('Certificate is not expired')

		// Obtain a new certificate
		const oldCertificateFolder = await this.obtain({ domains, email })

		// Revoke the certificate
		if (revoke) {
			await this.revoke(
				readFile({
					filename: 'cert.pem',
					folder: oldCertificateFolder
				}),
				readFile({
					filename: 'privkey.pem',
					folder: oldCertificateFolder
				}),
				{
					reason
				})

			// Delete the old certificate folder
			deleteFolder({
				folder: oldCertificateFolder
			})
		}
	}

	/**
	 * Revoke a certificate, the certificate must be in the same folder as the domain
	 */
	public async revoke(certificate: string, privateKey: string, options: RevokeOptions = {}) {

		const {
			reason = REASON.unspecified
		} = options

		// Read the certificate file
		const certObject = new X509Certificate(certificate)

		// Get the directory
		await this.getDirectory()

		// Prepare the protected header
		const protect = {
			nonce: await this.getNonce(),
			jwk: keyObjectToJWK(certObject.publicKey),
			url: this.directory.revokeCert,
		}

		// Prepare the payload
		const payload = {
			certificate: certificateToDER(certificate), // Base64 encoded
			reason
		}

		// Encrypt the payload and the protected header into a JWS
		const jws = await createJWS(protect, payload, privateKey)

		// Revoke the certificate
		await this.performRequest(this.directory.revokeCert, {
			method: 'POST',
			body: JSON.stringify(jws)
		})
	}
}
