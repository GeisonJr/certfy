import * as envfy from '@geisonjr/envfy'
import { isBuffer, isString, isUndefined } from '@geisonjr/typefy'
import * as forge from 'node-forge'
import { createHash, createPrivateKey, createPublicKey, createSign, generateKeyPairSync, JsonWebKey, KeyObject } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/**
 * Convert a string or object to a base64url string
 */
export function toBase64Url(data: object | string): string {
  if (isBuffer(data))
    return data.toString('base64url')

  if (isString(data))
    return Buffer.from(data).toString('base64url')

  return Buffer.from(JSON.stringify(data)).toString('base64url')
}

/**
 * Convert a KeyObject to a JsonWebKey
 * @example
 * const key = crypto.generateKeyPairSync('rsa', {
 *   modulusLength: 2048
 * })
 * const jwk = keyObjectToJWK(key.publicKey)
 */
export function keyObjectToJWK(key: KeyObject): JsonWebKey {
  return key.export({ format: 'jwk' })
}

/**
 * Convert a KeyObject to a PEM string
 */
export function keyObjectToPEM(key: KeyObject): string {
  return key.export({
    format: 'pem',
    type: 'pkcs1'
  }).toString()
}

export async function createJWS(protect: {
  alg?: 'RS256'
  jwk?: JsonWebKey
  kid?: string
  nonce: string
  url?: string
}, payload: object, privateKey: string | KeyObject) {
  protect.alg ??= 'RS256'

  if (isUndefined(protect.jwk) && isUndefined(protect.kid))
    throw new Error('Missing "kid" or "jwk" in the protected header')

  const protectBase64 = toBase64Url(protect)
  const payloadBase64 = toBase64Url(payload)
  const signature = sign(`${protectBase64}.${payloadBase64}`, privateKey)
  const signatureBase64 = toBase64Url(signature)

  return {
    protected: protectBase64,
    payload: payloadBase64,
    signature: signatureBase64
  }
}

/**
 * Generate a thumbprint from a KeyObject
 */
export function thumbprint(key: KeyObject): string {
  const jwk = keyObjectToJWK(key)
  const jwkString = JSON.stringify({
    e: jwk.e,
    kty: jwk.kty,
    n: jwk.n
  })
  return toBase64Url(hash(jwkString))
}

/**
 * Generate a hash from a string or object
 */
export function hash(data: string): Buffer {
  const hash = createHash('SHA256')
  hash.update(data)
  hash.end()
  return hash.digest()
}

export function sign(data: string, privateKey: string | KeyObject): Buffer {
  const sign = createSign('SHA256')
  sign.update(data)
  sign.end()
  return sign.sign(privateKey)
}

/**
 * Create private key
 */
export function newPrivateKey(key: string): KeyObject {
  return createPrivateKey({
    key,
    format: 'pem',
    type: 'pkcs1'
  })
}

/**
 * Create public key
 */
export function newPublicKey(key: string): KeyObject {
  return createPublicKey({
    key,
    format: 'pem',
    type: 'pkcs1'
  })
}

/**
 * Delete folder
 */
export function deleteFolder(options: {
  folder: string
}): void {
  const defaultDir = join(homedir(), '.certfy')
  const envDir = envfy.string('CERTFY_DIR', defaultDir)

  let dir = envDir
  if (options.folder !== '')
    dir = join(dir, options.folder)

  if (!existsSync(dir))
    return

  rmSync(dir, {
    recursive: true,
    force: true,
  })
}

/**
 * Read File
 */
export function readFile(options: {
  filename: string
  folder: string
}): string {
  const defaultDir = join(homedir(), '.certfy')
  const envDir = envfy.string('CERTFY_DIR', defaultDir)

  let dir = envDir
  if (options.folder !== '')
    dir = join(dir, options.folder)

  if (!existsSync(dir))
    return ''

  const file = join(dir, options.filename)

  return readFileSync(file, {
    encoding: 'utf8'
  })
}

/**
 * Write file
 */
export function writeFile(options: {
  data: string | Buffer
  filename: string
  folder: string
}): void {
  const defaultDir = join(homedir(), '.certfy')
  const envDir = envfy.string('CERTFY_DIR', defaultDir)

  let dir = envDir
  if (options.folder !== '')
    dir = join(dir, options.folder)

  if (!existsSync(dir))
    mkdirSync(dir, { recursive: true })

  const file = join(dir, options.filename)

  writeFileSync(file, options.data, {
    encoding: 'utf8'
  })
}

/**
 * Request a API endpoint
 */
export async function request<T>(url: string, options: RequestInit = {}): Promise<{
  data: Awaited<T>
  headers: Headers
}> {

  async function parseResponse(response: Response): Promise<T> {
    const contentType = response.headers.get('Content-Type') ?? ''

    if (/application\/([a-zA-Z]+\+)?json/.test(contentType))
      return await response.json()

    return await response.text() as unknown as T
  }

  // Set the method
  options.method ??= 'GET'

  // Set the headers
  options.headers = new Headers(options.headers)

  // Check if the method is POST
  if (options.method === 'POST')
    // Check if the content type is set
    if (!options.headers.has('Content-Type'))
      // Set the default content type
      options.headers.set('Content-Type', 'application/jose+json')

  // Execute the request
  const response = await fetch(url, options)

  // Parse the response
  const data = await parseResponse(response)

  // Check if the response is ok
  if (!response.ok)
    throw data

  return {
    data,
    headers: response.headers
  }
}

/**
 * Create a Certificate Signing Request
 */
export function createCSR(options: {
  commonName: string
  // country?: string
  // locality?: string
  // organization?: string
  // organizationUnit?: string
  // state?: string
  subjectAltNames: string[]
}): { csr: string; privateKey: string; publicKey: string } {


  const { privateKey: cryptoPrivateKey, publicKey: cryptoPublicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    }
  })

  const privateKey = forge.pki.privateKeyFromPem(cryptoPrivateKey)
  const publicKey = forge.pki.publicKeyFromPem(cryptoPublicKey)

  const csr = forge.pki.createCertificationRequest()

  csr.publicKey = publicKey

  csr.setSubject([
    {
      name: 'commonName',
      value: options.commonName
    },
    // {
    //   name: 'countryName',
    //   value: options.country ?? ''
    // },
    // {
    //   shortName: 'ST',
    //   value: options.state ?? ''
    // },
    // {
    //   name: 'localityName',
    //   value: options.locality ?? ''
    // },
    // {
    //   name: 'organizationName',
    //   value: options.organization ?? ''
    // },
    // {
    //   shortName: 'OU',
    //   value: options.organization
    // }
  ])

  csr.setAttributes([
    {
      name: 'extensionRequest',
      extensions: [
        {
          name: 'subjectAltName',
          altNames: options.subjectAltNames.map((name) => ({
            type: 2, // DNS
            value: name
          }))
        }
      ]
    }
  ])

  csr.sign(privateKey, forge.md.sha256.create())

  const csrInASN1 = forge.pki.certificationRequestToAsn1(csr)
  const csrInDER = forge.asn1.toDer(csrInASN1).getBytes()

  return {
    csr: toBase64Url(Buffer.from(csrInDER, 'binary')),
    privateKey: cryptoPrivateKey,
    publicKey: cryptoPublicKey
  }
}

export function certificateToDER(cert: string): string {
  const certInPEM = forge.pki.certificateFromPem(cert)
  const csrInASN1 = forge.pki.certificateToAsn1(certInPEM)
  const csrInDER = forge.asn1.toDer(csrInASN1).getBytes()
  return toBase64Url(Buffer.from(csrInDER, 'binary'))
}
