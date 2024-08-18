<p align="center">
  <a href="https://geison.dev/">
    <img width="100" src="https://geison.dev/assets/icons/logo.svg" alt="Logo" />
  </a>
</p>

<h1 align="center">
  Certificate Generator with Let's Encrypt API
</h1>
<div align="center">

Easy to use, fast and lightweight library for Node.js.

<a>
  <img src="https://img.shields.io/github/license/geisonjr/certfy?style=flat" alt="MIT Licence" />
</a>
<a href="https://www.npmjs.com/package/@geisonjr/certfy">
  <img src="https://img.shields.io/npm/v/@geisonjr/certfy?style=flat-square" alt="NPM version" />
</a>
<a href="https://www.npmjs.com/package/@geisonjr/certfy">
  <img src="https://img.shields.io/npm/dt/@geisonjr/certfy?style=flat-square" alt="NPM downloads" />
</a>
</div>

> [!WARNING]
> This project is under development and is not yet ready for use.

## 🌱 Overview

This library is designed to facilitate the generation of certificates using the Let's Encrypt API.

## ✨ Features

- [x] Create a new certificate
- [x] Renew a certificate
- [x] Revoke a certificate
- [ ] Get certificate information

## 🚀 Tecnologies

The following tools were used in the construction of the project:

- [Node.js](https://nodejs.org/en/)
- [TypeScript](https://www.typescriptlang.org/)

## 📦 Install

Use the package manager [npm](https://docs.npmjs.com/),
[yarn](https://classic.yarnpkg.com/lang/en/docs/).

```bash
npm install @geisonjr/certfy
```

```bash
yarn add @geisonjr/certfy
```

## 🏗️ Usage

### Environment Variables

> [!TIP]
> You can use the `.env` file to set the environment variables.
> 
> - `DIRECTORY_PATH`: The path where the certificates will be saved.

```bash
DIRECTORY_PATH=/Users/<username>/certificates
# or
DIRECTORY_PATH=C:\Users\<username>\certificates
# or
DIRECTORY_PATH=./certificates
```

### Example

```typescript
import { Certfy } from '@geisonjr/certfy';

const certfy = new Certfy()

// Create a new certificate
certfy.obtainCertificate({
  domains: ['example.com', 'www.example.com'],
  email: [
    'username@example.com'
  ]
})

// Renew a certificate
certfy.renewCertificate({
  domains: ['example.com', 'www.example.com'],
  email: [
    'username@example.com'
  ]
})

const certificate = fs.readFileSync('fullchain.pem')

// Revoke a certificate
certfy.revokeCertificate(certificate)
```

## 📚 References

- [Let's Encrypt](https://letsencrypt.org/docs)
- [ACME Protocol](https://tools.ietf.org/html/rfc8555)

## 📋 License

This project is under the
[MIT License](https://github.com/geisonjr/certfy/blob/master/LICENSE)
