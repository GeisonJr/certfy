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
- [ ] Support for wildcard domains
- [ ] Scheduled certificate renewal

## 🚀 Tecnologies

The following tools were used in the construction of the project:

- [Node.js](https://nodejs.org/en/)
- [TypeScript](https://www.typescriptlang.org/)
- [Node-Forge](https://www.npmjs.com/package/node-forge)

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
> - `CERTFY_DIR`: The path where the certificates will be saved.

```bash
CERTFY_DIR=/Users/<username>/certificates
# or
CERTFY_DIR=C:\Users\<username>\certificates
# or
CERTFY_DIR=./certificates
```

### Example

```typescript
import { Certificate } from "@geisonjr/certfy";

const cert = new Certificate();

// Create a new certificate
await cert.obtain({
	domains: ["www.example.com", "example.com"],
	email: ["username@example.com"], // Optional
});

// Renew a certificate
await cert.renew({
	domains: ["www.example.com", "example.com"],
	email: ["username@example.com"], // Optional
  force: true, // Optional
  revoke: true, // Optional
  reason: REASON.unspecified, // Optional
});

// Revoke a certificate
const certificate: string = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
const privateKey: string = "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----";

await cert.revoke(certificate, privateKey, {
  reason: REASON.unspecified, // Optional
});
```

#### Can you see a complete example [here](./example/index.ts), to run the example use the following commands:

```bash
npm run example
```

```bash
yarn example
```

## 📚 References

- [Let's Encrypt](https://letsencrypt.org/docs)
- [ACME Protocol](https://tools.ietf.org/html/rfc8555)

## 📋 License

This project is under the
[MIT License](https://github.com/geisonjr/certfy/blob/master/LICENSE)
