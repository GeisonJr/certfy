import { Certificate } from '../src'
import { readFile } from '../src/util'

(async () => {
  const cert = new Certificate({
    staging: true // Change this to false or remove it to use the production environment
  })

  try {

    // The domains to request a certificate for (wildcards are not supported)
    const domains = ['example.dev', 'www.example.dev'] // Caution: The first domain in the array gets used as the folder name

    // The email address to use for the ACME account
    const email = ['username@example.dev']

    console.log('Obtaining certificate...')

    // Obtaining a new certificate
    await cert.obtain({
      domains,
      email
    })

    console.log('Certificate obtained')

    console.log('Renewing certificate...')

    // Renew the certificate, forcing the renewal even if the certificate is not expired
    await cert.renew({
      domains,
      email,
      force: true, // Force the renewal, even if the certificate is not expired
      revoke: true // Revoke the old certificate after renewal
    })

    console.log('Certificate renewed')

    console.log('Revoking certificate...')

    // Revoke the issued certificate
    const certificate = readFile({
      filename: 'cert.pem',
      folder: domains[0]
    })

    const privateKey = readFile({
      filename: 'privkey.pem',
      folder: domains[0]
    })

    await cert.revoke(certificate, privateKey)

    console.log('Certificate revoked')
  } catch (error) {
    console.log(error)
  }
})()
