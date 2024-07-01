'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey

    // I changed this to array /Frej
    this.conns = [] // data for each active connection

    // I changed this to array /Frej
    this.certs = [] // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {

    this.EGKeyPair = await generateEG()

    const certificate = {
      username: username,
      publicKey: this.EGKeyPair.pub
    }
    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)

    if (await verifyWithECDSA(this.caPublicKey, certString, signature)) {
      this.certs.push(certificate)
    }
    else {
      throw ('Certificate not verified!')
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
  async sendMessage (name, plaintext) {

    let receiverConn = null;
    for (let conn of this.conns) {
      if (conn.name == name) {
        receiverConn = conn;
        break;
      }
    }
    let sharedSecret;
    if (receiverConn == null) {
      let receiverCert = null;
      for (let cert of this.certs) {
        if (cert.username == name) {
          receiverCert = cert;
          break;
        }
      }
      if (receiverCert != null) {
        sharedSecret = await computeDH(this.EGKeyPair.sec, receiverCert.publicKey);
        // Shared secret is input to root chain.

        receiverConn = {
          username: name,
          certificate: receiverCert,
          kdfKeys: {
            rootChain: null,
            sendingChain: null, //chain key
            receivingChain: null //chain key
          }
        };
        this.conns.push(receiverConn);
      }
      else {
        throw ('No certificate found!');
      }
    }

    // encrypt plaintext with symmetric encryption (AES-GCM) using messageKey,
    // which is the output from the sending KDF chain

    // TODO: Update keys

    // TODO: HKDF step, save state in conn, do encryption
    // TODO: Use correct key
    let aesKey = await HMACtoAESKey(sharedSecret, "constant");

    let iv = genRandomSalt();

    const header = {
      publicKey: this.EGKeyPair.pub,
      iv: iv
    }

    const ciphertext = await encryptWithGCM(aesKey, plaintext, iv);
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {

    // TODO: Only compute new DH when necessary.
    let dhOutput = await computeDH(this.EGKeyPair.sec, header.publicKey);

    // TODO: Ratchet steps

    // TODO: Use correct key
    let aesKey = await HMACtoAESKey(dhOutput, "constant");

    let plaintext = await decryptWithGCM(aesKey, ciphertext, header.iv);
    return bufferToString(plaintext);
  }
};

module.exports = {
  MessengerClient
}
