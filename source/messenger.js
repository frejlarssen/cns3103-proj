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

class Connection {
  constructor (name, certificate) {
    this.name = name
    this.certificate = certificate
    this.dhRachetKeyPair = {
      pub: null,
      priv: null
    }
    this.dhRemoteKey = null
    this.rootKey = null
    this.chainKeys = {
      sending: null,
      receiving: null
    }
    this.messageNumbers = {
      sending: 0,
      receiving: 0
    }
    this.messageNumbersPrevious = 0
    //this.messageKeysSkipped = []
  }
}

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

  findConn(name) {
    let specificConn = null;
    for (let conn of this.conns) {
      if (conn.user == name) {
        specificConn = conn;
        break;
      }
    }
    return specificConn;
  }

  findCert (name) {
    let specificCert = null;
    for (let cert of this.certs) {
      if (cert.username == name) {
        specificCert = cert;
        break;
      }
    }
    return specificCert;
  }

  async ratchetEncrypt (conn, plaintext) {
    // TODO: constantSalt is very arbitrarily defined and should in fact be constant
    let constantSalt = await HMACtoHMACKey(conn.chainKeys.sending, "constant");
    let messageKey;
    [conn.chainKeys.sending, messageKey] = await HKDF(conn.chainKeys.sending, constantSalt, "ratchet-str");
    let header = {
      dhPub: conn.dhRachetKeyPair.pub,
      messageNumbersPrevious: conn.messageNumbersPrevious,
      messageNumbersSending: conn.messageNumbersSending
    }
    conn.messageNumbersSending += 1;
    let aesKey = await HMACtoAESKey(messageKey, "constant");
    let iv = genRandomSalt();
    let ciphertext = await encryptWithGCM(aesKey, plaintext, iv);
    return [header, ciphertext]
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

    let conn = this.findConn(name);
    let intermediateSecret;

    if (conn == null) {
      let receiverCert = this.findCert(name);
      //console.log("rec cert: ");
      //console.log(receiverCert);
      if (receiverCert != null) {
        let secretKey = await computeDH(this.EGKeyPair.sec, receiverCert.publicKey);
        conn = new Connection(name, receiverCert);
        let keyPair = await generateEG();
        conn.dhRachetKeyPair.pub = keyPair.pub;
        conn.dhRachetKeyPair.priv = keyPair.sec;
        conn.dhRemoteKey = receiverCert.publicKey;
        intermediateSecret = await computeDH(conn.dhRachetKeyPair.priv, conn.dhRemoteKey);
        //console.log("secretKey:")
        //console.log(secretKey)
        let hkdfOutput = await HKDF(secretKey, intermediateSecret, "ratchet-str");
        [conn.rootKey, conn.chainKeys.sending] = hkdfOutput;
        this.conns.push(conn);
      }
      else {
        throw ('No certificate found!');
      }
    }

    return await this.ratchetEncrypt (conn, plaintext);
  }

  trySkippedMessageKeys (conn, header, ciphertext) {
    return null;
  }

  async dhRatchet (conn, header) {
    //console.log("in dhRatchet");
    conn.messageNumbersPrevious = conn.messageNumbersSending;
    conn.messageNumbers.sending = 0;
    conn.messageNumbers.receiving = 0;
    conn.dhRemoteKey = header.dhPub;
    let dhOutput = await computeDH(conn.dhRachetKeyPair.priv, conn.dhRemoteKey);
    //console.log("conn.rootKey in dhRatchet:");
    //console.log(conn.rootKey);
    //console.log("dhOutput in dhRatchet:");
    //console.log(dhOutput);
    //console.log("after dhOutput");
    [conn.rootKey, conn.chainKeys.receiving] = await HKDF(conn.rootKey, dhOutput);
    //console.log("conn.chainKeys.receiving after initialization:");
    //console.log(conn.chainKeys.receiving);
    conn.dhRachetKeyPair = generateEG();
    [conn.rootKey, conn.chainKeys.receiving] = await HKDF(conn.rootKey, dhOutput);
  }

  async ratchetDecrypt (conn, header, ciphertext) {
    let plaintext = this.trySkippedMessageKeys(conn, header, ciphertext);
    if (plaintext != null) {
      return plaintext;
    }
    if (header.dhPub != conn.dhRemoteKey) {
      // TODO: skipMessageKeys()
      console.log("dhRatchet()");
      this.dhRatchet(conn, header);
    }
    // TODO: skipMessageKeys()
    // TODO: constantSalt is very arbitrarily defined and should in fact be constant
    console.log("conn.chainKeys.receiving:");
    console.log(conn.chainKeys.receiving);
    let constantSalt = await HMACtoHMACKey(conn.chainKeys.receiving, "constant");
    let messageKey;
    [conn.chainKeys.receiving, messageKey] = await HKDF(conn.chainKeys.receiving, constantSalt, "ratchet-str");
    conn.messageNumbers.receiving += 1;
    let aesKey = await HMACtoAESKey(messageKey, "constant");
    let iv = genRandomSalt();
    return await decryptWithGCM(aesKey, ciphertext, iv);
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

    let conn = this.findConn(name);

    if (conn == null) {
      // TODO: Authenticate header
      let senderCert = this.findCert(name);
      if (senderCert != null) {
        conn = new Connection(name, senderCert);
        conn.dhRachetKeyPair.priv = this.EGKeyPair.sec;
        conn.dhRachetKeyPair.pub = this.EGKeyPair.pub;

        conn.rootKey = await computeDH(this.EGKeyPair.sec, senderCert.publicKey);
      }
      else {
        throw ('No certificate found!');
      }
    }

    return this.ratchetDecrypt(conn, header, ciphertext);
  }
};

module.exports = {
  MessengerClient
}
