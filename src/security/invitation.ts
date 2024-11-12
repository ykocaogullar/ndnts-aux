import { CertStorage } from './cert-storage.ts';
import { Certificate, createSigner, ECDSA, ValidityPeriod } from '@ndn/keychain';
import { Name } from '@ndn/packet';
import { Version } from '@ndn/naming-convention2';
import { NamedSigner } from '@ndn/keychain';

export interface InvitationData {
  workspaceCert: Certificate;
  inviteeCert: Certificate;
  // groupEncryptionKey: Uint8Array;  // Todo
  // trustPolicies: string; // Policies governing trust within the workspace
  // signature: Uint8Array; // Digital signature of the inviter (K3)
}

export class InvitationPackage {
  private certStorage?: CertStorage;
  private personal_publicKey?: CryptoKey;
  private personal_privateKey?: CryptoKey;
  private signer?: NamedSigner;
  private email?: Name;
  readyEvent: Promise<void>;

  constructor() {
    // Initialize readyEvent with a resolved Promise
    this.readyEvent = Promise.resolve();
  }

  /** Initialize certStorage with a separate method */
  initializeCertStorage(certStorage: CertStorage) {
    this.certStorage = certStorage;
    this.readyEvent = (async () => {
      await this.certStorage!.readyEvent;
    })();
  }

  /** Get CertStorage's signer if initialized, else use custom signer */
  get signerInstance() {
    if (this.certStorage) {
      return this.certStorage.signer;
    }
    if (!this.signer) {
      throw new Error('Signer is not initialized.');
    }
    return this.signer;
  }

  /** Use CertStorage's certificate if certStorage is initialized */
  get certificate() {
    if (!this.certStorage) {
      throw new Error('certStorage is not initialized.');
    }
    return this.certStorage.certificate;
  }

  async getPublicKey(): Promise<Uint8Array | null> {
    if (!this.personal_publicKey) {
      console.warn('Public key is not set.');
      return null;
    }
    try {
      const publicKeyArrayBuffer = await crypto.subtle.exportKey('spki', this.personal_publicKey);
      return new Uint8Array(publicKeyArrayBuffer);
    } catch (error) {
      console.error('Failed to export public key:', error);
      return null;
    }
  }

  async getPrivateKey(): Promise<Uint8Array | null> {
    if (!this.personal_privateKey) {
      console.warn('Private key is not set.');
      return null;
    }
    try {
      const privateKeyArrayBuffer = await crypto.subtle.exportKey('pkcs8', this.personal_privateKey);
      return new Uint8Array(privateKeyArrayBuffer);
    } catch (error) {
      console.error('Failed to export private key:', error);
      return null;
    }
  }

  pemToArrayBuffer(pem: string): ArrayBuffer {
    // Remove headers, footers, and any whitespace characters like newlines or spaces
    const b64 = pem.replace(/(-----(BEGIN|END) (CERTIFICATE|PRIVATE KEY|PUBLIC KEY)-----|\s|\r|\n)/g, '');

    try {
      // Decode the Base64 string to binary data
      const binaryString = atob(b64);
      const bytes = new Uint8Array(binaryString.length);

      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }

      return bytes.buffer;
    } catch (error) {
      console.error('Failed to decode base64 string. Check that the input is correctly formatted.', error);
      throw error;
    }
  }

  async setKeysFromStrings(privateKeyPem: string, publicKeyPem: string, email: string) {
    try {
      const privateKeyBytes = this.pemToArrayBuffer(privateKeyPem);
      const publicKeyBytes = this.pemToArrayBuffer(publicKeyPem);

      this.personal_privateKey = await crypto.subtle.importKey(
        'pkcs8',
        privateKeyBytes,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign'],
      );

      this.personal_publicKey = await crypto.subtle.importKey(
        'spki',
        publicKeyBytes,
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify'],
      );

      // Set email as Name type
      this.email = new Name(email);

      // Create the signer
      await this.createSigner();

      console.log('Keys successfully set in InvitationPackage');
      console.log('Private Key Info:', {
        type: this.personal_privateKey.type,
        algorithm: this.personal_privateKey.algorithm,
        usages: this.personal_privateKey.usages,
      });

      console.log('Public Key Info:', {
        type: this.personal_publicKey.type,
        algorithm: this.personal_publicKey.algorithm,
        usages: this.personal_publicKey.usages,
      });
    } catch (error) {
      console.error('Failed to set keys:', error);
    }
  }

  /** Create the signer using ECDSA.cryptoGenerate to import the keys */
  private async createSigner() {
    if (!this.personal_privateKey || !this.personal_publicKey || !this.email) {
      throw new Error('Keys or email are not set. Cannot create signer.');
    }

    // Get the private and public key as Uint8Array
    const privateKeyBytes = await this.getPrivateKey();
    const publicKeyBytes = await this.getPublicKey();

    if (!privateKeyBytes || !publicKeyBytes) {
      throw new Error('Failed to retrieve keys as Uint8Array. Ensure keys are properly set.');
    }

    // Generate key pair using cryptoGenerate with imported keys
    const keyPair = await ECDSA.cryptoGenerate({
      importPkcs8: [privateKeyBytes, publicKeyBytes],
    }, true);

    // Construct the full name as email/KEY/randomNumber
    const fullName = new Name([this.email.toString(), 'KEY', Math.floor(Math.random() * 100000).toString()]);

    // Use this constructed Name in createSigner
    this.signer = createSigner(fullName, ECDSA, keyPair);

    console.log('Signer successfully created');
  }

  /** Generate a personal certificate using Certificate.build */
  async generatePersonalCertificate(): Promise<Certificate> {
    if (!this.signer || !this.personal_publicKey || !this.email) {
      throw new Error('Signer, public key, or email is not set.');
    }

    // Construct the certificate name according to the new convention
    const certName = new Name([
      this.email.toString(), // IdentityName (email)
      'KEY',
      '1', // KeyId
      this.email.toString(), // IssuerId (email)
      Version.create(Date.now()), // Version (current timestamp for uniqueness)
    ]);

    console.log(certName);

    // Convert the public key to SPKI format (Uint8Array)
    const publicKeySpki = new Uint8Array(await crypto.subtle.exportKey('spki', this.personal_publicKey));

    // Set the validity period (e.g., 1 year)
    const validityPeriod = new ValidityPeriod(Date.now(), Date.now() + 365 * 24 * 60 * 60 * 1000);

    // Use Certificate.build to create the certificate
    const personalCert = await Certificate.build({
      name: certName,
      publicKeySpki,
      signer: this.signer,
      validity: validityPeriod,
    });

    console.log('Personal certificate generated:', personalCert);

    return personalCert;
  }

  /** Create an invitation using the CertStorage signer */
  createInvitation(inviteeCert: Certificate): InvitationData {
    if (!this.certStorage) {
      throw new Error('certStorage is not initialized.');
    }

    const invitationData = {
      workspaceCert: this.certStorage.trustAnchor,
      inviteeCert,
    };

    return invitationData;
  }

  ////////////////////

  /** Generate a workspace certificate signed by the provided X.509 private key */
  async generateWorkspaceCertificate(
    domainName: string,
    workspaceName: string,
    x509PrivateKeyPem: string,
    x509Certificate: string,
  ): Promise<Certificate> {
    if (!domainName || !workspaceName || !x509PrivateKeyPem || !x509Certificate) {
      throw new Error('Domain name, workspace name, X.509 certificate, or private key is missing.');
    }

    // Concatenate domain name and workspace name
    const identityName = `${domainName}.${workspaceName}`;

    // Construct the certificate name according to the new convention
    const certName = new Name([
      identityName, // IdentityName (email)
      'KEY',
      '1', // KeyId
      domainName, // IssuerId (email)
      Version.create(Date.now()), // Version (current timestamp for uniqueness)
    ]);

    // Generate a new ECDSA key pair for the workspace
    const { privateKey: _workspacePrivateKey, publicKey: workspacePublicKey } = await ECDSA.cryptoGenerate({}, true);

    // Convert the X.509 PEM private key to CryptoKey format for signing
    const x509PrivateKeyBytes = new Uint8Array(this.pemToArrayBuffer(x509PrivateKeyPem));

    const x509SignerKeyPair = await ECDSA.cryptoGenerate(
      {
        importPkcs8: [
          x509PrivateKeyBytes,
          new Uint8Array(
            this.pemToArrayBuffer(
              '-----BEGIN PUBLIC KEY-----MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9nbBuq8RSXfjzvKGOwkWZNA55l700FHc2IS3JTLQhLrS2m7IB6ggjhyupEVu9nWA0VJqi1CBTO5R0sk3e1yDvA==-----END PUBLIC KEY-----',
            ),
          ),
        ],
      },
      true,
    );

    // Construct the full name as email/KEY/randomNumber
    const signername = new Name([identityName, 'KEY', Math.floor(Math.random() * 100000).toString()]);

    // Create the signer using the imported X.509 private key
    const x509Signer = createSigner(signername, ECDSA, x509SignerKeyPair);

    // Set up the validity period (e.g., 1 year from now)
    const validityPeriod = new ValidityPeriod(Date.now(), Date.now() + 365 * 24 * 60 * 60 * 1000);

    // Build and return the workspace certificate, signed by the X.509 private key
    const workspaceCert = await Certificate.build({
      name: certName,
      publicKeySpki: new Uint8Array(await crypto.subtle.exportKey('spki', workspacePublicKey)),
      signer: x509Signer,
      validity: validityPeriod,
    });

    console.log('Workspace certificate generated:', workspaceCert);
    return workspaceCert;
  }
}
