import { Decoder, Encoder } from '@ndn/tlv';
import { Component, Data, Interest, Name, Signer, LLSign, ValidityPeriod, Verifier } from '@ndn/packet';
import { Certificate, createSigner, createVerifier, ECDSA } from '@ndn/keychain';
import * as endpoint from '@ndn/endpoint';
import type { Forwarder } from '@ndn/fw';
import { Version } from '@ndn/naming-convention2';
import { Storage } from '../storage/mod.ts';
import { SecurityAgent } from './types.ts';


// Define the invitation data
interface InvitationData {
  workspaceCert: Certificate;  // Workspace certificate
  inviteeCert: Certificate;    // Invitee's certificate
  //groupEncryptionKey: Uint8Array;  // Todo
  trustPolicies: string;  // Policies governing trust within the workspace
  signature: Uint8Array;      // Digital signature of the inviter (K3)
}

/**
 * A Signer & Verifier handling cross-zone trust relation.
 */
// TODO: (Urgent) Add test to this class
export class InvitationPackage implements SecurityAgent {
  private _signer: Signer | undefined;
  readonly readyEvent: Promise<void>;
  // private trustedNames: string[] = [];  // TODO: Not used for now.

  constructor(
    readonly trustAnchor: Certificate,
    readonly ownCertificate: Certificate,
    readonly storage: Storage,
    readonly fw: Forwarder,
    prvKeyBits: Uint8Array,
  ) {
    this.readyEvent = (async () => {
      await this.importCert(trustAnchor);
      await this.importCert(ownCertificate);
      const keyPair = await ECDSA.cryptoGenerate({
        importPkcs8: [prvKeyBits, ownCertificate.publicKeySpki],
      }, true);
      this._signer = createSigner(
        ownCertificate.name.getPrefix(ownCertificate.name.length - 2),
        ECDSA,
        keyPair,
      ).withKeyLocator(ownCertificate.name);
    })();
  }

  /** Obtain the signer */
  get signer() {
    return this._signer!;
  }

  /** Obtain this node's own certificate */
  get certificate() {
    return this.ownCertificate;
  }

  /** Import an external certificate into the storage */
  async importCert(cert: Certificate) {
    await this.storage.set(cert.name.toString(), Encoder.encode(cert.data));
  }

  /**
   * Fetch a certificate based on its name from local storage and then remote.
   * @param keyName The certificate's name.
   * @param localOnly If `true`, only look up the local storage without sending an Interest.
   * @returns The fetched certificate. `undefined` if not found.
   */
  async getCertificate(keyName: Name, localOnly: boolean): Promise<Certificate | undefined> {
    const certBytes = await this.storage.get(keyName.toString());
    if (certBytes === undefined) {
      if (localOnly) {
        return undefined;
      } else {
        try {
          const result = await endpoint.consume(
            new Interest(
              keyName,
              Interest.MustBeFresh,
              Interest.Lifetime(5000),
            ),
            {
              // Fetched key must be signed by a known key
              // TODO: Find a better way to handle security
              verifier: this.localVerifier,
              retx: 20,
              fw: this.fw,
            },
          );

          // Cache result certificates. NOTE: no await needed
          this.storage.set(result.name.toString(), Encoder.encode(result));

          return Certificate.fromData(result);
        } catch {
          //console.error(`Failed to fetch certificate: ${keyName.toString()}`);
          return undefined;
        }
      }
    } else {
      return Certificate.fromData(Decoder.decode(certBytes, Data));
    }
  }

  /**
   * Verify a packet. Throw an error if failed.
   * @param pkt The packet to verify.
   * @param localOnly If `true`, only look up the local storage for the certificate.
   */
  async verify(pkt: Verifier.Verifiable, localOnly: boolean) {
    const keyName = pkt.sigInfo?.keyLocator?.name;
    if (!keyName) {
      throw new Error(`Data not signed: ${pkt.name.toString()}`);
    }
    const cert = await this.getCertificate(keyName, localOnly);
    if (cert === undefined) {
      throw new Error(`No certificate: ${pkt.name.toString()} signed by ${keyName.toString()}`);
    }
    const verifier = await createVerifier(cert, { algoList: [ECDSA] });
    try {
      await verifier.verify(pkt);
    } catch (error) {
      throw new Error(`Unable to verify ${pkt.name.toString()} signed by ${keyName.toString()} due to: ${error}`);
    }
  }

  /** Obtain an verifier that fetches certificate */
  get verifier(): Verifier {
    return {
      verify: (pkt) => this.verify(pkt, false),
    };
  }

  /** Obtain an verifier that does not fetch certificate remotely */
  get localVerifier(): Verifier {
    return {
      verify: (pkt) => this.verify(pkt, true),
    };
  }

  public static async create(
    trustAnchor: Certificate,
    ownCertificate: Certificate,
    storage: Storage,
    fw: Forwarder,
    prvKeyBits: Uint8Array,
  ) {
    const result = new InvitationPackage(
      trustAnchor,
      ownCertificate,
      storage,
      fw,
      prvKeyBits,
    );
    await result.readyEvent;
    return result;
  }

  // Function to create an invitation
async createInvitation(
  inviteeCert: Certificate,      // Invitee's certificate (K1 → K1')
  trustPolicies: string          // Trust policies for the workspace
): Promise<InvitationData> {
  // Step 1: Create the invitation data object using `trustAnchor` as the workspace certificate
  const invitationData = {
    workspaceCert: this.trustAnchor,  // Using the trustAnchor as the workspace certificate
    inviteeCert,                 // Invitee's certificate
    trustPolicies,               // Trust policies as a string
    signature: new Uint8Array(), // Signature placeholder to be filled later
  };

  // Step 2: Serialize the invitation data (excluding signature for now)
  const serializedData = this.serializeInvitation(invitationData);

  // Step 3: Create the Signable object
  const name = new Name([
    ...this.trustAnchor.name.comps,              // <workspace> components from trustAnchor
    ...this.ownCertificate.name.comps,           // <inviter> components from ownCertificate
    Component.from("INVITE"),                    // Convert "INVITE" to a Component
    ...inviteeCert.name.getPrefix(-1).comps,     // Extract components from <invitee>
    Component.from(Date.now().toString()),       // Convert timestamp to a Component
  ]);

  // Step 4: Create a Data packet with the constructed name and serialized invitation data
  const dataPacket = new Data(name);
  dataPacket.content = serializedData;  // Set the serialized invitation data as the content

  // Step 5: Use the existing signer (this.signer) to sign the Data packet
  await this.signer.sign(dataPacket);

  // Step 6: After signing, the signature is stored within the Data packet
  // Extract the signature from the Data packet if needed
  const signature = dataPacket.sigValue;  // This contains the signature

  // Step 7: Store the signature in the invitation data
  invitationData.signature = signature;

  // Step 8: Return the completed invitation data
  return invitationData;
}

// Helper function to serialize invitation data (excluding signature)
serializeInvitation(data: Omit<InvitationData, "signature">): Uint8Array {
  // Convert the relevant fields of the invitation to a binary format for signing
  const jsonData = {
    workspaceCert: data.workspaceCert.data,  // Get the raw certificate data
    inviteeCert: data.inviteeCert.data,      // Get the invitee's raw certificate data
    trustPolicies: data.trustPolicies,       // Trust policies as a string
  };

  // Return a Uint8Array that represents the serialized invitation
  return new TextEncoder().encode(JSON.stringify(jsonData));
}

// Define the function that takes a serialized invitation and deserializes it back into an InvitationData object
deserializeInvitation(serializedInvitation: Uint8Array): InvitationData {
  // Step 1: Convert the Uint8Array back into a string (assuming it's JSON-encoded)
  const jsonString = new TextDecoder().decode(serializedInvitation);
  
  // Step 2: Parse the JSON string back into an object
  const parsedData = JSON.parse(jsonString);
  
  // Step 3: Recreate the certificates from the parsed data
  const workspaceCert = Certificate.fromData(parsedData.workspaceCert);
  const inviteeCert = Certificate.fromData(parsedData.inviteeCert);
  
  // Step 4: Return the reconstructed InvitationData object
  return {
    workspaceCert: workspaceCert,            // Reconstructed workspace certificate
    inviteeCert: inviteeCert,                // Reconstructed invitee certificate
    trustPolicies: parsedData.trustPolicies, // Trust policies as a string
    signature: parsedData.signature          // Signature as a Uint8Array
  };
}

}
