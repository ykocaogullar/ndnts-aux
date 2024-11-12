import type { Signer, Verifier } from '@ndn/packet';
import { InvitationData } from './invitation.ts';

export interface SecurityAgent {
  signer: Signer;
  verifier: Verifier;
}

export { InvitationData };
