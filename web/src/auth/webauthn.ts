// Helpers for the browser-side WebAuthn ceremony. Each helper translates
// between the JSON envelope the portal API uses (base64url-encoded
// ArrayBuffers) and the binary WebAuthn API expects.

export function b64uToBuf(s: string): ArrayBuffer {
  let t = s.replace(/-/g, '+').replace(/_/g, '/')
  while (t.length % 4) t += '='
  const bin = atob(t)
  const buf = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i)
  return buf.buffer
}

export function bufToB64u(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export interface RegisterBeginResp {
  challenge_id: string
  publicKey: {
    challenge: string
    rp: { id: string; name: string }
    user: { id: string; name: string; displayName: string }
    pubKeyCredParams: { type: string; alg: number }[]
    timeout?: number
    excludeCredentials?: { id: string; type: string; transports?: string[] }[]
    authenticatorSelection?: PublicKeyCredentialCreationOptions['authenticatorSelection']
    attestation?: AttestationConveyancePreference
  }
}

export interface PasskeyRow {
  id: string
  nickname: string
  transports: string[] | null
  created_at: string
  last_used_at: string
}

// runRegisterCeremony asks the authenticator to create a credential and
// returns the JSON envelope our /register/finish endpoint expects.
export async function runRegisterCeremony(begin: RegisterBeginResp): Promise<unknown> {
  // Deep-clone the options so we can mutate string fields into
  // ArrayBuffers without touching the cached React Query response.
  const opts = JSON.parse(JSON.stringify(begin.publicKey)) as any
  opts.challenge = b64uToBuf(opts.challenge)
  opts.user.id = b64uToBuf(opts.user.id)
  ;(opts.excludeCredentials || []).forEach((c: any) => {
    c.id = b64uToBuf(c.id)
  })

  const cred = (await navigator.credentials.create({ publicKey: opts })) as PublicKeyCredential | null
  if (!cred) throw new Error('user cancelled')
  const att = cred.response as AuthenticatorAttestationResponse
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufToB64u(att.attestationObject),
      clientDataJSON: bufToB64u(att.clientDataJSON),
    },
    clientExtensionResults: cred.getClientExtensionResults?.() || {},
  }
}
