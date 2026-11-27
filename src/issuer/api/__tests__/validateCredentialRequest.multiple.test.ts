import { vi, expect, test } from 'vitest';
import { ErrorCodes, CredentialOfferStatus } from '#root/types/api';
import { Issuer } from '#root/issuer/Issuer';
import { Session } from '#root/database/entities/index';

vi.mock('#root/issuer/lib/verifyAccessTokenJWT', () => ({
    verifyAccessTokenJWT: vi.fn(),
}));

import { verifyAccessTokenJWT } from '#root/issuer/lib/verifyAccessTokenJWT';
import { validateCredentialRequest } from '../validateCredentialRequest';

// A pre-authorized offer for two credentials, which the wallet collects with one
// credential request each.

function newIssuer() {
    const issuer = new Issuer(
        { name: 'issuer', baseUrl: 'https://example.com/issuer', did: '' },
        { credential_configurations_supported: {}, credential_issuer: '', credential_endpoint: '' }
    );
    issuer.did = { did: 'did:example:123' } as any;
    return issuer;
}

function newSession(status: CredentialOfferStatus, emailIssued: boolean, pidIssued: boolean) {
    const session = new Session();
    session.uuid = 'sess-1';
    session.state = 'state-1';
    session.expirationDate = new Date(Date.now() + 60000);
    session.data = {
        credentialOffer: { grants: { 'urn:ietf:params:oauth:grant-type:pre-authorized_code': { 'pre-authorized_code': 'x', authorization_server: 'https://example.com/issuer' } } },
        status,
        credentialDataSets: {
            'email#0': { id: 'email#0', credentialId: 'email', credentialConfiguration: { format: 'jwt_vc_json' }, data: {}, issued: emailIssued },
            'pid#1': { id: 'pid#1', credentialId: 'pid', credentialConfiguration: { format: 'jwt_vc_json' }, data: {}, issued: pidIssued },
        },
    } as any;
    return session;
}

async function request(session: Session, credentialConfigurationId: string) {
    const issuer = newIssuer();
    vi.spyOn(issuer, 'getSessionByState').mockResolvedValue(session);
    vi.spyOn(issuer, 'storeSession').mockResolvedValue(undefined as any);
    vi.mocked(verifyAccessTokenJWT).mockResolvedValue({
        payload: { iss: issuer.options.baseUrl, issuer_state: session.state },
    } as any);
    const req = {
        body: { credential_configuration_id: credentialConfigurationId, proofs: { jwt: ['not-a-jwt'] } },
        header: (name: string) => (name === 'Authorization' ? 'Bearer some-access-token' : undefined),
    } as any;
    // A request that passes the checks under test goes on to the proof, which is garbage here
    // and fails as a thrown parse error rather than an ApiState.
    return await validateCredentialRequest(issuer, req).catch((e) => e);
}

test('accepts the second credential of an offer after the first was issued', async () => {
    const result = await request(newSession(CredentialOfferStatus.CREDENTIAL_REQUEST_RECEIVED, true, false), 'pid');
    expect(result).toBeInstanceOf(Error);
});

test('refuses a credential of the offer that was already issued', async () => {
    const result = await request(newSession(CredentialOfferStatus.CREDENTIAL_REQUEST_RECEIVED, true, false), 'email');
    expect(result.error).toBe(ErrorCodes.INVALID_CREDENTIAL_REQUEST);
    expect(result.description).toBe('Credential already issued');
});

test('refuses any request once every credential of the offer was issued', async () => {
    const result = await request(newSession(CredentialOfferStatus.CREDENTIAL_ISSUED, true, true), 'pid');
    expect(result.error).toBe(ErrorCodes.INVALID_REQUEST);
    expect(result.description).toBe('No access token created');
});

test('refuses a pre-authorized request before a token was created', async () => {
    const result = await request(newSession(CredentialOfferStatus.OFFER_CREATED, false, false), 'email');
    expect(result.error).toBe(ErrorCodes.INVALID_REQUEST);
    expect(result.description).toBe('No access token created');
});
