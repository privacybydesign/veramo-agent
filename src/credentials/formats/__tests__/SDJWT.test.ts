import { expect, test } from 'vitest';
import { Issuer } from '../../../issuer/Issuer';
import { SDJWT } from '../SDJWT';
import { Credential } from '../../Credential';
import { Factory } from '@muisit/cryptokey';
import { decodeSdJwtSync } from '@sd-jwt/decode';
import { digest } from '@sd-jwt/crypto-nodejs';

async function createCredential(statusType:string, attribute:any)
{
    const issuer = new Issuer({}, {});
    issuer.key = await Factory.createFromType('Secp256r1', "44d2575ca39d5b875b17f3ae372183acd1da561dbbfde6591facbca98b83fb11");
    issuer.did = { did: await Factory.toDIDJWK(issuer.key) };
    issuer.keyRef = issuer.key.exportPublicKey();

    const credential = new Credential();
    credential.issuer = issuer;
    credential.type = 'CredentialTest';
    credential.data = {name:'Test'};
    credential.metaData.credentialStatus = [{
        attribute,
        listIndex: 0,
        index: 12,
        options: {name: 'list', size: 131072, purpose: 'revocation', type: statusType}
    }];
    return credential;
}

async function issue(credential:Credential, format:string)
{
    const sdjwt = new SDJWT(credential, format);
    await sdjwt.build();
    await sdjwt.sign();
    return decodeSdJwtSync(credential.output as string, digest).jwt.payload as any;
}

test('vc+sd-jwt carries the W3C credentialStatus and no IETF status claim', async () => {
    const entry = {
        id: 'https://example.com/sl/list/0#12',
        type: 'BitstringStatusListEntry',
        index: 12,
        statusListCredential: 'https://example.com/sl/list/0',
        statusPurpose: 'revocation',
    };
    const payload = await issue(await createCredential('BitstringStatusList', entry), 'vc+sd-jwt');

    expect(payload.credentialStatus).toEqual(entry);
    expect(payload.status).toBeUndefined();
});

test('vc+sd-jwt drops an IETF status list', async () => {
    const entry = { idx: 12, uri: 'https://example.com/sl/list/0' };
    const payload = await issue(await createCredential('statuslist+jwt', entry), 'vc+sd-jwt');

    expect(payload.credentialStatus).toBeUndefined();
    expect(payload.status).toBeUndefined();
});

test('dc+sd-jwt carries the IETF status claim', async () => {
    const entry = { idx: 12, uri: 'https://example.com/sl/list/0' };
    const payload = await issue(await createCredential('statuslist+jwt', entry), 'dc+sd-jwt');

    expect(payload.status).toEqual({ status_list: entry });
});
