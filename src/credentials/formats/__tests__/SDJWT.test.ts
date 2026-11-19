import { expect, test } from 'vitest';
import { Issuer } from '../../../issuer/Issuer';
import { SDJWT } from '../SDJWT';
import { Credential } from '../../Credential';
import { Factory } from '@muisit/cryptokey';
import { decodeSdJwtSync } from '@sd-jwt/decode';
import { digest } from '@sd-jwt/crypto-nodejs';
import { getVctConfigurationStore } from '../../../vct/Store';

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

async function createTypedCredential(configuration:any)
{
    const credential = await createCredential('statuslist+jwt', { idx: 12, uri: 'https://example.com/sl/list/0' });
    credential.issuer!.options = { baseUrl: 'https://issuer.example/org' } as any;
    credential.type = 'RulebookTest';
    credential.data = { name: 'Test', address: { city: 'Utrecht' } };
    credential.configuration = configuration;
    getVctConfigurationStore()['rulebook-test'] = {
        credentials: ['RulebookTest'],
        path: '/vct/rulebook-test',
        fullPath: 'https://issuer.example/vct/rulebook-test',
        document: { vct: 'https://issuer.example/vct/rulebook-test', claims: [{ path: ['address', 'city'], sd: 'allowed' }] } as any,
    };
    return credential;
}

test('a configured vct that is not a URL is issued as-is, with the local disclosure rules', async () => {
    const credential = await createTypedCredential({ format: 'dc+sd-jwt', vct: 'urn:eudi:eucc:1', credential_definition: { type: [] } });
    const sdjwt = new SDJWT(credential, 'dc+sd-jwt');
    await sdjwt.build();
    await sdjwt.sign();
    const decoded = decodeSdJwtSync(credential.output as string, digest);
    const payload = decoded.jwt.payload as any;

    expect(payload.vct).toBe('urn:eudi:eucc:1');
    expect(payload['vct#integrity']).toBeUndefined();
    expect(payload.address._sd).toHaveLength(1);
    expect(decoded.disclosures.map((d) => d.key)).toEqual(['city']);
});

test('without a configured vct the local vct document url is issued', async () => {
    const credential = await createTypedCredential({ format: 'dc+sd-jwt', credential_definition: { type: [] } });
    const payload = await issue(credential, 'dc+sd-jwt');

    expect(payload.vct).toBe('https://issuer.example/vct/rulebook-test');
    expect(payload['vct#integrity']).toBeDefined();
});

test('omit_fed_claim leaves out the fed claim', async () => {
    const withFed = await issue(await createTypedCredential({ format: 'dc+sd-jwt', credential_definition: { type: [] } }), 'dc+sd-jwt');
    const withoutFed = await issue(await createTypedCredential({ format: 'dc+sd-jwt', omit_fed_claim: true, credential_definition: { type: [] } }), 'dc+sd-jwt');

    expect(withFed.fed).toBe('https://issuer.example/org');
    expect(withoutFed.fed).toBeUndefined();
});

async function disclosureKeys(data:any, claims:any[])
{
    const credential = await createTypedCredential({ format: 'dc+sd-jwt', credential_definition: { type: [] } });
    credential.data = data;
    getVctConfigurationStore()['rulebook-test'].document = { vct: 'https://issuer.example/vct/rulebook-test', claims } as any;
    const sdjwt = new SDJWT(credential, 'dc+sd-jwt');
    await sdjwt.build();
    await sdjwt.sign();
    return decodeSdJwtSync(credential.output as string, digest).disclosures.map((d) => d.key ?? '[element]').sort();
}

test('a null path segment discloses the claims inside every array element', async () => {
    const keys = await disclosureKeys({ reps: [{ name: 'A', role: 'x' }, { name: 'B', role: 'y' }] },
        [{ path: ['reps'], sd: 'allowed' }, { path: ['reps', null], sd: 'allowed' }, { path: ['reps', null, 'name'], sd: 'allowed' }]);

    // the elements stay inline because their own claims are disclosed separately
    expect(keys).toEqual(['name', 'name', 'reps']);
});

test('a trailing null path segment discloses each array element', async () => {
    const keys = await disclosureKeys({ tags: ['a', 'b'] }, [{ path: ['tags', null], sd: 'allowed' }]);

    expect(keys).toEqual(['[element]', '[element]']);
});
