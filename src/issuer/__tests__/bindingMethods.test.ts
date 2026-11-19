import { expect, test } from 'vitest';
import { Issuer } from '../Issuer';

function bindingMethods(config:any)
{
    const issuer = new Issuer({ baseUrl: 'https://issuer.example/org' } as any, {
        credential_configurations_supported: { Test: { format: 'dc+sd-jwt', credential_definition: { type: [] }, ...config } },
    } as any);
    return (issuer.generateMetadata().credential_configurations_supported as any).Test.cryptographic_binding_methods_supported;
}

test('the default binding methods are the did methods', () => {
    expect(bindingMethods({})).toEqual(['did:jwk', 'did:key']);
});

test('cnf_jwk offers only jwk binding', () => {
    expect(bindingMethods({ cnf_jwk: true })).toEqual(['jwk']);
});
