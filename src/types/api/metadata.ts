import { CredentialConfigurationDisplay, CredentialDisplay, CredentialFormat, Metadata, SupportedProofTypes } from "#root/types/specification/metadata";
import { StatusListOptions } from "../internal/statuslists.js";

export interface MetadataConfiguration extends Omit<Metadata, 'credential_configurations_supported'> {
    "@context"?: string[];
    credential_configurations_supported:ExtendableCredentialConfigurations;
}

export interface ExtendableCredentialConfigurations {
    [key:string]: ExtendableCredentialConfiguration;
}

export interface ExtendableCredentialConfiguration extends CredentialConfigurationJwtVC {
    extends?:string;
    // a URL is fetched as the type metadata; any other value (e.g. 'urn:eudi:eucc:1') is issued as-is
    vct?:string;
    // leave out the non-standard `fed` claim, for types whose schema forbids extra claims
    omit_fed_claim?:boolean;
    // offer only jwk holder binding, so the credential carries cnf.jwk
    cnf_jwk?:boolean;
    statuslist?: StatusListOptions[];
}

export interface CredentialConfigurationJwtVC {
    format: CredentialFormat;
    scope?:string;                                     // optional scope used in the OAuth process
    cryptographic_binding_methods_supported?:string[]; // cryptographic key material representations supported
    credential_signing_alg_values_supported?:string[]; // array of signing algorithms implemented
    proof_types_supported?:SupportedProofTypes;
    display?:CredentialDisplay[];                      // array of display properties for this credential
    credential_definition: CredentialDefinition;
}

export interface CredentialDefinition {
    type:string[];
    credentialSubject?:CredentialSubjects;
    claims?:CredentialConfigurationClaimData[]; // new style definitions
}

export type ClaimOriginPath = string[];

export interface CredentialConfigurationClaimData {
    path: string[];
    origin?: ClaimOriginPath[]; // an array of paths of possible origins for this specific claim
    mandatory?:boolean;
    value_type?: string;
    display?: CredentialConfigurationDisplay[];
}

// TODO: support nested claims... or move to path descriptions
export interface CredentialSubjects {
    [x:string]:CredentialSubjectConfiguration;
}

export interface CredentialSubjectConfiguration {
    mandatory?: boolean;
    value_type?: string;
    display?: CredentialDisplay[];
    origin?: ClaimOriginPath[]; // an array of paths of possible origins for this specific claim
}