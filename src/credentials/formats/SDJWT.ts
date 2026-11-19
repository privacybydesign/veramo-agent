import Debug from 'debug';
const debug = Debug('issuer:sdjwt');

import { Credential } from '#root/credentials/Credential';
import { SDJwtVcInstance, SdJwtVcPayload } from '@sd-jwt/sd-jwt-vc'
import { DisclosureFrame, Signer } from '@sd-jwt/types'
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { getVctForCredentialType } from "#root/vct/Store";
import { getLocalVctIntegrity, getRemoteVctWithIntegrity } from "#root/vct/Integrity";
import { VctClaimPathElement } from "#root/types/specification/vct";
import { fromString } from 'uint8arrays';
import moment from 'moment';
import { Factory } from '@muisit/cryptokey';
import { VCDM } from './VCDM.js';
import { StatusListCredentialAttributeIETF, StatusListCredentialData } from '#root/types/internal/statuslists';

export class SDJWT
{
    private credential:Credential;
    private baseCredential:any;
    private type:string = 'dc+sd-jwt';
    public constructor(credential:Credential, type:string = 'dc+sd-jwt')
    {
        this.credential = credential;
        this.type = type;
    }

    public async build()
    {
        if (this.type == 'dc+sd-jwt') {
            this.baseCredential = this.credential.data;
        }
        else {
            const cred = new VCDM(this.credential);
            this.baseCredential = await cred.build();
        }
    }

    public async sign()
    {
        debug("signing SD JWT");

        // vct is only set for dc+sd-jwt; a vc+sd-jwt has none, so cast past SdJwtVcPayload's required vct
        const baseCredential = {
            iss: this.credential.issuer!.did!.did,
            ...(!this.credential.configuration?.omit_fed_claim && {fed: this.credential.issuer?.options.baseUrl}),
            iat: moment().unix()
        } as unknown as SdJwtVcPayload;

        let vct:any = null;
        let vctIntegrity:string|null = null;
        const configuredVct = this.credential?.configuration?.vct;
        if (this.type == 'dc+sd-jwt' && configuredVct && !isHttpUrl(configuredVct)) {
            // a type identifier that is not a URL cannot be fetched: issue it as-is and take
            // the disclosure rules from the locally configured vct document
            debug("setting configured vct identifier", configuredVct);
            vct = getVctForCredentialType(this.credential.type!);
            baseCredential.vct = configuredVct;
        }
        else if (this.type == 'dc+sd-jwt') {
            debug("setting vct");
            if (configuredVct) {
                debug("getting vct based on configured value");
                const remote = await getRemoteVctWithIntegrity(configuredVct);
                if (remote) {
                    vct = remote.vct;
                    vctIntegrity = remote.integrity;
                }
                debug("remote vct is ", vct);
            }
            else {
                debug("using locally stored vct");
                vct = getVctForCredentialType(this.credential.type!);
                if (vct) {
                    vctIntegrity = getLocalVctIntegrity(vct);
                }
            }
            if (vct) {
                debug("setting credential vct to ", vct.vct);
                baseCredential.vct = vct.vct;
                if (vctIntegrity) {
                    (baseCredential as any)['vct#integrity'] = vctIntegrity;
                }
            }
            else {
                debug("dc+sd-jwt has NO VCT set");
            }
        }

        if (this.credential.automaticallyBindHolder && this.credential.holder) {
            // https://www.rfc-editor.org/rfc/rfc7800.html
            if (this.credential.holder.type == "kid") {
                baseCredential.cnf = {kid: this.credential.holder.data};
            }
            else if (this.credential.holder.type == "jwk") {
                baseCredential.cnf = {jwk: this.credential.holder.data};
            }
            else if (this.credential.holder.type == "x5c") {
                baseCredential.cnf = {x5c: this.credential.holder.data};
            }
            else {
                throw new Error("Cannot create confirm cnf claim for holder binding for non supported proof type " + this.credential.holder.type);
            }
        }

        // if we have a credentialSubject, convert it to claims
        if (this.baseCredential) {
            Object.keys(this.baseCredential).forEach((k) => {
                baseCredential[k] = this.baseCredential![k];
            });
        }

        if (this.credential.metaData.expirationDate) {
            baseCredential.exp = moment(this.credential.metaData.expirationDate).unix();
        }
        this.addStatusListData(baseCredential);

        const signer: Signer = async (data: string): Promise<string> => {
            return await this.credential.issuer!.key!.sign(this.credential.issuer!.algorithm(), fromString(data, 'utf-8'), 'base64url')
        }

        const sdjwt = new SDJwtVcInstance({
          signer,
          signAlg: this.credential.issuer!.algorithm(),
          hasher: digest,
          saltGenerator: generateSalt,
          hashAlg: 'sha-256',
        });
    
        const disclosureFrame:DisclosureFrame<SdJwtVcPayload> = this.createDisclosureFrameFromVct(vct, baseCredential);
        const sdcredential = await sdjwt.issue(baseCredential, disclosureFrame, {
          header: {
            typ: this.type,
            cty: 'vc',
            kid: '#' + Factory.getKeyReference(this.credential.issuer!.did!.did)
          },
        });
    
        this.credential.output = sdcredential;
    }

    private createDisclosureFrameFromVct(vct:any, payload:any):DisclosureFrame<SdJwtVcPayload>
    {
        let disclosureFrame:DisclosureFrame<SdJwtVcPayload> = {};
        if (vct && vct.claims) {
            const paths:VctClaimPathElement[][] = vct.claims
                .filter((claim:any) => claim.path && (claim.sd === 'allowed' || claim.sd === 'always'))
                .map((claim:any) => claim.path);
            for (const path of paths) {
                // an array element whose own claims are disclosed separately stays inline: wallets such
                // as irmago do not look for disclosures inside a disclosed array element
                if (path[path.length - 1] === null && paths.some((other) => isLongerPathUnder(other, path))) {
                    continue;
                }
                disclosureFrame = this.addPathToDisclosureFrame(disclosureFrame, path, payload);
            }
        }
        return disclosureFrame as DisclosureFrame<SdJwtVcPayload>;
    }

    private addPathToDisclosureFrame(disclosureFrame:DisclosureFrame<SdJwtVcPayload>, path:VctClaimPathElement[], data:any): DisclosureFrame<SdJwtVcPayload>
    {
        // a null segment selects every array element; the frame needs one entry per actual element
        if (path.length > 0 && path[0] === null) {
            if (!Array.isArray(data)) {
                return disclosureFrame;
            }
            const frame = disclosureFrame as any;
            data.forEach((element, index) => {
                if (path.length === 1) {
                    frame._sd = frame._sd ?? [];
                    if (!frame._sd.includes(index)) {
                        frame._sd.push(index);
                    }
                }
                else {
                    frame[index] = this.addPathToDisclosureFrame(frame[index] ?? {}, path.slice(1), element);
                }
            });
            return disclosureFrame;
        }
        if (path.length === 1) {
            if (!disclosureFrame._sd) {
                disclosureFrame._sd = [];
            }
            disclosureFrame._sd.push(path[0] as string);
        }
        else if (path.length > 1) {
            const key = path[0]!;
            if (!disclosureFrame[key]) {
                disclosureFrame[key] = {};
            }
            const remainingPath = path.slice(1);
            const frameToAdd = disclosureFrame[key] as DisclosureFrame<SdJwtVcPayload>;
            const frame = this.addPathToDisclosureFrame(frameToAdd, remainingPath, data?.[key as string]);
            disclosureFrame[key] = frame as any;
        }
        return disclosureFrame;
    }

    // add the status-list data for IETF token lists.
    private addStatusListData(baseCredential:SdJwtVcPayload)
    {
        // a vc+sd-jwt is a VCDM 2.0 credential: its status lives in credentialStatus, set by VCDM.build()
        if (this.type != 'dc+sd-jwt') {
            return;
        }

        // status list data should _always_ be added by the issuer, never by passing prefabricated data.
        // Hence we can be more or less sure of the constitution of the data at this point. It should contain
        // ready to consume StatusListCredentialAttributes
        if (this.credential.metaData.credentialStatus) {
            // array of entries
            const statusses:StatusListCredentialData[] = this.credential.metaData.credentialStatus;
           
            // as opposed to the JOSE implementation, we retain all the available
            // status lists and add them as entries here.
            // However, the IETF spec only allows a single status list. We take the first
            // one if there are more, so SDJWT implementations must restrict the number
            // of configured status lists
            if (statusses.length > 0) {
                // IETF specifies that the status of a JWT is embedded in the status claim
                // as a status_list entry, no matter the encoding.
                // The statuslist agent returns a ready to use return value
                baseCredential.status = {
                    // we cast here to pass the type check, but if it were a BitstringStatusList, it'd be fine
                    // this is very much use case driven, so application defined
                    status_list: statusses[0].attribute as StatusListCredentialAttributeIETF
                };
            }
        }
    }
}
function isHttpUrl(value:string): boolean
{
    return /^https?:\/\//i.test(value);
}

function isLongerPathUnder(other:VctClaimPathElement[], prefix:VctClaimPathElement[]): boolean
{
    return other.length > prefix.length && prefix.every((segment, index) => other[index] === segment);
}
