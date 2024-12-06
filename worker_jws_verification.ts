import {SignedDataVerifier, VerificationException, VerificationStatus} from "./jws_verification";
import {Validator} from "./models/Validator";
import {Environment} from "./models/Environment";
import base64url from "base64url";
import {KEYUTIL, KJUR, X509, zulutodate} from "jsrsasign";
import jsonwebtoken = require('jsonwebtoken');

const MAX_SKEW = 60000
const pemPrefix = '-----BEGIN CERTIFICATE-----'
const pemPostfix = '-----END CERTIFICATE-----'

export class WorkerSignedDataVerifier extends SignedDataVerifier {

    private static newX509Cert(certBuffer: Buffer, pemFormat: boolean = false): X509 {
        let pem: string
        if (!pemFormat) {
            pem = certBuffer.toString('base64').trim();
        } else {
            pem = certBuffer.toString().trim();
        }

        //内容已经是Base64编码了，只需加header、footer即可
        if (!pem.startsWith(pemPrefix)) {//transform to pem format
            pem = `${pemPrefix}\n${pem}\n${pemPostfix}`
        }

        try {
            const x509 = new X509()
            x509.readCertPEM(pem)
            return x509
        } catch (e) {

            throw new VerificationException(VerificationStatus.INVALID_CERTIFICATE, new Error(`Bad cert format!${e}`))
        }
    };

    private readonly appleRootCertificates: X509[];

    constructor(appleRootCertificates: Buffer[], certPEMFormat: boolean, enableOnlineChecks: boolean, environment: Environment, bundleId: string, appAppleId?: number) {
        super([], enableOnlineChecks, environment, bundleId, appAppleId)

        this.appleRootCertificates = appleRootCertificates.map(cert => WorkerSignedDataVerifier.newX509Cert(cert, certPEMFormat))
    }

    protected async verifyJWT<T>(jwt: string, validator: Validator<T>, signedDateExtractor: (decodedJWT: T) => Date): Promise<T> {
        jwt = jwt.trim()
        let certificateChain;
        let decodedJWT
        try {
            decodedJWT = jsonwebtoken.decode(jwt)
            if (!validator.validate(decodedJWT)) {
                this.throwVerifyErr(VerificationStatus.FAILURE, 'Bad decodedJWT')
            }

            if (this.environment === Environment.XCODE || this.environment === Environment.LOCAL_TESTING) {
                // Data is not signed by the App Store, and verification should be skipped
                // The environment MUST be checked in the public method calling this
                return decodedJWT as T
            }

            const header = jwt.split('.')[0]
            const decodedHeader = base64url.decode(header)
            const headerObj = JSON.parse(decodedHeader)
            const chain: string[] = headerObj['x5c'] ?? []
            const alg: string = headerObj['alg']
            if (chain.length != 3) {
                this.throwVerifyErr(VerificationStatus.INVALID_CHAIN_LENGTH, 'INVALID_CHAIN_LENGTH')
            }
            certificateChain = chain.slice(0, 2).map(cert => WorkerSignedDataVerifier.newX509Cert(Buffer.from(cert), true))

            const effectiveDate = this.enableOnlineChecks ? new Date() : signedDateExtractor(decodedJWT as T)
            const publicKey = await this.verifyCertChain(this.appleRootCertificates, certificateChain[0], certificateChain[1], effectiveDate);
            const encodedKey = KEYUTIL.getPEM(publicKey);

            const isValid = KJUR.jws.JWS.verifyJWT(jwt, encodedKey, {alg: [alg]});
            if (!isValid) {
                this.throwVerifyErr(VerificationStatus.VERIFICATION_FAILURE, 'JWT verify failed with public key')
            }
            //jsonwebtoken.verify(jwt, encodedKey) as T
            return decodedJWT as T
        } catch (error) {
            if (error instanceof VerificationException) {
                throw error
            } else if (error instanceof Error) {
                throw new VerificationException(VerificationStatus.VERIFICATION_FAILURE, error)
            }
            throw new VerificationException(VerificationStatus.VERIFICATION_FAILURE)
        }
    }

    protected async verifyCertChain(trustedRoots: X509[], leaf: X509, intermediate: X509, effectiveDate: Date) {
        let rootCert
        for (const root of trustedRoots) {
            if (intermediate.getIssuerString() === root.getSubjectString() && intermediate.verifySignature(root.getPublicKey())) {
                rootCert = root
                break;
            }
        }
        this.verifyAssertTrue(rootCert != null, 'No trusted root for intermediate!')

        this.verifyAssertTrue(
            leaf.getIssuerString() === intermediate.getSubjectString() && leaf.verifySignature(intermediate.getPublicKey()),
            'Bad leaf and intermediate chain!'
        )

        const basicConstraints = intermediate.getExtBasicConstraints();
        const intermediateIsCA = basicConstraints && basicConstraints.cA;
        this.verifyAssertTrue(intermediateIsCA === true, 'Intermediate not CA!')

        this.verifyAssertTrue(leaf.getExtInfo('1.2.840.113635.100.6.11.1') !== undefined, 'Leaf no 1.2.840.113635.100.6.11.1')
        this.verifyAssertTrue(intermediate.getExtInfo('1.2.840.113635.100.6.2.1') !== undefined, 'Intermediate no 1.2.840.113635.100.6.2.1')

        this.verifyAssertTrue(this.checkCertDates(leaf, effectiveDate), 'Leaf time expired!')
        this.verifyAssertTrue(this.checkCertDates(intermediate, effectiveDate), 'Intermediate time expired!')
        this.verifyAssertTrue(this.checkCertDates(rootCert as X509, effectiveDate), 'Root time expired!')

        // if (this.enableOnlineChecks) {
        //     await Promise.all([this.checkOCSPStatus(leaf, intermediate), this.checkOCSPStatus(intermediate, rootCert)])
        // }

        return leaf.getPublicKey();
    }

    private verifyAssertTrue(condition: boolean, errMsg?: string) {
        if (!condition) this.throwVerifyErr(VerificationStatus.INVALID_CERTIFICATE, errMsg)
    }

    private checkCertDates(cert: X509, effectiveDate: Date) {
        let notBefore = zulutodate(cert.getNotBefore());
        let notAfter = zulutodate(cert.getNotAfter());
        let effectiveTime = effectiveDate.getTime();
        if ((effectiveTime + MAX_SKEW) < notBefore.getTime() || (effectiveTime - MAX_SKEW) > notAfter.getTime()) {
            return false
        }

        return true
    }

}
