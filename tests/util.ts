// Copyright (c) 2023 Apple Inc. Licensed under MIT License.

import * as fs from 'fs';
import {Environment} from '../models/Environment';
import {SignedDataVerifier} from '../jws_verification';
import {ECKeyPairOptions, generateKeyPairSync} from 'crypto';
import jsonwebtoken = require('jsonwebtoken');
import {WorkerSignedDataVerifier} from "../worker_jws_verification";

const defaultUseWorkVerifier = true;

export function readFile(path: string): string {
    return fs.readFileSync(path, {
        encoding: 'utf8'
    })
}

export function readBytes(path: string): Buffer {
    return fs.readFileSync(path)
}

export function getSignedPayloadVerifier(environment: Environment, bundleId: string, appAppleId: number,
                                         certificatesDERFiles: string[] = ['tests/resources/certs/testCA.der'],
                                         useWorkVerifier: boolean = defaultUseWorkVerifier): SignedDataVerifier {
    const certBuffers: Buffer[] = certificatesDERFiles.map((derFile: string) => readBytes(derFile));
    if (useWorkVerifier) {
        const pemFormat = certificatesDERFiles[0].endsWith('.pem')
        return new WorkerSignedDataVerifier(certBuffers, pemFormat, false, environment, bundleId, appAppleId)

    } else {
        return new SignedDataVerifier(certBuffers, false, environment, bundleId, appAppleId)
    }
}

export function getSignedPayloadVerifierWithDefaultAppAppleId(environment: Environment, bundleId: string): SignedDataVerifier {
    return getSignedPayloadVerifier(environment, bundleId, 1234)
}

export function getDefaultSignedPayloadVerifier(): SignedDataVerifier {
    return getSignedPayloadVerifierWithDefaultAppAppleId(Environment.LOCAL_TESTING, "com.example")
}

export function createSignedDataFromJson(path: string): string {
    const fileContents = readFile(path)
    const keyPairOptions: ECKeyPairOptions<'pem', 'pem'> = {
        namedCurve: 'prime256v1',
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    }
    const keypair = generateKeyPairSync("ec", keyPairOptions)
    const privateKey = keypair.privateKey
    return jsonwebtoken.sign(fileContents, privateKey, {algorithm: 'ES256'});
}
