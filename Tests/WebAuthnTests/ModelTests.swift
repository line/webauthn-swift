// Copyright 2024 LY Corporation
//
// LY Corporation licenses this file to you under the Apache License,
// version 2.0 (the "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at:
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

import XCTest
@testable import WebAuthn

final class ModelTests: XCTestCase {
    let rpId = "ios:test-rp-id"
    let aaguid = UUID.init(uuidString: "00000000-ffff-ffff-ffff-000000000000")!
    let credentialId = generateRandomBytes(len: 32)!
    var attestedCredData: AttestedCredentialData {
        let privateKey = try! generatePublicPrivateKeyPair(kSecAttrKeyTypeECSECPrimeRandom as String, 256).get()
        let pubKey = getPublicKey(privateKey)!
        let cborPubKey = try! convertSecKeyToCborEc2coseKey(pubKey).get()
        return AttestedCredentialData(aaguid: aaguid, credentialId: credentialId, publicKey: cborPubKey)
    }
    let extsOut = AuthenticatorExtensionsOutput()

    func testNoneAttestationObjectWithoutAttestedCredentialDataAndExtension() throws {
        let authData = AuthenticatorData(rpId.toSHA256()!, true, true, UInt32(0), nil, nil)
        let attestationObject = NoneAttestationObject(authData: authData.toData())
        let encoded = try! attestationObject.toCBOR().get()
        let decoded = try! NoneAttestationObject.decode(encoded).get()
        XCTAssertEqual(decoded.authData, authData.toData())
    }

    func testNoneAttestationObjectWithoutAttestedCredentialData() throws {
        let authData = AuthenticatorData(rpId.toSHA256()!, true, true, UInt32(0), nil, extsOut)
        let attestationObject = NoneAttestationObject(authData: authData.toData())
        let encoded = try! attestationObject.toCBOR().get()
        let decoded = try! NoneAttestationObject.decode(encoded).get()
        XCTAssertEqual(decoded.authData, authData.toData())
    }

    func testNoneAttestationObjectWithoutExtension() throws {
        let authData = AuthenticatorData(rpId.toSHA256()!, true, true, UInt32(0), attestedCredData, nil)
        let attestationObject = NoneAttestationObject(authData: authData.toData())
        let encoded = try! attestationObject.toCBOR().get()
        let decoded = try! NoneAttestationObject.decode(encoded).get()
        XCTAssertEqual(decoded.authData, authData.toData())
    }

    func testNoneAttestationObject() throws {
        let authData = AuthenticatorData(rpId.toSHA256()!, true, true, UInt32(0), attestedCredData, extsOut)
        let attestationObject = NoneAttestationObject(authData: authData.toData())
        let encoded = try! attestationObject.toCBOR().get()
        let decoded = try! NoneAttestationObject.decode(encoded).get()
        XCTAssertEqual(decoded.authData, authData.toData())
    }
}


