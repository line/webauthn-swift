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

final class EC2COSEKeyTests: XCTestCase {
    private let ec2Algorithms: [COSEAlgorithmIdentifier] = [.ES256, .ES384, .ES512]

    func testCreateFromEveryEC2Algorithm() throws {
        let expectedCoordinateLengths = [COSEAlgorithmIdentifier.ES256: 32, .ES384: 48, .ES512: 66]
        for alg in ec2Algorithms {
            let pubKeyData = try generatePublicKeyData(alg)
            let coseKey = try EC2COSEKey.create(pubKey: pubKeyData, alg: alg).get()

            XCTAssertEqual(coseKey.kty, 2)
            XCTAssertEqual(coseKey.alg, alg.rawValue)
            XCTAssertEqual(coseKey.crv, alg.curve)
            XCTAssertEqual(coseKey.x.count, expectedCoordinateLengths[alg])
            XCTAssertEqual(coseKey.y.count, expectedCoordinateLengths[alg])
            // The coordinates must be the uncompressed key without its 0x04 prefix.
            XCTAssertEqual(coseKey.x + coseKey.y, pubKeyData.dropFirst())
        }
    }

    func testCreateWithNonEC2Algorithm() throws {
        let pubKeyData = try generatePublicKeyData(.ES256)
        for alg in COSEAlgorithmIdentifier.allCases where !ec2Algorithms.contains(alg) {
            switch EC2COSEKey.create(pubKey: pubKeyData, alg: alg) {
            case .success:
                XCTFail("A non-EC2 algorithm must not produce an EC2 COSE key: \(alg)")
            case .failure(let error):
                guard case .coreError(let coreError, _) = error else {
                    XCTFail("Unexpected error for \(alg): \(error)")
                    continue
                }
                XCTAssertEqual(coreError, .notSupportedError)
            }
        }
    }

    func testCreateWithCompressedKey() throws {
        var pubKeyData = try generatePublicKeyData(.ES256)
        pubKeyData[pubKeyData.startIndex] = 0x03 // compressed point prefix
        assertSecKeyError(EC2COSEKey.create(pubKey: pubKeyData, alg: .ES256))
    }

    func testCreateWithKeyOfWrongLength() throws {
        assertSecKeyError(EC2COSEKey.create(pubKey: try generatePublicKeyData(.ES384), alg: .ES256))
        assertSecKeyError(EC2COSEKey.create(pubKey: try generatePublicKeyData(.ES256), alg: .ES384))
        assertSecKeyError(EC2COSEKey.create(pubKey: Data(), alg: .ES256))
    }

    private func generatePublicKeyData(_ alg: COSEAlgorithmIdentifier) throws -> Data {
        let privateKey = try generatePrivateKey(try XCTUnwrap(alg.secKeyType),
                                                try XCTUnwrap(alg.keySizeInBits)).get()
        let publicKey = try XCTUnwrap(getPublicKey(privateKey))
        return try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, nil) as Data?)
    }

    private func assertSecKeyError(_ result: Result<EC2COSEKey, WebAuthnError>) {
        switch result {
        case .success:
            XCTFail("An invalid public key must not produce an EC2 COSE key")
        case .failure(let error):
            guard case .secKeyError = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }
}
