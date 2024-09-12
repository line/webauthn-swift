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

final class KeyHelperTests: XCTestCase {
    private let es256Type = kSecAttrKeyTypeECSECPrimeRandom as String
    private let es256Length = 256

    func testSignAndVerify() throws {
        // Sign
        let privateKey = try generatePublicPrivateKeyPair(es256Type, es256Length).get()
        let secret = "this is a secret".toData()!
        let signature = try sign(privateKey, .ecdsaSignatureMessageX962SHA256, secret).get()
        // Verify
        let publicKey = getPublicKey(privateKey)
        XCTAssertNotNil(publicKey)
        let verification = try verify(publicKey!, .ecdsaSignatureMessageX962SHA256, secret, signature).get()
        XCTAssertTrue(verification)
    }

    // Verify a signature using a public key.
    func verify(_ publicKey: SecKey, _ algorithm: SecKeyAlgorithm, _ hash: Data, _ signature: Data
    ) -> Result<Bool, WebAuthnError> {
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            return .failure(.secKeyError(cause: "Given algorithm is not supported: \(algorithm) (verify)"))
        }
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(publicKey, algorithm, hash as CFData, signature as CFData, &error)
        guard error == nil else {
            let error = error!.takeRetainedValue() as Error
            return .failure(.secKeyError(cause: error.localizedDescription))
        }
        return .success(result)
    }
}
