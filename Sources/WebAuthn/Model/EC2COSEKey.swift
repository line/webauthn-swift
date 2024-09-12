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

import Foundation
import SwiftCBOR

struct EC2COSEKey {
    let kty: Int // EC2 key type
    let alg: Int // ES256 signature algorithm
    let crv: Int // P-256 curve
    let x: Data
    let y: Data

    static func create(pubKey: Data) -> Self {
        // public key: 04 [32 bytes x] [32 bytes y] -> uncompressed public key (65 bytes)
        assert(pubKey[0] == 4, "Given public key must be uncompressed key.")
        assert(pubKey.count == 65, "Given public key's length must be 65.")
        let x = pubKey[1..<33]
        let y = pubKey[33..<pubKey.count]
        return EC2COSEKey(kty: 2,
                          alg: COSEAlgorithmIdentifier.ES256.rawValue,
                          crv: 1,
                          x: x,
                          y: y)
    }

    func toCBOR() -> Result<Data, WebAuthnError> {
        let ec2COSEKey: [Int: Any] = [
            1: self.kty,  // kty
            3: self.alg,  // alg
            -1: self.crv, // crv
            -2: self.x,   // x
            -3: self.y    // y
        ]
        do {
            let cbor = try CBOR.encodeMap(ec2COSEKey)
            return .success(Data(cbor))
        } catch {
            return .failure(.encodingError(error))
        }
    }
}
