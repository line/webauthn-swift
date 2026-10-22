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
    private static let uncompressedPointPrefix: UInt8 = 0x04 // First byte of ANSI X9.63 uncompressed elliptic curve point.

    let kty: Int // EC2 key type
    let alg: Int // ECDSA signature algorithm
    let crv: Int // Curve the key lies on
    let x: Data
    let y: Data

    static func create(pubKey: Data, alg: COSEAlgorithmIdentifier) -> Result<Self, WebAuthnError> {
        guard let crv = alg.curve, let coordinateLength = alg.coordinateOctetLength else {
            let msg = "Given algorithm is not a supported elliptic curve algorithm: \(alg)"
            return .failure(.coreError(.notSupportedError, cause: msg))
        }
        let expectedLength = 1 + coordinateLength * 2
        guard pubKey.count == expectedLength else {
            let msg = "Given public key's length must be \(expectedLength) for \(alg), but was \(pubKey.count)."
            return .failure(.secKeyError(cause: msg))
        }
        guard pubKey.first == Self.uncompressedPointPrefix else {
            return .failure(.secKeyError(cause: "Given public key must be an uncompressed key."))
        }
        let coordinates = pubKey.dropFirst()
        return .success(EC2COSEKey(kty: 2,
                                   alg: alg.rawValue,
                                   crv: crv,
                                   x: Data(coordinates.prefix(coordinateLength)),
                                   y: Data(coordinates.suffix(coordinateLength))))
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
