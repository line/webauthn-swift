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

enum COSEAlgorithmIdentifier: Int, Codable, CaseIterable {
    case RS1   = -65535 // RSASSA-PKCS1-v1_5 with SHA-1
    case RS256 = -257   // RSASSA-PKCS1-v1_5 with SHA-256
    case RS384 = -258   // RSASSA-PKCS1-v1_5 with SHA-384
    case RS512 = -259   // RSASSA-PKCS1-v1_5 with SHA-512
    case PS256 = -37    // RSASSA-PSS with SHA-256
    case PS384 = -38    // RSASSA-PSS with SHA-384
    case PS512 = -39    // RSASSA-PSS with SHA-512
    case EDDSA = -8     // EdDSA
    case ES256 = -7     // ECDSA with SHA-256
    case ES384 = -35    // ECDSA with SHA-384
    case ES512 = -36    // ECDSA with SHA-512
    case ES256K = -47   // ECDSA using secp256k1 and SHA-256 (RFC 8812)

    var secKeyType: String? {
        switch self {
        case .RS1, .RS256, .RS384, .RS512, .PS256, .PS384, .PS512:
            return kSecAttrKeyTypeRSA as String
        case .ES256, .ES384, .ES512:
            return kSecAttrKeyTypeECSECPrimeRandom as String
        case .EDDSA, .ES256K:
            // The Security framework offers neither Edwards curves nor secp256k1.
            return nil
        }
    }

    var keySizeInBits: Int? {
        switch self {
        case .RS1, .RS256, .RS384, .RS512, .PS256, .PS384, .PS512:
            return 2048
        case .ES256:
            return 256
        case .ES384:
            return 384
        case .ES512:
            // NIST P-521, not 512.
            return 521
        case .EDDSA, .ES256K:
            return nil
        }
    }

    var curve: Int? {
        switch self {
        case .ES256:
            return 1 // P-256
        case .ES384:
            return 2 // P-384
        case .ES512:
            return 3 // P-521
        case .RS1, .RS256, .RS384, .RS512, .PS256, .PS384, .PS512, .EDDSA, .ES256K:
            return nil
        }
    }

    var coordinateOctetLength: Int? {
        guard curve != nil, let keySizeInBits = keySizeInBits else {
            return nil
        }
        return (keySizeInBits + 7) / 8
    }
}
