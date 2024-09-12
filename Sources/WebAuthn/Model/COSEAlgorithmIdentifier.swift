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
    case ES256K = -43   // ECDSA using P-256K and SHA-256

    var keyType: String {
        switch self {
        case .RS1, .RS256, .RS384, .RS512, .PS256, .PS384, .PS512:
            return kSecAttrKeyTypeRSA as String
        case .EDDSA, .ES256, .ES384, .ES512, .ES256K:
            return kSecAttrKeyTypeECSECPrimeRandom as String
        }
    }

    var keyLen: Int {
        switch self {
        case .RS1:
            return 160
        case .RS256, .PS256, .EDDSA, .ES256, .ES256K:
            return 256
        case .RS384, .PS384, .ES384:
            return 384
        case .RS512, .PS512, .ES512:
            return 512
        }
    }
}
