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

public enum AuthenticatorType: CaseIterable {
    private static let biometricAAGUID = UUID.init(uuidString: "4e3db665-c12d-5d2d-6a09-a15b78972bc9")!
    private static let deviceCredentialAAGUID = UUID.init(uuidString: "5c7b7e9a-2b85-464e-9ea3-529582bb7e34")!

    case biometric
    case deviceCredential

    init?(aaguid: UUID) {
        switch aaguid {
        case AuthenticatorType.biometricAAGUID:
            self = .biometric
        case AuthenticatorType.deviceCredentialAAGUID:
            self = .deviceCredential
        default:
            return nil
        }
    }

    var aaguid: UUID {
        switch self {
        case .biometric:
            return AuthenticatorType.biometricAAGUID
        case .deviceCredential:
            return AuthenticatorType.deviceCredentialAAGUID
        }
    }

    var uuidString: String {
        switch self {
        case .biometric:
            return self.aaguid.uuidString
        case .deviceCredential:
            return self.aaguid.uuidString
        }
    }
}
