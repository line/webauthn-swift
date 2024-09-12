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

/// It manages public key credentials using the device credential authenticator.
///
/// It enables secure user authentication by utilizing biometry or a passcode.
/// If biometry is available, the system uses that first. If not, the system
/// prompts the user for the device passcode or user's password.
public class DeviceCredential<RP: RelyingParty>: PublicKeyCredential {
    public var aaguid = AuthenticatorType.deviceCredential.aaguid
    public var rp: RP
    public var credSrcStorage: CredentialSourceStorage
    public var keyStorage = KeyStorage(.deviceCredential)
    public var localAuthn: LocalAuthenticationProtocol

    public init(_ rp: RP, _ db: CredentialSourceStorage, _ localAuthnUIString: String? = nil) {
        self.rp = rp
        self.credSrcStorage = db
        self.localAuthn = LocalAuthentication(.deviceOwnerAuthentication)
        if let localAuthnUIString = localAuthnUIString {
            self.localAuthn.localizedReason = localAuthnUIString
        }
    }
}
