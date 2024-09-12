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

struct AttestedCredentialData: Codable {
    let aaguid: UUID
    let credentialId: Data
    let publicKey: Data // CBOR-encoded public key

    func toData() -> Data {
        let aaguidData = self.aaguid.toData()
        // According to the spec(https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data),
        // type of credential identifier length is 16-bit unsigned big-endian integer.
        let credentialIdLengthData = UInt16(credentialId.count).toDataBigEndian()
        return aaguidData + credentialIdLengthData + self.credentialId + publicKey
    }
}
