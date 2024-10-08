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

let upMask: UInt8 = 1      // User present result
let uvMask: UInt8 = 1 << 2 // User verified result
let atMask: UInt8 = 1 << 6 // Attested credential data included
let edMask: UInt8 = 1 << 7 // Extension data included

let rpIdHashLength                = 32
let flagsLength                   = 1 // 1 byte
let signCounterLength             = 4 // 4 bytes
let aaguidLength                  = 16
let credentialIdLengthBytesLength = 2

func createFlags(up userPresent: Bool, uv userVerified: Bool, at atIncluded: Bool, ed edIncluded: Bool) -> UInt8 {
    var flags: UInt8 = 0
    if userPresent { flags = flags | upMask }
    if userVerified { flags = flags | uvMask }
    if atIncluded { flags = flags | atMask }
    if edIncluded { flags = flags | edMask }
    return flags
}

struct AuthenticatorData: Codable {
    let rpIdHash: Data
    let userPresent: Bool
    let userVerified: Bool
    let atIncluded: Bool
    let edIncluded: Bool
    var signCount: UInt32 // 32-bit unsigned big-endian integer
    let attestedCredentialData: AttestedCredentialData?
    let extensions: AuthenticatorExtensionsOutput?

    init(_ rpIdHash: Data, _ up: Bool, _ uv: Bool, _ count: UInt32,
         _ attestedCredData: AttestedCredentialData?, _ extensions: AuthenticatorExtensionsOutput?) {
        self.rpIdHash = rpIdHash
        self.userPresent = up
        self.userVerified = uv
        self.atIncluded = attestedCredData != nil ? true : false
        self.edIncluded = extensions != nil ? true : false
        self.signCount = count
        self.attestedCredentialData = attestedCredData
        self.extensions = extensions
    }

    func toData() -> Data {
        let flags = createFlags(up: self.userPresent, uv: self.userVerified, at: self.atIncluded, ed: self.edIncluded)
        let flagsData = flags.toData()
        let signCountData = self.signCount.toDataBigEndian()
        var data = rpIdHash + flagsData + signCountData
        if let attestedCredentialData = self.attestedCredentialData {
            data += attestedCredentialData.toData()
        }
        if let extensions = self.extensions {
            data += extensions.toData()
        }
        return data
    }
}
