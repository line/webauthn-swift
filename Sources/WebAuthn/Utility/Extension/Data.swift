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

import CryptoKit
import Foundation

extension Data {
    public func toBase64Url() -> String {
        return self.base64EncodedString().replacingOccurrences(of: "+", with: "-")
                                         .replacingOccurrences(of: "/", with: "_")
                                         .replacingOccurrences(of: "=", with: "")
    }

    func toUInt8() -> UInt8 {
        assert(self.count == 1)
        return self[0]
    }

    func toUInt16BigEndian() -> UInt16 {
        assert(self.count == 2)
        return self.withUnsafeBytes {
            $0.load(as: UInt16.self).bigEndian
        }
    }

    func toUInt32BigEndian() -> UInt32 {
        assert(self.count == 4)
        return self.withUnsafeBytes {
            $0.load(as: UInt32.self).bigEndian
        }
    }

    func toSHA256() -> Data {
        return Data(SHA256.hash(data: self))
    }
}
