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

extension String {
    func base64UrlToData() -> Data? {
        var base64 = self.replacingOccurrences(of: "-", with: "+")
                         .replacingOccurrences(of: "_", with: "/")
        if base64.count % 4 != 0 {
            base64.append(String(repeating: "=", count: 4 - base64.count % 4))
        }
        return Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
    }

    func toData() -> Data {
        return Data(self.utf8)
    }

    func toSHA256() -> Data {
        return Data(self.utf8).toSHA256()
    }
}
