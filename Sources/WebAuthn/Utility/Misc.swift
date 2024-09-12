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

func generateRandomBytes(len: Int) -> Data? {
    var randomBytes = [Int8](repeating: 0, count: len)
    guard SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes) == errSecSuccess else {
        return nil
    }
    return Data(bytes: randomBytes, count: len)
}

func getOrigin() -> String? {
    if let bundleId = Bundle.main.bundleIdentifier {
        return "ios:bundle-id:" + bundleId
    } else { return nil }
}
