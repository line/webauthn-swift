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
@testable import WebAuthn

class MockKeychain: KeychainProtocol {
    var storage: [String: SecKey] = [:]

    func add(_ query: [String: Any]) -> OSStatus {
        let kid = query[kSecAttrLabel as String] as! String
        let key = query[kSecValueRef as String] as! SecKey
        storage[kid] = key
        return errSecSuccess
    }
    
    func get(_ query: [String: Any]) -> KeychainResult {
        let kid = query[kSecAttrLabel as String] as! String
        if storage[kid] == nil {
            return KeychainResult(status: errSecItemNotFound, queryResult: nil)
        }
        return KeychainResult(status: errSecSuccess,
                              queryResult: storage[kid] as AnyObject)
    }
    
    func update(_ query: [String: Any], with attributes: [String: Any]) -> OSStatus {
        let kid = query[kSecAttrLabel as String] as! String
        storage[kid] = (attributes[kSecValueRef as String] as! SecKey)
        return errSecSuccess
    }

    func delete(_ query: [String: Any]) -> OSStatus {
        storage = [:]
        return errSecSuccess
    }
}

extension MockKeychain {
    func deleteAll() {
        storage = [:]
    }
}

class MockKeychainWithAddFailed: MockKeychain {
    override func add(_ query: [String: Any]) -> OSStatus {
        return errSecInternalError // -67671
    }
}

class MockKeychainWithGetFailed: MockKeychain {
    override func get(_ query: [String: Any]) -> KeychainResult {
        return KeychainResult(status: errSecInternalError, queryResult: nil) // -67671
    }
}

class MockKeychainWithDeleteFailed: MockKeychain {
    override func delete(_ query: [String: Any]) -> OSStatus {
        return errSecInternalError // -67671
    }
}

class MockKeychainWithAddAndDeleteFailed: MockKeychain {
    override func add(_ query: [String: Any]) -> OSStatus {
        return errSecInternalError // -67671
    }

    override func delete(_ query: [String: Any]) -> OSStatus {
        return errSecInternalError // -67671
    }
}
