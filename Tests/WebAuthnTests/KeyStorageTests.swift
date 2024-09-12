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

import XCTest
@testable import WebAuthn

final class KeychainManagerTests: XCTestCase {
    var mock = MockKeychain()
    var ks: KeyStorage {
        KeyStorage(.biometric, keychain: mock)
    }
    let keyLength = 256
    let keyType = kSecAttrKeyTypeECSECPrimeRandom as String

    override func tearDownWithError() throws {
        mock.deleteAll()
    }

    func testStore() {
        let keyId1 = "testKeyId1"
        let key1 = try! generatePublicPrivateKeyPair(keyType, keyLength).get()
        XCTAssertNoThrow(try ks.store(keyId1, key: key1).get())
        XCTAssertEqual(mock.storage[keyId1], key1)
        let keyId2 = "testKeyId2"
        let key2 = try! generatePublicPrivateKeyPair(keyType, keyLength).get()
        XCTAssertNoThrow(try ks.store(keyId2, key: key2).get())
        XCTAssertEqual(mock.storage[keyId2], key2)
        // case: if there is a key matching with keyId
        let key3 = try! generatePublicPrivateKeyPair(keyType, keyLength).get()
        XCTAssertNoThrow(try ks.store(keyId1, key: key3).get())
        XCTAssertEqual(mock.storage[keyId1], key3)
    }

    func testLoad() {
        let keyId = "testKeyId"
        let key = try! generatePublicPrivateKeyPair(keyType, keyLength).get()
        XCTAssertNoThrow(try ks.store(keyId, key: key).get())
        let loadedKey = try? ks.load(keyId).get()
        XCTAssertEqual(loadedKey, key)
    }

    func testDelete() {
        let keyId = "testKeyId"
        XCTAssertNoThrow(try ks.delete(keyId).get())
        let key = try! generatePublicPrivateKeyPair(keyType, keyLength).get()
        XCTAssertNoThrow(try ks.store(keyId, key: key).get())
        XCTAssertNoThrow(try ks.delete(keyId).get())
        XCTAssertNil(mock.storage[keyId])
    }
}
