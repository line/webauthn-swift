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

@testable import WebAuthn

enum MockCredSrcStorageError: Error {
    case itemNotFound
    case loadFailed
    case loadAllFailed
    case storeFailed
    case deleteFailed
    case getSignatureCounterFailed
    case increaseSignatureCounterFailed
}

struct CredentialSourceEntity {
    let id: String
    let type: String
    let aaguid: String
    let userId: String?
    let rpId: String
    var counter: UInt32
}

class MockCredentialSourceStorage: CredentialSourceStorage {
    var storage: [String: CredentialSourceEntity] = [:]

    func load(_ credId: String) -> Result<PublicKeyCredentialSource?, Error> {
        guard let e = storage[credId] else {
            return .failure(MockCredSrcStorageError.itemNotFound)
        }
        return .success(PublicKeyCredentialSource(id: e.id, type: e.type, aaguid: e.aaguid, userId: e.userId, rpId: e.rpId))
    }
    
    func loadAll() -> Result<[PublicKeyCredentialSource]?, Error> {
        let result = storage.map { (_, e) in
            PublicKeyCredentialSource(id: e.id, type: e.type, aaguid: e.aaguid, userId: e.userId, rpId: e.rpId)
        }
        return .success(result)
    }
    
    func store(_ credSrc: PublicKeyCredentialSource) -> Result<(), Error> {
        storage[credSrc.id] = CredentialSourceEntity(id: credSrc.id, type: credSrc.type, aaguid: credSrc.aaguid,
                                                     userId: credSrc.userId, rpId: credSrc.rpId, counter: 0)
        return .success(())
    }
    
    func delete(_ credId: String) -> Result<(), Error> {
        storage[credId] = nil
        return .success(())
    }

    func increaseSignatureCounter(_ credId: String) -> Result<UInt32, Error> {
        if let credSrc = storage[credId] {
            let updatedCounter = credSrc.counter + 1
            storage[credId]!.counter = updatedCounter
            return .success(updatedCounter)
        } else {
            return .failure(MockCredSrcStorageError.itemNotFound)
        }
    }
}

extension MockCredentialSourceStorage {
    func deleteAll() {
        storage = [:]
    }

    func getSignatureCounter(_ credId: String) -> Result<UInt32, Error> {
        if let credSrc = storage[credId] {
            return .success(credSrc.counter)
        } else {
            return .failure(MockCredSrcStorageError.itemNotFound)
        }
    }
}

class MockCredentialSourceStorageWithLoadFailed: MockCredentialSourceStorage {
    override func load(_ credId: String) -> Result<PublicKeyCredentialSource?, Error> {
        return .failure(MockCredSrcStorageError.loadFailed)
    }
}

class MockCredentialSourceStorageWithLoadlAllFailed: MockCredentialSourceStorage {
    override func loadAll() -> Result<[PublicKeyCredentialSource]?, Error> {
        return .failure(MockCredSrcStorageError.loadAllFailed)
    }
}

class MockCredentialSourceStorageWithStoreFailed: MockCredentialSourceStorage {
    override func store(_ credSrc: PublicKeyCredentialSource) -> Result<(), Error> {
        return .failure(MockCredSrcStorageError.storeFailed)
    }
}

class MockCredentialSourceStorageWithDeleteFailed: MockCredentialSourceStorage {
    override func delete(_ credId: String) -> Result<(), Error> {
        return .failure(MockCredSrcStorageError.deleteFailed)
    }
}

class MockCredentialSourceStorageWithIncreaseSignatureCounterFailed: MockCredentialSourceStorage {
    override func increaseSignatureCounter(_ credId: String) -> Result<UInt32, Error> {
        return .failure(MockCredSrcStorageError.increaseSignatureCounterFailed)
    }
}
