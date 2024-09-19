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

final class AuthenticatorTests: XCTestCase {
    let db = MockCredentialSourceStorage()
    let mockKeychain = MockKeychain()
    var ks: KeyStorage {
        return KeyStorage(.biometric, keychain: mockKeychain) // .biometry is unnecessary here
    }
    let la = MockLocalAuthenticationWithSuccess()
    let defaultRpId = "ios:test-rpid"
    let defaultUserId = "ios:test-userid" // same as username only for testing

    override func tearDownWithError() throws {
        db.deleteAll()
        mockKeychain.deleteAll()
    }

    func register(_ authn: Authenticator,
                  _ rpId: String = "ios:test-rpid",
                  _ username: String = "ios:test-userid",
                  _ regList: [PublicKeyCredentialDescriptor]? = nil,
                  _ credTypesAndPubKeyAlgs: [PublicKeyCredentialParameters] = [PublicKeyCredentialParameters(type: "public-key", alg: .ES256)],
                  _ extensions: AuthenticatorExtensionsInput? = nil
    ) async -> Result<AuthenticatorMakeCredentialResult, WebAuthnError> {
        let rpEntity = PublicKeyCredentialRpEntity(id: rpId, name: rpId)
        let userEntity = PublicKeyCredentialUserEntity(id: username, name: username, displayName: username)
        return await authn.makeCredential(hash: "ios:test-create".toSHA256(),
                                          rpEntity: rpEntity,
                                          userEntity: userEntity,
                                          credTypesAndPubKeyAlgs: credTypesAndPubKeyAlgs,
                                          excludeCredentialDescriptorList: regList,
                                          extensions: extensions)
    }

    func authenticate(_ authn: Authenticator,
                      _ rpId: String = "ios:test-rpid",
                      _ allowedList: [PublicKeyCredentialDescriptor]? = nil,
                      _ extensions: AuthenticatorExtensionsInput? = nil
    ) async -> Result<AuthenticatorGetAssertionResult, WebAuthnError> {
        return await authn.getAssertion(rpId: rpId,
                                        hash: "ios:test-get".toSHA256(),
                                        allowCredentialDescriptorList: allowedList,
                                        extensions: extensions)
    }

    func testMakeCredentialAndGetAssertion() async throws {
        let authn = BiometricAuthenticator(db, ks, la)
        let registrationResult = try await register(authn, defaultRpId, defaultUserId).get()
        let credentialId = registrationResult.credentialId
        let allowedList = [PublicKeyCredentialDescriptor(type: "public-key",
                                                         id: credentialId.toBase64Url(),
                                                         transports: [.itn])]
        let authenticationResult = try await authenticate(authn, defaultRpId, allowedList).get()
        XCTAssertEqual(credentialId, authenticationResult.credentialId)
    }

    func testMakeCredentialWithUnsupportedKeyParams() async throws {
        let authn = BiometricAuthenticator(db, ks, la)
        let keyParams = [PublicKeyCredentialParameters(type: "public-key", alg: .EDDSA)] // unsupported key params
        do {
            _ = try await register(authn, defaultRpId, defaultUserId, nil, keyParams).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .coreError(let err, _):
                XCTAssertEqual(err, .notSupportedError)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testMakeCredentialWithLoadFailedAtCredSrcStorage() async throws {
        let db = MockCredentialSourceStorageWithLoadFailed()
        let authn = BiometricAuthenticator(db, ks, la)
        let tempCredId = "test"
        do {
            let descriptors = [PublicKeyCredentialDescriptor(type: "public-key", id: tempCredId, transports: nil)]
            _ = try await register(authn, defaultRpId, defaultUserId, descriptors).get()
            XCTFail("Here should not be executed")
        } catch {
            let error = error as! WebAuthnError
            switch error {
            case .credSrcStorageError(let err, let credId, _):
                XCTAssertEqual(err as! MockCredSrcStorageError, .loadFailed)
                XCTAssertEqual(credId, tempCredId)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testMakeCredentialWithRegisteredUser() async throws {
        let authn = BiometricAuthenticator(db, ks, la)
        do {
            let registrationResult = try await register(authn).get() // first sign up
            let credId = registrationResult.credentialId
            let regList = [PublicKeyCredentialDescriptor(type: "public-key", id: credId.toBase64Url(), transports: [.itn])]
            _ = try await register(authn, defaultRpId, defaultUserId, regList).get() // second sign up
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .coreError(let err, _):
                XCTAssertEqual(err, .invalidStateError)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testMakeCredentialWithUnsupportedLA() async throws {
        let la = MockLocalAuthenticationWithoutSupport()
        let authn = BiometricAuthenticator(db, ks, la)
        do {
            _ = try await register(authn).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .coreError(let err, _):
                XCTAssertEqual(err, .constraintError)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testMakeCredentialWhenUserVerificationIsFailed() async throws {
        let la = MockLocalAuthenticationWithFailure()
        let authn = BiometricAuthenticator(db, ks, la)
        do {
            _ = try await register(authn).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .laError(_):
                XCTAssert(true, "This case will always succeed")
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testMakeCredentialWithStoreFailedAtCredSrcStorage() async throws {
        let db = MockCredentialSourceStorageWithStoreFailed()
        let authn = BiometricAuthenticator(db, ks, la)
        do {
            _ = try await register(authn).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .credSrcStorageError(let err, let credId, _):
                XCTAssertEqual(err as? MockCredSrcStorageError, .storeFailed)
                XCTAssertNotNil(credId) // At this point, credId is already generated.
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testMakeCredentialWithStoreFailedAtKeyStorage() async throws {
        let mockKeychain = MockKeychainWithAddFailed()
        let ks = KeyStorage(.biometric, keychain: mockKeychain)
        let authn = BiometricAuthenticator(db, ks, la)
        do {
            _ = try await register(authn).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .keyStorageError(let err, let credId, _):
                XCTAssertEqual(err, .storeFailed(status: -67671))
                XCTAssertNotNil(credId)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testGetAssertionWithLoadAllFailedAtCredSrcStorage() async throws {
        let db = MockCredentialSourceStorageWithLoadlAllFailed()
        let authn = BiometricAuthenticator(db, ks, la)
        do {
            _ = try await authenticate(authn).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .credSrcStorageError(let err, let credId, _):
                XCTAssertEqual(err as? MockCredSrcStorageError, .loadAllFailed)
                XCTAssertNil(credId)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testGetAssertionWithLoadFailedAtCredSrcStorage() async throws {
        let db = MockCredentialSourceStorageWithLoadFailed()
        let authn = BiometricAuthenticator(db, ks, la)
        let notAllowedCredId = "suspicious credential id".toData().toBase64Url()
        do {
            let notAllowedList = [PublicKeyCredentialDescriptor(type: "public-key", id: notAllowedCredId, transports: [.itn])]
            _ = try await authenticate(authn, defaultRpId, notAllowedList).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .credSrcStorageError(let err, let credId, _):
                XCTAssertEqual(err as? MockCredSrcStorageError, .loadFailed)
                XCTAssertEqual(credId, notAllowedCredId)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testGetAssertionWithUnregisteredUser() async throws {
        let authn = BiometricAuthenticator(db, ks, la)
        do {
            _ = try await authenticate(authn).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .coreError(let err, _):
                XCTAssertEqual(err, .notAllowedError)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testGetAssertionWithInvalidKey() async throws {
        let authn = BiometricAuthenticator(db, ks, la)
        do {
            let registrationResult = try await register(authn, defaultRpId, defaultUserId).get()
            let credentialId = registrationResult.credentialId
            let allowedList = [PublicKeyCredentialDescriptor(type: "public-key",
                                                             id: credentialId.toBase64Url(),
                                                             transports: [.itn])]
            mockKeychain.deleteAll() // Delete all before authentication
            _ = try await authenticate(authn, defaultRpId, allowedList).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .keyNotFoundError:
                XCTAssert(true, "This case will always succeed")
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testGetAssertionWithLoadFailedAtKeyStorage() async throws {
        let authn = BiometricAuthenticator(db, ks, la)
        var credentialId: String?
        do {
            let registrationResult = try await register(authn, defaultRpId, defaultUserId).get()
            credentialId = registrationResult.credentialId.toBase64Url()
            let allowedList = [PublicKeyCredentialDescriptor(type: "public-key",
                                                             id: credentialId!,
                                                             transports: [.itn])]
            // Forcibly break the keychain.
            let modifiedKeychain = MockKeychainWithGetFailed()
            authn.keyStorage = KeyStorage(.biometric, keychain: modifiedKeychain)
            modifiedKeychain.storage = mockKeychain.storage
            _ = try await authenticate(authn, defaultRpId, allowedList).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .keyStorageError(let err, let credId, _):
                XCTAssertEqual(err, .loadFailed(status: -67671))
                XCTAssertNotNil(credentialId)
                XCTAssertEqual(credId, credentialId!)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testGetAssertionWithIncreaseSignatureCounterFailed() async throws {
        let db = MockCredentialSourceStorageWithIncreaseSignatureCounterFailed()
        let authn = BiometricAuthenticator(db, ks, la)
        var credentialId: String?
        do {
            let registrationResult = try await register(authn, defaultRpId, defaultUserId).get()
            credentialId = registrationResult.credentialId.toBase64Url()
            let allowedList = [PublicKeyCredentialDescriptor(type: "public-key",
                                                             id: credentialId!,
                                                             transports: [.itn])]
            _ = try await authenticate(authn, defaultRpId, allowedList).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .credSrcStorageError(let err, let credId, _):
                XCTAssertEqual(err as? MockCredSrcStorageError, .increaseSignatureCounterFailed)
                XCTAssertEqual(db.storage.count, 1)
                XCTAssertNotNil(credentialId)
                XCTAssertEqual(credId, credentialId!)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }
}
