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

final class PublicKeyCredentialTests: XCTestCase {
    let rp = MockRelyingParty()
    let db = MockCredentialSourceStorage()
    let mockKeychain = MockKeychain()
    var ks: KeyStorage {
        KeyStorage(.biometric, keychain: mockKeychain)
    }
    let defaultUsername = "ios:test-username"
    var regOpt: MockRelyingParty.RegistrationOptions {
        return MockRegistrationOptions(username: defaultUsername, displayname: defaultUsername,
                                       attestation: .none, attachment: .platform, userVerification: .preferred)
    }
    var authnOpt: MockRelyingParty.AuthenticationOptions {
        return MockAuthenticationOptions(username: defaultUsername, userVerification: .preferred)
    }

    override func tearDownWithError() throws {
        rp.deleteExcludeAndAllowCredentials()
        db.deleteAll()
        mockKeychain.deleteAll()
    }

    func testCreateAndGet() async throws {
        let credential = MockPublicKeyCredential(rp, db, ks)
        let signupResult = try await credential.create(regOpt).get()
        XCTAssertTrue(signupResult)
        let signinResult = try await credential.get(authnOpt).get()
        XCTAssertTrue(signinResult)
    }

    func testCreateWithGetRegistrationDataFailed() async throws {
        let rp = MockRelyingPartyWithGetRegistrationDataFailed()
        do {
            let credential = MockPublicKeyCredential(rp, db, ks)
            _ = try await credential.create(regOpt).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .rpError(let err):
                XCTAssertEqual(err as? MockRPError, .getRegistrationDataFailed)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testCreateWithVerifyRegistrationFailed() async throws {
        let rp = MockRelyingPartyWithVerifyRegistrationFailed()
        do {
            let credential = MockPublicKeyCredential(rp, db, ks)
            _ = try await credential.create(regOpt).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .rpError(let err):
                XCTAssertEqual(err as? MockRPError, .verifyRegistrationFailed)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testCreateWithDeleteFailedAtCredentialStorage() async throws {
        let rp = MockRelyingPartyWithVerifyRegistrationFailed()
        let db = MockCredentialSourceStorageWithDeleteFailed()
        let credential = MockPublicKeyCredential(rp, db, ks)
        do {
            _ = try await credential.create(regOpt).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as! WebAuthnError {
            case .credSrcStorageError(let err, let credId, let trigger):
                XCTAssertEqual(err as! MockCredSrcStorageError, .deleteFailed)
                XCTAssertNotNil(credId)
                switch trigger as! WebAuthnError {
                case .rpError(let err):
                    XCTAssertEqual(err as! MockRPError, .verifyRegistrationFailed)
                default:
                    XCTFail("Unexpected error thrown: \(err)")
                }
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
            XCTAssertEqual(mockKeychain.storage.count, 0)
            XCTAssertEqual(db.storage.count, 1)
        }
    }

    func testCreateWithDeleteFailedAtKeyStorage() async throws {
        let rp = MockRelyingPartyWithVerifyRegistrationFailed()
        let mockKeychain = MockKeychainWithDeleteFailed()
        let ks = KeyStorage(.biometric, keychain: mockKeychain)
        let credential = MockPublicKeyCredential(rp, db, ks)
        do {
            _ = try await credential.create(regOpt).get()
        } catch {
            switch error as! WebAuthnError {
            case .keyStorageError(let err, let credId, let trigger):
                XCTAssertEqual(err, .deleteFailed(status: -67671))
                XCTAssertNotNil(credId)
                switch trigger as! WebAuthnError {
                case .rpError(let err):
                    XCTAssertEqual(err as! MockRPError, .verifyRegistrationFailed)
                default:
                    XCTFail("Unexpected error thrown: \(err)")
                }
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
            XCTAssertEqual(mockKeychain.storage.count, 1)
            XCTAssertEqual(db.storage.count, 1)
        }
    }

    func testGetWithGetAuthenticationDataFailed() async throws {
        let rp = MockRelyingPartyWithGetAuthenticationDataFailed()
        do {
            let credential = MockPublicKeyCredential(rp, db, ks)
            let signupResult = try await credential.create(regOpt).get()
            XCTAssertTrue(signupResult)
            _ = try await credential.get(authnOpt).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .rpError(let err):
                XCTAssertEqual(err as? MockRPError, .getAuthenticationDataFailed)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testGetBeforeCreate() async throws {
        do {
            let credential = MockPublicKeyCredential(rp, db, ks)
            _ = try await credential.get(authnOpt).get()
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

    func testGetWithVerifyAuthenticationFailed() async throws {
        let rp = MockRelyingPartyWithVerifyAuthenticationFailed()
        do {
            let credential = MockPublicKeyCredential(rp, db, ks)
            let signupResult = try await credential.create(regOpt).get()
            XCTAssertTrue(signupResult)
            _ = try await credential.get(authnOpt).get()
            XCTFail("Here should not be executed")
        } catch {
            switch error as? WebAuthnError {
            case .rpError(let err):
                XCTAssertEqual(err as? MockRPError, .verifyAuthenticationFailed)
            default:
                XCTFail("Unexpected error thrown: \(error)")
            }
        }
    }

    func testCreateAndGetWithPerformAsyncTask() throws {
        let credential = MockPublicKeyCredential(rp, db, ks)
        let expectation = XCTestExpectation()
        Task {
            credential.performAsyncTask {
                do {
                    let signupResult = try await credential.create(self.regOpt).get()
                    XCTAssertTrue(signupResult)
                    let signinResult = try await credential.get(self.authnOpt).get()
                    XCTAssertTrue(signinResult)
                } catch {
                    XCTFail("Unexpected error thrown: \(error)")
                }
                expectation.fulfill()
            }
        }
        wait(for: [expectation])
    }

    func testCreateAndGetForThreadSafety() throws {
        let threadCount = 10
        var signupSuccessCount = 0
        var invalidStateErrorCount = 0
        var expectations = [XCTestExpectation]()
        for _ in (0..<threadCount) { expectations.append(XCTestExpectation()) }
        DispatchQueue.concurrentPerform(iterations: threadCount) { index in
            let credential = MockPublicKeyCredential(rp, db, ks)
            credential.performAsyncTask {
                let result = await credential.create(self.regOpt)
                switch result {
                case .failure(let error):
                    switch error {
                    case .coreError(let err, _):
                        if err == .invalidStateError {
                            invalidStateErrorCount += 1
                        }
                    default:
                        XCTFail("Unexpected error thrown: \(error)")
                    }
                case .success(let success):
                    signupSuccessCount = success ? signupSuccessCount + 1 : signupSuccessCount
                }
                expectations[index].fulfill()
            }
        }
        wait(for: expectations)
        XCTAssertEqual(signupSuccessCount, 1)
        XCTAssertEqual(invalidStateErrorCount, threadCount - 1)
    }

    func testGetWhenMultipleSignIn() throws {
        let credential = MockPublicKeyCredential(MockRelyingParty(), db, ks)
        // sign up
        let expectation = XCTestExpectation()
        credential.performAsyncTask {
            let signupResult = try? await credential.create(self.regOpt).get()
            XCTAssertNotNil(signupResult)
            expectation.fulfill()
        }
        wait(for: [expectation])
        // multiple sign in
        let threadCount = 10
        var expectations = [XCTestExpectation]()
        for _ in (0..<threadCount) { expectations.append(XCTestExpectation()) }
        DispatchQueue.concurrentPerform(iterations: threadCount) { index in
            credential.performAsyncTask {
                let signinResult = try? await credential.get(self.authnOpt).get()
                XCTAssertNotNil(signinResult)
                XCTAssertTrue(signinResult!)
                expectations[index].fulfill()
            }
        }
        wait(for: expectations)
        do {
            let credSrcs = try db.loadAll().get()
            XCTAssertEqual(credSrcs!.count, 1)
            let signatureCounter = try db.getSignatureCounter(credSrcs![0].id).get()
            XCTAssertEqual(signatureCounter, UInt32(threadCount))
        } catch {
            XCTFail("Unexpected error thrown: \(error)")
        }
    }
}
