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

enum MockRPError: Error, Equatable {
    case getRegistrationDataFailed
    case verifyRegistrationFailed
    case getAuthenticationDataFailed
    case verifyAuthenticationFailed
}

struct MockRegistrationOptions: RegistrationOptions {
    let username: String
    let displayname: String
    let attestation: AttestationConveyancePreference
    let attachment: AuthenticatorAttachment
    let userVerification: UserVerificationRequirement
}

struct MockRegistrationData: RegistrationData {
    var attestation: AttestationConveyancePreference
    var authenticatorSelection: AuthenticatorSelectionCriteria
    var challenge: String
    var excludeCredentials: [PublicKeyCredentialDescriptor]?
    var extensions: ClientExtensionsInput?
    var pubKeyCredParams: [PublicKeyCredentialParameters]
    var rp: PublicKeyCredentialRpEntity
    var user: PublicKeyCredentialUserEntity
}

struct MockAuthenticationOptions: AuthenticationOptions {
    var username: String
    var userVerification: UserVerificationRequirement
}

struct MockAuthenticationData: AuthenticationData {
    var allowCredentials: [PublicKeyCredentialDescriptor]?
    var challenge: String
    var extensions: ClientExtensionsInput?
    var rpId: String
    var userVerification: UserVerificationRequirement
}

class MockRelyingParty: RelyingParty {
    typealias RegistrationOptions = MockRegistrationOptions
    typealias RegistrationData = MockRegistrationData
    typealias AuthenticationOptions = MockAuthenticationOptions
    typealias AuthenticationData = MockAuthenticationData

    private let rpHost = "test.service.com"
    private let rpName = "ios:test-service"

    private var excludeCredentials: [PublicKeyCredentialDescriptor]?
    private var allowCredentials: [PublicKeyCredentialDescriptor]?

    func getRegistrationData(_ option: RegistrationOptions) async -> Result<RegistrationData, Error> {
        let pubKeyCredParams = Array(COSEAlgorithmIdentifier.allCases).map {
            PublicKeyCredentialParameters(type: "public-key", alg: $0)
        }
        let data = RegistrationData(attestation: option.attestation,
                                    authenticatorSelection: AuthenticatorSelectionCriteria(
                                        authenticatorAttachment: option.attachment,
                                        userVerification: option.userVerification),
                                    challenge: "ios:test-challenge-creation",
                                    excludeCredentials: excludeCredentials,
                                    extensions: nil,
                                    pubKeyCredParams: pubKeyCredParams,
                                    rp: PublicKeyCredentialRpEntity(id: rpHost, name: rpName),
                                    user: PublicKeyCredentialUserEntity(
                                        id: "ios:test-user-id", name: option.username, displayName: option.displayname))
        return .success(data)
    }

    func verifyRegistration(_ result: PublicKeyCredentialCreateResult) async -> Result<Bool, Error> {
        let registeredCredential = PublicKeyCredentialDescriptor(type: "public-key",
                                                                 id: result.id.toBase64Url(),
                                                                 transports: [])
        excludeCredentials = [registeredCredential]
        allowCredentials = [registeredCredential]
        return .success(true)
    }

    func getAuthenticationData(_ option: AuthenticationOptions) async -> Result<AuthenticationData, Error> {
        let data = AuthenticationData(allowCredentials: allowCredentials, challenge: "ios:test-challenge-assertion",
                                  extensions: nil, rpId: rpHost, userVerification: option.userVerification)
        return .success(data)
    }

    func verifyAuthentication(_ result: PublicKeyCredentialGetResult) async -> Result<Bool, Error> {
        return .success(true)
    }
}

extension MockRelyingParty {
    func deleteExcludeAndAllowCredentials() {
        excludeCredentials = []
        allowCredentials = []
    }
}

class MockRelyingPartyWithGetRegistrationDataFailed: MockRelyingParty {
    override func getRegistrationData(_ option: RegistrationOptions) async -> Result<RegistrationData, Error> {
        return .failure(MockRPError.getRegistrationDataFailed)
    }
}

class MockRelyingPartyWithVerifyRegistrationFailed: MockRelyingParty {
    override func verifyRegistration(_ result: PublicKeyCredentialCreateResult) async -> Result<Bool, Error> {
        return .failure(MockRPError.verifyRegistrationFailed)
    }
}

class MockRelyingPartyWithGetAuthenticationDataFailed: MockRelyingParty {
    override func getAuthenticationData(_ option: AuthenticationOptions) async -> Result<AuthenticationData, Error> {
        return .failure(MockRPError.getAuthenticationDataFailed)
    }
}

class MockRelyingPartyWithVerifyAuthenticationFailed: MockRelyingParty {
    override func verifyAuthentication(_ result: PublicKeyCredentialGetResult) async -> Result<Bool, Error> {
        return .failure(MockRPError.verifyAuthenticationFailed)
    }
}
