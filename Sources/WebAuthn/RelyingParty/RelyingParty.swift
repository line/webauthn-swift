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

public protocol RegistrationOptions {
    var username: String { get }
    var displayname: String { get }
    var attestation: AttestationConveyancePreference { get }
    var attachment: AuthenticatorAttachment { get }
    var userVerification: UserVerificationRequirement { get }
}

public protocol AuthenticationOptions {
    var username: String { get }
    var userVerification: UserVerificationRequirement { get }
}

public protocol RegistrationData {
    var attestation: AttestationConveyancePreference { get }
    var authenticatorSelection: AuthenticatorSelectionCriteria { get }
    var challenge: String { get }
    var excludeCredentials: [PublicKeyCredentialDescriptor]? { get }
    var extensions: ClientExtensionsInput? { get }
    var pubKeyCredParams: [PublicKeyCredentialParameters] { get }
    var rp: PublicKeyCredentialRpEntity { get }
    var user: PublicKeyCredentialUserEntity { get }
}

public protocol AuthenticationData {
    var allowCredentials: [PublicKeyCredentialDescriptor]? { get }
    var challenge: String { get }
    var extensions: ClientExtensionsInput? { get }
    var rpId: String { get }
    var userVerification: UserVerificationRequirement { get }
}

/// It defines the behavior of a relying party which is a server providing
/// access to a secured software application.
public protocol RelyingParty {
    associatedtype RegOpts: RegistrationOptions
    associatedtype RegData: RegistrationData
    associatedtype AuthnOpts: AuthenticationOptions
    associatedtype AuthnData: AuthenticationData

    func getRegistrationData(_ options: RegOpts) async -> Result<RegData, Error>
    func verifyRegistration(_ result: PublicKeyCredentialCreateResult) async -> Result<Bool, Error>
    func getAuthenticationData(_ options: AuthnOpts) async -> Result<AuthnData, Error>
    func verifyAuthentication(_ result: PublicKeyCredentialGetResult) async -> Result<Bool, Error>
}
