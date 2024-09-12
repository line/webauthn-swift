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

// It can be possible to generate several `PublicKeyCredential` instances
// concurrently. It means that multiple accounts can be registered for one user.
// To avoid this issue, we manage it using an operation queue to register
// accounts not in parallel.
private var _webAuthnQueue = OperationQueue()

/// It defines the behavior of a public key credential.
///
/// `PublicKeyCredential` protocol is based on the WebAuthn 2.0 standard. This
/// credential can be used for secure authentication using an asymmetric key
/// pair instead of using a password. The protocol includes create() and get()
/// methods for registration and authentication.
public protocol PublicKeyCredential {
    associatedtype RP: RelyingParty

    var aaguid: UUID { get }
    var rp: RP { get }
    var credSrcStorage: CredentialSourceStorage { get }
    var keyStorage: KeyStorage { get }
    var localAuthn: LocalAuthenticationProtocol { get }
}

extension PublicKeyCredential {
    private static var WebAuthnQueue: OperationQueue {
        _webAuthnQueue.maxConcurrentOperationCount = 1 // Serial queue
        return _webAuthnQueue
    }

    /// This method allows you to perform an asynchronous task.
    public func performAsyncTask(_ asyncTask: @escaping () async -> Void) {
        Task { @MainActor in // execute on the same thread to ensure operations are added in order
            Self.WebAuthnQueue.addOperation(AsyncOperation(asyncTask: asyncTask))
        }
    }

    /// This method allows you to register a user credential by generating an
    /// asymmetric key pair. The private key is securely stored on the client
    /// side, while the public key is stored by the relying party.
    public func create(_ options: RP.RegOpts) async -> Result<Bool, WebAuthnError> {
        var credIdStr: String?
        do {
            let data = try await rp.getRegistrationData(options).mapError { e in
                WebAuthnError.rpError(e)
            }.get()
            let createOptions = PublicKeyCredentialCreationOptions(
                rp: data.rp,
                user: data.user,
                challenge: data.challenge,
                publicKeyCredentialParams: data.pubKeyCredParams,
                excludeCredentials: data.excludeCredentials,
                authenticatorSelection: data.authenticatorSelection,
                attestation: data.attestation,
                extensions: data.extensions)
            let userIdLen = createOptions.user.id.count
            guard 1 <= userIdLen, userIdLen <= 64 else {
                throw WebAuthnError.coreError(.typeError, cause: "User ID length is invalid: \(userIdLen)")
            }
            let credTypesAndPubKeyAlgs = getCredTypesAndPubKeyAlgs(createOptions.publicKeyCredentialParams)
            guard !credTypesAndPubKeyAlgs.isEmpty else {
                throw WebAuthnError.coreError(.notSupportedError, cause: "`credTypesAndPubKeyAlgs` is empty")
            }
            guard let origin = getOrigin() else {
                throw WebAuthnError.utilityError(cause: "Failed to get an origin")
            }
            let collectedClientData = CollectedClientData(
                type: "webauthn.create", challenge: createOptions.challenge, origin: origin)
            let clientDataJson = try collectedClientData.encodeJSON().get()
            guard let authnType = AuthenticatorType(aaguid: aaguid) else {
                throw WebAuthnError.coreError(.notSupportedError, cause: "Given aaguid is not supported: \(aaguid)")
            }
            let authenticator = getAuthenticator(authnType: authnType)
            let authnResult = try await authenticator.makeCredential(
                hash: clientDataJson.toSHA256(),
                rpEntity: createOptions.rp,
                userEntity: createOptions.user,
                credTypesAndPubKeyAlgs: credTypesAndPubKeyAlgs,
                excludeCredentialDescriptorList: createOptions.excludeCredentials,
                extensions: createOptions.extensions?.processAuthenticatorExtensionsInput()).get()
            credIdStr = authnResult.credentialId.toBase64Url()
            let createResult = PublicKeyCredentialCreateResult(
                id: authnResult.credentialId,
                clientDataJson: clientDataJson,
                attestation: authnResult.attestationObject,
                clientExtensionsOutput: createOptions.extensions?.processClientExtensionsOutput())
            let result = try await rp.verifyRegistration(createResult).mapError { e in
                WebAuthnError.rpError(e)
            }.get()
            return .success(result)
        } catch {
            // If credIdStr is not nil, it means that authenticator task was
            // successfully completed, but an error occurred during verification
            // in relying party. In this case, the contents of the key storage
            // and credential source storage need to be deleted.
            if let credIdStr = credIdStr {
                var err: WebAuthnError
                if let error = error as? WebAuthnError {
                    err = error
                } else {
                    err = .unknownError(error)
                }
                let result = deleteStorage(credIdStr, deleteTrigger: err)
                switch result {
                case .failure(let deleteErr):
                    return .failure(deleteErr)
                case .success(_):
                    return .failure(err)
                }
            } else {
                guard let error = error as? WebAuthnError else {
                    return .failure(WebAuthnError.unknownError(error))
                }
                return .failure(error)
            }
        }
    }

    /// This method allows you to authenticate a user by communicating with a
    /// relying party using a previously registered credential.
    public func get(_ options: RP.AuthnOpts) async -> Result<Bool, WebAuthnError> {
        do {
            let data = try await rp.getAuthenticationData(options).mapError { e in
                WebAuthnError.rpError(e)
            }.get()
            let getOptions = PublicKeyCredentialRequestOptions(
                rpId: data.rpId,
                challenge: data.challenge,
                allowCredentials: data.allowCredentials,
                userVerification: data.userVerification,
                extensions: data.extensions)
            guard let origin = getOrigin() else {
                throw WebAuthnError.utilityError(cause: "Failed to get an origin")
            }
            let collectedClientData = CollectedClientData(
                type: "webauthn.get", challenge: getOptions.challenge, origin: origin)
            let clientDataJson = try collectedClientData.encodeJSON().get()
            guard let authnType = AuthenticatorType(aaguid: aaguid) else {
                throw WebAuthnError.coreError(.notSupportedError, cause: "Given aaguid is not supported: \(aaguid)")
            }
            let authenticator = getAuthenticator(authnType: authnType)
            let authnResult = try await authenticator.getAssertion(
                rpId: getOptions.rpId,
                hash: clientDataJson.toSHA256(),
                allowCredentialDescriptorList: getOptions.allowCredentials,
                extensions: getOptions.extensions?.processAuthenticatorExtensionsInput()).get()
            let getResult = PublicKeyCredentialGetResult(
                id: authnResult.credentialId,
                clientDataJson: clientDataJson,
                userHandle: authnResult.userHandle,
                authenticatorData: authnResult.authenticatorData,
                signature: authnResult.signature,
                clientExtensionsOutput: getOptions.extensions?.processClientExtensionsOutput())
            let result = try await rp.verifyAuthentication(getResult).mapError { e in
                WebAuthnError.rpError(e)
            }.get()
            return .success(result)
        } catch {
            guard let error = error as? WebAuthnError else {
                return .failure(WebAuthnError.unknownError(error))
            }
            return .failure(error)
        }
    }

    private func getCredTypesAndPubKeyAlgs(_ params: [PublicKeyCredentialParameters]
    ) -> [PublicKeyCredentialParameters] {
        let type = "public-key"
        var credTypesAndPubKeyAlgs: [PublicKeyCredentialParameters] = []
        if params.isEmpty {
            credTypesAndPubKeyAlgs.append(PublicKeyCredentialParameters(type: type, alg: .ES256))
            credTypesAndPubKeyAlgs.append(PublicKeyCredentialParameters(type: type, alg: .RS256))
        } else {
            for param in params where param.type == type {
                credTypesAndPubKeyAlgs.append(param)
            }
        }
        return credTypesAndPubKeyAlgs
    }

    private func getAuthenticator(authnType: AuthenticatorType) -> Authenticator {
        switch authnType {
        case .biometric:
            return BiometricAuthenticator(credSrcStorage, keyStorage, localAuthn)
        case .deviceCredential:
            return DeviceCredentialAuthenticator(credSrcStorage, keyStorage, localAuthn)
        }
    }

    private func deleteStorage(_ id: String, deleteTrigger: WebAuthnError) -> Result<(), WebAuthnError> {
        let maxDeleteRetry = 2
        for trial in 0..<maxDeleteRetry {
            do {
                let keyStorageResult = keyStorage.delete(id)
                switch keyStorageResult {
                case .failure(let err):
                    throw WebAuthnError.keyStorageError(err, credId: id, deleteTrigger: deleteTrigger)
                case .success(_):
                    let credSrcStorageResult = credSrcStorage.delete(id)
                    switch credSrcStorageResult {
                    case .failure(let err):
                        throw WebAuthnError.credSrcStorageError(err, credId: id, deleteTrigger: deleteTrigger)
                    case .success(_):
                        break
                    }
                }
            } catch {
                if trial == maxDeleteRetry - 1 {
                    // Only errors of type `WebAuthnError` are thrown.
                    return .failure(error as! WebAuthnError)
                }
            }
        }
        return .success(())
    }
}
