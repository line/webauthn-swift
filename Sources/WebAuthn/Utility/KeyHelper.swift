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

func convertSecKeyToCborEc2coseKey(_ key: SecKey) -> Result<Data, WebAuthnError> {
    switch convertSecKeyToData(key) { // key is always an uncompressed key
    case .failure(let err):
        return .failure(err)
    case .success(let keyData):
        let EC2COSEKey = EC2COSEKey.create(pubKey: keyData)
        switch EC2COSEKey.toCBOR() {
        case .failure(let err):
            return .failure(err)
        case .success(let cborEc2coseKey):
            return .success(cborEc2coseKey)
        }
    }
}

private func convertSecKeyToData(_ key: SecKey) -> Result<Data, WebAuthnError> {
    var error: Unmanaged<CFError>?
    guard let data = SecKeyCopyExternalRepresentation(key, &error) as? Data else {
        let error = error!.takeRetainedValue() as Error
        return .failure(.secKeyError(cause: error.localizedDescription))
    }
    return .success(data)
}

func generatePublicPrivateKeyPair(_ type: String, _ bits: Int) -> Result<SecKey, WebAuthnError> {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: type,
        kSecAttrKeySizeInBits as String: bits,
        kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        let error = error!.takeRetainedValue() as Error
        return .failure(.secKeyError(cause: error.localizedDescription))
    }
    return .success(key)
}

func getPublicKey(_ privateKey: SecKey) -> SecKey? {
    return SecKeyCopyPublicKey(privateKey)
}

func getKeyAlgorithm(_ key: SecKey) -> Result<SecKeyAlgorithm, WebAuthnError> {
    guard let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
          let keyType = attributes[kSecAttrKeyType] as? String,
          let keyLength = attributes[kSecAttrKeySizeInBits] as? Int
    else {
        return .failure(.secKeyError(cause: "Failed to get attributes related in given key"))
    }
    switch keyType as CFString {
    case kSecAttrKeyTypeECSECPrimeRandom:
        switch keyLength {
        case 256:
            return .success(.ecdsaSignatureMessageX962SHA256)
        default:
            return .failure(.secKeyError(cause: "Given key length is not currently supported: \(keyLength)"))
        }
    default:
        return .failure(.secKeyError(cause: "Given key type is not currently supported: \(keyType)"))
    }
}

func sign(_ privateKey: SecKey, _ algorithm: SecKeyAlgorithm, _ hash: Data) -> Result<Data, WebAuthnError> {
    guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
        return .failure(.secKeyError(cause: "Given algorithm is not supported: \(algorithm)"))
    }
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(privateKey, algorithm, hash as CFData, &error) as Data? else {
        let error = error!.takeRetainedValue() as Error
        return .failure(.secKeyError(cause: error.localizedDescription))
    }
    return .success(signature)
}
