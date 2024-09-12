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
import SwiftCBOR

protocol AttestationObject {
    associatedtype AttStmt // attestation statement

    var fmt: String { get }
    var attStmt: AttStmt? { get }
    var authData: Data { get } // Its name must be authData not authenticatorData

    static func decode(_ data: Data) -> Result<Self, WebAuthnError>

    func toCBOR() -> Result<Data, WebAuthnError>
}

struct NoneAttestationObject: AttestationObject, Codable {
    typealias AttStmt = NoneStmt

    var fmt: String = "none"
    var attStmt: AttStmt?
    let authData: Data

    func toCBOR() -> Result<Data, WebAuthnError> {
        let attObj: [String: Any] = [
            "fmt": self.fmt,
            "attStmt": [:], // when the format is "none", `attStmt` should be empty.
            "authData": self.authData
        ]
        do {
            let cbor = try CBOR.encodeMap(attObj)
            return .success(Data(cbor))
        } catch {
            return .failure(.encodingError(error))
        }
    }

    static func decode(_ data: Data) -> Result<Self, WebAuthnError> {
        do {
            let decoded = try CodableCBORDecoder().decode(Self.self, from: data)
            return .success(decoded)
        } catch {
            return .failure(.encodingError(error))
        }
    }
}
