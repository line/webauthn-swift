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

import LocalAuthentication

public protocol LocalAuthenticationProtocol {
    var localizedReason: String { get set }

    func execute() async -> Result<Bool, WebAuthnError>
}

final class LocalAuthentication: LocalAuthenticationProtocol {
    var context = LAContext()

    let policy: LAPolicy
    var localizedReason = "Register your account"

    init(_ policy: LAPolicy) {
        self.policy = policy
    }

    func execute() async -> Result<Bool, WebAuthnError> {
        var error: NSError?
        guard context.canEvaluatePolicy(policy, error: &error) else {
            let msg = error?.localizedDescription ?? "Can't evaluate policy"
            return .failure(.coreError(.constraintError, cause: msg))
        }
        do {
            let result = try await context.evaluatePolicy(policy, localizedReason: localizedReason)
            return .success(result)
        } catch {
            return .failure(.laError(error))
        }
    }
}
