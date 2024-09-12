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

public enum WebAuthnError: Error {
    case coreError(CoreError, cause: String? = nil)
    case keyStorageError(KeyStorageError, credId: String, deleteTrigger: Error? = nil)
    case credSrcStorageError(Error, credId: String? = nil, deleteTrigger: Error? = nil) // credId can be nil when loadAll()
    case rpError(Error)
    case encodingError(Error)
    case laError(Error)
    case secKeyError(cause: String)
    case keyNotFoundError
    case utilityError(cause: String)
    case unknownError(Error)
}
