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

class AsyncOperation: Operation {
    private enum OperationState: String {
        case ready
        case executing
        case finished
    }

    private var stateLock = NSRecursiveLock()
    private var _state: OperationState = .ready
    private var state: OperationState {
        get {
            stateLock.lock()
            let value = _state
            stateLock.unlock()
            return value
        }
        set {
            stateLock.lock()
            defer {
                stateLock.unlock()
            }
            let oldValue = _state
            guard newValue != oldValue else { return }
            willChangeValue(forKey: newValue.rawValue)
            willChangeValue(forKey: oldValue.rawValue)
            _state = newValue
            didChangeValue(forKey: oldValue.rawValue)
            didChangeValue(forKey: newValue.rawValue)
        }
    }

    private let asyncTask: () async -> Void

    init(
        asyncTask: @escaping () async -> Void
    ) {
        self.asyncTask = asyncTask
    }

    override var isReady: Bool {
        super.isReady && state == .ready
    }

    override var isExecuting: Bool {
        state == .executing
    }

    override var isFinished: Bool {
        state == .finished
    }

    override func start() {
        state = .executing

        guard !isCancelled else {
            state = .finished
            return
        }

        main()
    }

    override func main() {
        Task {
            await asyncTask()
            state = .finished
        }
    }
}
