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

final class CommonTests: XCTestCase {
    func testDataToUInt8() {
        let data = Data.init([32])
        let uint8: UInt8 = 32
        XCTAssertEqual(data.toUInt8(), uint8)
    }

    func testUInt8ToData() {
        let uint8: UInt8 = 32
        let data = Data.init([32])
        XCTAssertEqual(uint8.toData(), data)
    }

    func testDataToUInt16BigEndian() {
        let data = Data.init([0, 32])
        let uint16: UInt16 = 32
        XCTAssertEqual(data.toUInt16BigEndian(), uint16)
    }

    func testUInt16ToDataBigEndian() {
        let uint16: UInt16 = 32
        let data = Data.init([0, 32])
        XCTAssertEqual(uint16.toDataBigEndian(), data)
    }

    func testDataToUInt32() {
        let data = Data.init([0, 0, 0, 5])
        let uint32: UInt32 = 5
        XCTAssertEqual(data.toUInt32BigEndian(), uint32)
    }

    func testUInt32ToData() {
        let uint32: UInt32 = 5
        let data = Data.init([0, 0, 0, 5])
        XCTAssertEqual(uint32.toDataBigEndian(), data)
    }

    func testBase64UrlToData() {
        let data = "data".toData()
        let base64Url = data.toBase64Url()
        let dataFromBase64Url = base64Url.base64UrlToData()
        XCTAssertNotNil(dataFromBase64Url)
        XCTAssertEqual(data, dataFromBase64Url)
    }
}
