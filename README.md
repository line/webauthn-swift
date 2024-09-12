# WebAuthn Swift

WebAuthn Swift is an open-source implementation of the WebAuthn 2.0 standard for
secure and password-less authentication in mobile applications. It is built with
Swift and seamlessly integrates with native iOS apps. The WebAuthn Swift enables
developers to effortlessly integrate advanced authentication mechanisms,
streamlining the login process and providing strong security solutions for a
wide range of application requirements and user scenarios.

## Components

### PublicKeyCredential

`PublicKeyCredential` [protocol](./Sources/WebAuthn/PublicKeyCredential/PublicKeyCredential.swift)
is based on the WebAuthn 2.0 standard. This credential can be used for secure
authentication using an asymmetric key pair instead of using a password. The
protocol includes `create()` and `get()` methods for registration and
authentication.

- `create()`: This method allows you to register a user credential by generating
an asymmetric key pair. The private key is securely stored on the client side,
while the public key is stored by the relying party.
- `get()`: This method allows you to authenticate a user by communicating with a
relying party using a previously registered credential.

We offer two classes that inherit from `PublicKeyCredential`. Each class uses
different types of authenticators.

- [Biometric](./Sources/WebAuthn/PublicKeyCredential/Biometric.swift):
Manages public key credentials using [the biometric authenticator](./Sources/WebAuthn/Authenticator/BiometricAuthenticator.swift).
It facilitates secure user authentication by leveraging biometric features such
as Touch ID or Face ID on supported devices.
- [DeviceCredential](./Sources/WebAuthn/PublicKeyCredential/DeviceCredential.swift):
Manages public key credentials using [the device credential authenticator](./Sources/WebAuthn/Authenticator/DeviceCredentialAuthenticator.swift).
It enables secure user authentication by utilizing biometry or a passcode. If
biometry is available, the system uses that first. If not, the system prompts
the user for the device passcode or user's password.

### RelyingParty

`RelyingParty` [protocol](./Sources/WebAuthn/RelyingParty/RelyingParty.swift) is
essential for facilitating communication with your relying party which is a
server providing access to a secured software application.

### CredentialSourceStorage

`CredentialSourceStorage` is a [protocol](./Sources/WebAuthn/Storage/CredentialSourceStorage.swift)
that defines the behavior of a database for handling a public key credential
source and its [signature counter](https://www.w3.org/TR/webauthn-3/#signature-counter).

## Requirements

- Swift >= 5.9

## Getting Started

### Adding the dependency

Add the following entry in your `Package.swift` to start using `WebAuthn`:

```swift
.package(url: "https://github.com/line/webauthn-swift.git", from: "1.0.0")
```

and `WebAuthn` dependency to your target:
```swift
.target(name: "MyApp", dependencies: [.product(name: "WebAuthn", package: "webauthn-swift")])
```

## Usage

If you want to use a public key credential, you need to define your relying
party and credential source storage in advance. To get started
with your implementation, we recommend checking out a sample application
available on [GitHub](https://github.com/line/webauthndemo-swift). This sample
provides a practical example of how to implement each class inheriting each
protocol in a real-world application.

### Step 1: Implement a relying party class inheriting `RelyingParty` protocol

You need to create a relying party class inheriting `RelyingParty` protocol. We
strongly recommend to see the real implementation of relying party.

- [webauthndemo-swift/RelyingParty](https://github.com/line/webauthndemo-swift/blob/main/Shared/Authn/Network/RelyingParty.swift)

### Step 2: Implement a credential source storage class inheriting `CredentialSourceStorage` protocol

You need to create a credential source storage class inheriting
`CredentialSourceStorage` protocol. You need to store the following data
contained in [PublicKeyCredentialSource](./Sources/WebAuthn/Model/PublicKeyCredentialSource.swift)
and a signature counter for each credential source at a minimum.

We strongly recommend to see the real implementation using SQLite3.

- [webauthndemo-swift/CredentialSourceStorage](https://github.com/line/webauthndemo-swift/blob/main/Shared/Authn/Storage/CredentialSourceStorage.swift)

### Step 4: Initialize a public key credential class

Once you have your relying party, credential storage, and key storage
implementation ready, you can initialize the public key credential.

```swift
let rp = YourRelyingParty()
let db = YourCredentialSourceStorage()

// You can use a biometric for public key credential.
let credential = Biometric(rp, db)

// ,or you can use a device credential for public key credential.
let credential = DeviceCredential(rp, db) 
```

### Step 5: Create an asymmetric key pair and register a user

Call `create()` method to create an asymmetric key pair and register a user.

```swift
let options: yourRegistrationOptions = ...
let signUp: Result<Bool, Error> = await credential.create(options)
```

You can use the `performAsyncTask` method to execute the task asynchronously.

```swift
credential.performAsyncTask {
    let signUp = await credential.create(options)
}
```

### Step 6: Authenticate a user

Call `get()` method to authenticate a user using existing credential.

```swift
let options: yourAuthenticationOptions = ...
let signIn: Result<Bool, Error> = await credential.get(options)
```

You can also use the `performAsyncTask` method to execute the task
asynchronously.

```swift
credential.performAsyncTask {
    let signIn = await credential.get(options)
}
```

## Contact Information

We are committed to open-sourcing our work to support your use cases. We want to
know how you use this library and what problems it helps you to solve. For
communication, we encourage you to use the [Issues](https://github.com/line/webauthn-swift/issues)
section of our GitHub repository to report issues, suggest enhancements, or ask
questions about the library. This will help us to address your concerns more
efficiently and allow the community to benefit from your input.

Please refrain from posting any sensitive or confidential information in the
issues. If you need to discuss something sensitive, please mention that in your
issue, and we will find a more secure way to communicate.