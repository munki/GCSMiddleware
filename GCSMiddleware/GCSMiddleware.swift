//
//  GCSMiddleware.swift
//  GCSMiddleware
//
//  Created by Greg Neagle on 5/17/25.
//
//  Copyright 2025 Greg Neagle.
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       https://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

import Foundation
import Security

/// Construct a string to sign with the provided key and returns the complete url.
func generateSignedUrl(
    _ url: String,
    withKey key: SecKey,
    clientId: String,
    expiration: Int
) -> String? {
    guard let parsedURL = URL(string: url) else { return nil }
    let path = parsedURL.path
    let toSign = "GET\n\n\n\(expiration)\n\(path)"
    if let signature = signSHA256(Data(toSign.utf8), withKey: key) {
        let signatureString = signature.base64EncodedString()
        let queryItems = [
            URLQueryItem(name: "GoogleAccessId", value: clientId),
            URLQueryItem(name: "Expires", value: String(expiration)),
            URLQueryItem(name: "Signature", value: signatureString),
        ]
        if let queryString = encodeQueryItems(queryItems) {
            return "https://storage.googleapis.com\(path)\(queryString)"
        }
    }
    return nil
}

/// Read our json file that contains our private key and client ID
func readJsonKeystore(_ path: String) -> (SecKey, String)? {
    if FileManager.default.fileExists(atPath: path),
       let data = FileManager.default.contents(atPath: path)
    {
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: String],
           let privateKeyData = json["private_key"],
           let privateKey = rsaPrivateKeyFromPemString(privateKeyData),
           let clientId = json["client_email"]
        {
            return (privateKey, clientId)
        }
    }
    // we got nothin'
    return nil
}

/// Construct a signed GCS url
func buildSignedGCSurl(_ url: String) -> String? {
    // expiration is 15 minutes from now
    let expiration = Int(Date().timeIntervalSince1970) + 15 * 60
    let jsonFile = (Bundle.main.bundlePath as NSString).appendingPathComponent("middleware/gcs.json")
    if let (key, clientId) = readJsonKeystore(jsonFile) {
        return generateSignedUrl(url, withKey: key, clientId: clientId, expiration: expiration)
    }
    return nil
}

class GCSMiddleware: MunkiMiddleware {
    func processRequest(_ request: MunkiMiddlewareRequest) -> MunkiMiddlewareRequest {
        if request.url.hasPrefix("https://storage.googleapis.com"),
           let modifiedURL = buildSignedGCSurl(request.url)
        {
            var modifiedRequest = request
            modifiedRequest.url = modifiedURL
            return modifiedRequest
        }
        // not a Google storage URL, leave the request unmodified
        return request
    }
}

// MARK: dylib "interface"

final class GCSMiddlewareBuilder: MiddlewarePluginBuilder {
    override func create() -> MunkiMiddleware {
        return GCSMiddleware()
    }
}

/// Function with C calling style for our dylib.
/// We use it to instantiate the MunkiMiddleware object and return an instance
@_cdecl("createPlugin")
public func createPlugin() -> UnsafeMutableRawPointer {
    return Unmanaged.passRetained(GCSMiddlewareBuilder()).toOpaque()
}
