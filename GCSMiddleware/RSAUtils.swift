//
//  RSAUtils.swift
//  CloudFrontMiddleware
//
//  Created by Greg Neagle on 5/16/25.
//

import Foundation
import Security

// Some notes on loading private keys from PEM data
// https://developer.apple.com/forums/thread/680572
// https://developer.apple.com/forums/thread/680554
// https://developer.apple.com/forums/thread/773777

// Some Amazon CloudFront documentation:
// https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-trusted-signers.html#private-content-creating-cloudfront-key-pairs
//
// from this, we can be pretty sure we're going to be dealing with
// 2048-bit RSA keys, which makes things simpler. See specifically:
//
//    "The key pair that you create must meet the following requirements:
//
//    It must be an SSH-2 RSA key pair.
//    It must be in base64-encoded PEM format.
//    It must be a 2048-bit key pair."
//

private let RSA_PRIVATE_KEY_START = "-----BEGIN RSA PRIVATE KEY-----"
private let RSA_PRIVATE_KEY_END = "-----END RSA PRIVATE KEY-----"
private let PRIVATE_KEY_START = "-----BEGIN PRIVATE KEY-----"
private let PRIVATE_KEY_END = "-----END PRIVATE KEY-----"

/// Extracts data from a PEM string and returns it
func dataFromPEM(_ pem: String, startTag: String, endTag: String) -> Data? {
    guard let startIndex = pem.range(of: startTag)?.upperBound,
          let endIndex = pem.range(of: endTag)?.lowerBound
    else {
        return nil
    }
    let keyDataBase64 = String(pem[startIndex ..< endIndex])
        .trimmingCharacters(in: .whitespacesAndNewlines)
        .components(separatedBy: .newlines)
        .joined()
    guard let keyData = Data(base64Encoded: keyDataBase64) else {
        return nil
    }
    return keyData
}

/// Removes the PKCS#8 header from the keyData, hopefully returning  PKCS#1 (RSA private key) data
/// Credit to https://github.com/btnguyen2k/swiftutils/blob/master/SwiftUtils/RSAUtils.swift
func stripPKCS8Header(_ privkey: Data) -> Data? {
    if privkey.count == 0 {
        return nil
    }

    var keyAsArray = [UInt8](repeating: 0, count: privkey.count / MemoryLayout<UInt8>.size)
    (privkey as NSData).getBytes(&keyAsArray, length: privkey.count)

    // PKCS#8: magic byte at offset 22, check if it's actually ASN.1
    var idx = 22
    if keyAsArray[idx] != 0x04 {
        return privkey
    }
    idx += 1

    // now we need to find out how long the key is, so we can extract the correct hunk
    // of bytes from the buffer.
    var len = Int(keyAsArray[idx])
    idx += 1
    let det = len & 0x80 // check if the high bit set
    if det == 0 {
        // no? then the length of the key is a number that fits in one byte, (< 128)
        len = len & 0x7F
    } else {
        // otherwise, the length of the key is a number that doesn't fit in one byte (> 127)
        var byteCount = Int(len & 0x7F)
        if byteCount + idx > privkey.count {
            return nil
        }
        // so we need to snip off byteCount bytes from the front, and reverse their order
        var accum: UInt = 0
        var idx2 = idx
        idx += byteCount
        while byteCount > 0 {
            // after each byte, we shove it over, accumulating the value into accum
            accum = (accum << 8) + UInt(keyAsArray[idx2])
            idx2 += 1
            byteCount -= 1
        }
        // now we have read all the bytes of the key length, and converted them to a number,
        // which is the number of bytes in the actual key.  we use this below to extract the
        // key bytes and operate on them
        len = Int(accum)
    }
    return privkey.subdata(in: idx ..< idx + len)
}

/// Lifted from Quinn "The Eskimo!": https://developer.apple.com/forums/thread/773777
/// We're not using this any more, instead uising stripPKCS8Header
func getRSA2048PrivateKeyDataFromPKCS8Data(_ keyData: Data) -> Data? {
    // Most private key PEMs are in PKCS#8 format.  There’s no way to import
    // that directly.  Instead you need to strip the header to get to the
    // `RSAPrivateKey` data structure (which is PKCS#1) encapsulated within
    // the PKCS#8. Doing that in the general case is hard.  In the specific
    // case of an 2048-bit RSA key, the following hack works.
    let rsaPrefix: [UInt8] = [
        0x30, 0x82, 0x04, 0xBE, 0x02, 0x01, 0x00, 0x30,
        0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
        0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82,
        0x04, 0xA8,
    ]
    guard keyData.starts(with: rsaPrefix) else {
        return nil
    }
    return keyData.dropFirst(rsaPrefix.count)
}

/// Attempt to parse a PEM string and get private key data
func privateKeyDataFromPEM(_ pem: String) -> Data? {
    if pem.contains(RSA_PRIVATE_KEY_START),
       let keyData = dataFromPEM(pem, startTag: RSA_PRIVATE_KEY_START, endTag: RSA_PRIVATE_KEY_END)
    {
        // -----BEGIN RSA PRIVATE KEY----- is a hint the key data is already in PKCS#1 format
        return keyData
    } else if pem.contains(PRIVATE_KEY_START),
              let keyData = dataFromPEM(pem, startTag: PRIVATE_KEY_START, endTag: PRIVATE_KEY_END)
    {
        // -----BEGIN PRIVATE KEY----- is a hint the key data is in PKCS#8 format
        // need to extract the PKCS#1 data from the PKCS#8 data
        return stripPKCS8Header(keyData)
    }
    return nil
}

/// Attempts to create a SecKey from data which must be in PKCS#1 format
func privateKeyfromData(_ data: Data) -> SecKey? {
    let keyAttrs = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass: kSecAttrKeyClassPrivate,
    ] as NSDictionary
    var error: Unmanaged<CFError>?
    let keyRef: SecKey? = SecKeyCreateWithData(
        data as CFData,
        keyAttrs as CFDictionary,
        &error
    )
    return keyRef
}

/// Attempts to load an RSA private key from a PEM string
func rsaPrivateKeyFromPemString(_ pem: String) -> SecKey? {
    guard let data = privateKeyDataFromPEM(pem) else {
        return nil
    }
    return privateKeyfromData(data)
}

/// Attempts to load an RSA private key from PEM-formatted data
func rsaPrivateKeyFromPemData(_ pem: Data) -> SecKey? {
    if let pemString = String(data: pem, encoding: .utf8) {
        return rsaPrivateKeyFromPemString(pemString)
    }
    return nil
}

/// Sign some data with a private key
func sign(_ data: Data, withKey key: SecKey, using algorithm: SecKeyAlgorithm) -> Data? {
    var error: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
        key,
        algorithm,
        data as CFData,
        &error
    ) as Data? else {
        let e = error!.takeRetainedValue() as Error
        print(e.localizedDescription)
        return nil
    }
    return signature
}

func signSHA1(_ data: Data, withKey key: SecKey) -> Data? {
    let algorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA1
    return sign(data, withKey: key, using: algorithm)
}

func signSHA256(_ data: Data, withKey key: SecKey) -> Data? {
    let algorithm = SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256
    return sign(data, withKey: key, using: algorithm)
}
