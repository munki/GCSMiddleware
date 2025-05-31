//
//  RSAUtilsTests.swift
//  GCSMiddlewareTests
//
//  Created by Greg Neagle on 5/16/25.
//

import Foundation
import Testing

struct RSAUtilsTests {
    /// Tests that we can extract private key data from a PEM string containing an RSA PRIVATE KEY (PKCS#1)
    @Test func getRSAPrivateKeyDataFromPEM() {
        let keyData = privateKeyDataFromPEM(RSA_PRIVATE_KEY_STRING)
        #expect(keyData != nil)
    }

    /// Tests that we can extract private key data from a PEM string containing an RSA PRIVATE KEY (PKCS#1)
    /// where the string line breaks are CRLF (typical Windows line breaks)
    @Test func getRSAPrivateKeyDataFromPEMwithCRLFendings() {
        // change the line endings to CRLFs
        let pemString = RSA_PRIVATE_KEY_STRING
            .split(separator: "\n")
            .joined(separator: "\r\n")
        let keyData = privateKeyDataFromPEM(pemString)
        #expect(keyData != nil)
    }

    /// Tests that we can extract private key data from a PEM string containing a PRIVATE KEY (PKCS#8)
    @Test func getPKCS8PrivateKeyDataFromPEM() {
        let keyData = privateKeyDataFromPEM(PRIVATE_KEY_STRING)
        #expect(keyData != nil)
    }

    /// Tests that we can extract private key data from a PEM string containing an PRIVATE KEY (PKCS#8)
    /// where the string line breaks are CRLF (typical Windows line breaks)
    @Test func getPKCS8PrivateKeyDataFromPEMwithCRLFendings() {
        // change the line endings to CRLFs
        let pemString = PRIVATE_KEY_STRING
            .split(separator: "\n")
            .joined(separator: "\r\n")
        let keyData = privateKeyDataFromPEM(pemString)
        #expect(keyData != nil)
    }

    /// Tests that we can load a private key from RSA (PKCS#1) data
    @Test func privateKeyfromRSADataIsNotNil() throws {
        let keyData = privateKeyDataFromPEM(RSA_PRIVATE_KEY_STRING)
        let unwrappedKeyData = try #require(keyData, "Could not load private key data from RSA PEM string")

        let key = privateKeyfromData(unwrappedKeyData)
        #expect(key != nil)
    }

    /// Tests that we can load a private key from PKCS#8 data
    @Test func privateKeyfromPKCS8DataIsNotNil() throws {
        let keyData = privateKeyDataFromPEM(PRIVATE_KEY_STRING)
        let unwrappedKeyData = try #require(keyData, "Could not load private key data from PKCS8 PEM string")

        let key = privateKeyfromData(unwrappedKeyData)
        #expect(key != nil)
    }

    /// Tests the higher level function for geting a private key from a PEM string with RSA data
    @Test func getRsaPrivateKeyFromRSAPemString() {
        let key = rsaPrivateKeyFromPemString(RSA_PRIVATE_KEY_STRING)
        #expect(key != nil)
    }

    /// Tests the higher level function for geting a private key from a PEM string with PKCS#8 data
    @Test func getRsaPrivateKeyFromPKCS8PemString() {
        let key = rsaPrivateKeyFromPemString(PRIVATE_KEY_STRING)
        #expect(key != nil)
    }

    /// Tests that our signSHA1 function generates the expected signature
    @Test func signSHA1DataWithPrivateKeyGeneratesExpected() throws {
        let expectedSignature = "i+W2UtxTiYXoL/yeeYgGtQ4knoedWBS7DND0FUjL1usZIx6pwzqvxegwssuEvPRgWq+SQqXJT5ikX0ARNBzHU7ve/kg0TGjWNK0ZvtyXdoExpNnEI/u3glVcovMt8oGa4xr4RvWLyU57bdxvbkYIG0bsiMpD4mUffg7dxxguf7WQ7Be0+VkAByL/KJFyDl+oOTxqckuQJ27pPZrESeH46XA6YpsG/mcsTIXkXqSKd5NQ0cIEWHeQ8LL3yIafMQ5rSQCxWy54GJ38qD74O6e4aqJ5rtWbGWGl7bjgNPjgom+ECC1uKMP0NJT0S61NPETsxkYygxjrtdweio4WEwpABA=="
        let message = Data("Hello, World!".utf8)
        let keyData = privateKeyDataFromPEM(RSA_PRIVATE_KEY_STRING)
        let unwrappedKeyData = try #require(keyData, "Could not load private key data from PEM string")
        let key = privateKeyfromData(unwrappedKeyData)
        let unwrappedKey = try #require(key, "Could not load private key")

        let signature = signSHA1(message, withKey: unwrappedKey)
        #expect(signature?.base64EncodedString() == expectedSignature)
    }

    /// Tests that our signSHA256 function generates the expected signature
    @Test func signSHA256DataWithPrivateKeyGeneratesExpected() throws {
        let expectedSignature = "VWYnp4eMt/OVBmhfE0b3330IAliZrBYOCwGswJbrUbSE2d8iu9ocYB5emvML9YdwH+kGJKBgZSsmFUQsvOQbd7jkRjCukcTkpmMCDjFhKNQolXGQss+J5IGvDgGsgGJuHY42D4uPWrybvLODOS1UDDmwJoYbnz2GTxc2201zYYm0GP0j7Yr+gAvOPDZQoMLXGmF7iwYkF4a/iHhb5Lhn0JHQQwD0en7h1qlyiDCKZfZRo8wjy9q5ddE0Wv2YoHwJecqa3eFnVlcN3ebg29FthQEHTEX0ksslU7wZBYRnpIs2/hxVMsi6HrTkjPaT55SxUmuW4Y+hgdQ157CwtJ4UkQ=="
        let message = Data("FOO_BAR_BAZ".utf8)
        let keyData = privateKeyDataFromPEM(RSA_PRIVATE_KEY_STRING)
        let unwrappedKeyData = try #require(keyData, "Could not load private key data from PEM string")
        let key = privateKeyfromData(unwrappedKeyData)
        let unwrappedKey = try #require(key, "Could not load private key")

        let signature = signSHA256(message, withKey: unwrappedKey)
        #expect(signature?.base64EncodedString() == expectedSignature)
    }
}
