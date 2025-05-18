//
//  RSAUtilsTests.swift
//  CloudFrontMiddlewareTests
//
//  Created by Greg Neagle on 5/16/25.
//

import Foundation
import Testing

struct RSAUtilsTests {
    @Test func getRSAPrivateKeyFromPEM() {
        let keyData = privateKeyDataFromPEM(RSA_PRIVATE_KEY_STRING)
        #expect(keyData != nil)
        let key = privateKeyfromData(keyData!)
        #expect(key != nil)
    }

    @Test func getPrivateKeyFromPEM() {
        let keyData = privateKeyDataFromPEM(PRIVATE_KEY_STRING)
        #expect(keyData != nil)
        let key = privateKeyfromData(keyData!)
        #expect(key != nil)
    }
    
    @Test func signSHA1DataWithPrivateKeyGeneratesExpected() {
        let expectedSignature = "i+W2UtxTiYXoL/yeeYgGtQ4knoedWBS7DND0FUjL1usZIx6pwzqvxegwssuEvPRgWq+SQqXJT5ikX0ARNBzHU7ve/kg0TGjWNK0ZvtyXdoExpNnEI/u3glVcovMt8oGa4xr4RvWLyU57bdxvbkYIG0bsiMpD4mUffg7dxxguf7WQ7Be0+VkAByL/KJFyDl+oOTxqckuQJ27pPZrESeH46XA6YpsG/mcsTIXkXqSKd5NQ0cIEWHeQ8LL3yIafMQ5rSQCxWy54GJ38qD74O6e4aqJ5rtWbGWGl7bjgNPjgom+ECC1uKMP0NJT0S61NPETsxkYygxjrtdweio4WEwpABA=="
        let message = Data("Hello, World!".utf8)
        if let keyData = privateKeyDataFromPEM(RSA_PRIVATE_KEY_STRING),
           let key = privateKeyfromData(keyData),
           let signature = signSHA1(message, withKey: key)
        {
            #expect(signature.base64EncodedString() == expectedSignature)
        } else {
            #expect(Bool(false))
        }
    }

    @Test func signSHA256DataWithPrivateKeyGeneratesExpected() {
        let expectedSignature = "VWYnp4eMt/OVBmhfE0b3330IAliZrBYOCwGswJbrUbSE2d8iu9ocYB5emvML9YdwH+kGJKBgZSsmFUQsvOQbd7jkRjCukcTkpmMCDjFhKNQolXGQss+J5IGvDgGsgGJuHY42D4uPWrybvLODOS1UDDmwJoYbnz2GTxc2201zYYm0GP0j7Yr+gAvOPDZQoMLXGmF7iwYkF4a/iHhb5Lhn0JHQQwD0en7h1qlyiDCKZfZRo8wjy9q5ddE0Wv2YoHwJecqa3eFnVlcN3ebg29FthQEHTEX0ksslU7wZBYRnpIs2/hxVMsi6HrTkjPaT55SxUmuW4Y+hgdQ157CwtJ4UkQ=="
        let message = Data("FOO_BAR_BAZ".utf8)
        if let keyData = privateKeyDataFromPEM(RSA_PRIVATE_KEY_STRING),
           let key = privateKeyfromData(keyData),
           let signature = signSHA256(message, withKey: key)
        {
            #expect(signature.base64EncodedString() == expectedSignature)
        } else {
            #expect(Bool(false))
        }
    }
}
