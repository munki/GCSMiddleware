//
//  GCSMiddlewareTests.swift
//  GCSMiddlewareTests
//
//  Created by Greg Neagle on 5/17/25.
//

import Foundation
import Testing

struct GCSMiddlewareTests {
    @Test func generateSignedUrlReturnsExpected() throws {
        let expectedURL = "https://storage.googleapis.com/foo/bar?GoogleAccessId=readonly@double.iam.gserviceaccount.com&Expires=1747270308&Signature=Hga23aNsQKDiLUceCarzz1UQvwOHQMNNunWAFpmIy%2FNwTb%2BfSXz97jXMnWpH16oQLA%2BJZ%2BskeyE3jg8%2FLBdO9Vq6eCdxAaAo%2Fh5UKIgq8jGLd2DqzkLWLYkd77VimhbQdspa5yHz3GSVinYncgfke%2FwdRgqQorTJix33AykskNR7osQD0jrAqvr8tXONm%2F2nbueIEjwCjoTJ%2FDWa3eetKzffCE4vlIl2aQWxQ%2BkwlkY3UdWQa1a%2FGdGGf5axxbZ4OdROJdGTPXP4VfId2XK0PMKZPc2sjO1Mw%2Fzvq211dkEtmiNQ3Yik4PbI80xv3ytONthVENOR9KArRcAQcE3eAw%3D%3D"
        let url = "https://storage.googleapis.com/foo/bar"
        let clientId = "readonly@double.iam.gserviceaccount.com"
        let expiration = 1_747_270_308
        let key = rsaPrivateKeyFromPemString(RSA_PRIVATE_KEY_STRING)
        let unwrappedKey = try #require(key, "Could not load RSA private key from PEM string")

        let signedURL = generateSignedUrl(
            url,
            withKey: unwrappedKey,
            clientId: clientId,
            expiration: expiration,
        )
        #expect(signedURL == expectedURL)
    }

    @Test func generateSignedUrlFromPercentEncodedURLReturnsExpected() throws {
        let expectedURL = "https://storage.googleapis.com/foo/bar%20baz?GoogleAccessId=readonly@double.iam.gserviceaccount.com&Expires=1747270308&Signature=4BNAeHKlLZRqW0St49hf5FRszUsHQ9YvBHDSh3%2BsFxyQec%2F14nwvZR5%2FB%2FMU6199kswVu1IFFAnJADqSHwnpIvJd1yxtj8vFIM8wcaWGGtleQFVRXjQPJXi%2BUfyRNrWhhqAmmch9D%2F3aEQNEcVFejiq7d4wtgokbM2gGN3rQGEFrVMWtwXdi%2F6j%2FE3rOBuGNIgn429c%2BFg%2BoK0AHEZ2hac1QKdNqt%2Fp64zkwlicHhMjW%2FbN9ha5i6o0YLn1dKkQG1K9WZyi880TiPHpZNYd%2Fke7OhwM9nLL8zff13l7FaH7hsHxTPwTHG%2BtD4116AUKTbO6vpfLRmWWPwBAwRyJHkQ%3D%3D"
        let url = "https://storage.googleapis.com/foo/bar%20baz"
        let clientId = "readonly@double.iam.gserviceaccount.com"
        let expiration = 1_747_270_308
        let key = rsaPrivateKeyFromPemString(RSA_PRIVATE_KEY_STRING)
        let unwrappedKey = try #require(key, "Could not load RSA private key from PEM string")

        let signedURL = generateSignedUrl(
            url,
            withKey: unwrappedKey,
            clientId: clientId,
            expiration: expiration,
        )
        #expect(signedURL == expectedURL)
    }

    // Make sure we can parse the gcs.json file
    @Test func readJsonKeyStore() throws {
        let jsonPath = try #require(TestingResource.path(for: "gcs.json"),
                                    "Could not get path for gcs.json")

        // readJsonKeystore result is an optional tuple of (SecKey, String)
        let result = readJsonKeystore(jsonPath)
        #expect(result?.0 != nil, "Failed to load private key from gcs.json")
        #expect(result?.1 == "readonly@double.iam.gserviceaccount.com",
                "Failed to read expected clientID from gcs.json")
    }

    /// Test that a non-GCS request is returned unmodified
    @Test func nonGCSRequestShouldNotBeModified() async throws {
        let request = MunkiMiddlewareRequest(
            url: "https://example.com",
            headers: [:]
        )
        // currently MunkiMiddlewareRequest structs are not directly comparable, so we''ll just
        // compare the instance variables
        let processedRequest = GCSMiddleware().processRequest(request)
        #expect(processedRequest.url == request.url)
        #expect(processedRequest.headers == request.headers)
    }
}
