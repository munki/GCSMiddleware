//
//  URLutils.swift
//  GCSMiddleware
//
//  Created by Greg Neagle on 5/17/25.
//

import Foundation

func encodeQueryItems(_ queryItems: [URLQueryItem]) -> String? {
    // Apple's URLQueryItems "automatically" encode their string
    // representations, but not the same way that, say, Python's
    // urllib quote_plus does. It's arguable if Apple does it
    // "correctly", but we're going to do something closer to the
    // way Python does it.
    var urlComponents = URLComponents()
    urlComponents.queryItems = queryItems
    if let queryString = urlComponents.string {
        return queryString
            .replacingOccurrences(of: "/", with: "%2F")
            .replacingOccurrences(of: "+", with: "%2B")
            .replacingOccurrences(of: "%20", with: "+")
    }
    return nil
}
