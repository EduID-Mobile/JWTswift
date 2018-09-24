//
//  UtilExtensions.swift
//  JWTswift
//
//  Created by Blended Learning Center on 21.12.17.
//  Copyright © 2017 Blended Learning Center. All rights reserved.
//

import Foundation
import CommonCrypto
import Security

extension Data {
    public var hexDescription : String {
        return reduce(""){$0 + String(format: "%02x", $1)}
    }
    
    public func hashSHA256() -> Data {
        
        var result : [UInt8] = [UInt8].init(repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        var digestData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        print(CC_SHA256_DIGEST_LENGTH)
        _ = digestData.withUnsafeMutableBytes { digestBytes in
            self.withUnsafeBytes{ messageBytes in
                CC_SHA256(messageBytes, CC_LONG(self.count), digestBytes)
            }
        }
        
        digestData.copyBytes(to: &result, count: digestData.count)
        
        return Data(bytes: result)
    }
    
    public func hashSHA512() -> Data {
        var result: [UInt8] = [UInt8].init(repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        var digestData = Data(count: Int(CC_SHA512_DIGEST_LENGTH))
        
        _ = digestData.withUnsafeMutableBytes { digestBytes in
            self.withUnsafeBytes{ messageBytes in
                CC_SHA512(messageBytes, CC_LONG(self.count), digestBytes)
            }
        }
        
        digestData.copyBytes(to: &result, count: digestData.count)
        
        return Data(bytes: result)
    }
}

extension String{
    
    public func hexToBase64() -> Data {
        var hex = self
        var data = Data()
        while hex.count > 0 {
            
            let indexHex = hex.index(hex.startIndex, offsetBy: 2)
            let c : String = String(hex[..<indexHex])
            hex = String(hex[indexHex...])
            var ch: UInt32 = 0
            Scanner(string: c).scanHexInt32(&ch)
            var char = UInt8 (ch)
            data.append(&char, count: 1)
        }
        //        let base64Str = data.base64EncodedString()
        
        return data // base64Str.clearPaddding()
    }
    
    public func base64ToBase64Url() -> String {
        let base64url = self.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        return base64url
    }
    
    public func base64UrlToBase64() -> String {
        let base64 = self.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        /* NO PADDING
         while(base64.count % 4 != 0){
         base64.append("=")
         }*/
        return base64
    }
    
    public func clearPaddding() -> String {
        var tmp = self
        while(tmp.last == "="){
            tmp.removeLast()
        }
        return tmp
    }
    
    public func addPadding() -> String {
        var tmp = self
        while(tmp.count % 4 != 0){
            tmp.append("=")
        }
        return tmp
    }
    
}

extension Sequence where Iterator.Element == Character {
    
    func asByteArray() -> [UInt8] {
        return String(self).utf8.map{UInt8($0)}
    }
}
