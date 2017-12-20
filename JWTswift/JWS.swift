//
//  JWS.swift
//  eduid-iOS
//
//  Created by Blended Learning Center on 08.12.17.
//  Copyright © 2017 Blended Learning Center. All rights reserved.
//

import Security
import Foundation

class JWS{
    
    var headerStr : String? = nil
    var payloadStr : String? = nil
    var signatureStr : String? = nil
    
    init() {
        
    }
    
    func sign(header: [String : Any], payload : [String: Any], key : SecKey) -> String? {
        var result : String?
        do{
            let jsonHeader = try JSONSerialization.data(withJSONObject: header, options: .init(rawValue: 0))
            var headerEncoded = jsonHeader.base64EncodedString()
            headerEncoded = removePadding(text: headerEncoded)
            let jsonPayload = try JSONSerialization.data(withJSONObject: payload, options: .init(rawValue: 0))
            var payloadEncoded = jsonPayload.base64EncodedString()
            payloadEncoded = removePadding(text: payloadEncoded)
            let dataToSign = headerEncoded + "." + payloadEncoded
            print("DATA TO SIGN : \(dataToSign)")
            
            var error : Unmanaged<CFError>?
            let signature = SecKeyCreateSignature(key, SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256, dataToSign.data(using: String.Encoding.utf8)! as CFData, &error) as Data?
            result = removePadding(text: (signature?.base64EncodedString())! )
            self.signatureStr = result! //+ "=="
            print("SIGNATURE : \(String(describing: result))" , " Length : \(String(describing: result?.count))")
            result = dataToSign + "." + result!
        }catch {print(error)}
        
        return result
    }
    
//    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
//    - RSA signature with PKCS#1 padding, input data must be SHA-256 generated digest.
//    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
//    - RSA signature with PKCS#1 padding, SHA-256 digest is generated from input data of any size.
    func verify(header :  [String : Any] , payload :[String: Any] , signature: inout String, key : SecKey ) -> Bool {
        var result : Bool = false
        while(signature.count%4 != 0){
            signature += "="
        }
        let datasignature = Data.init(base64Encoded: signature, options: .ignoreUnknownCharacters)
        print("DATA SIG: " , datasignature!.base64EncodedString())
        do{
            let jsonHeader = try JSONSerialization.data(withJSONObject: header, options: .init(rawValue: 0))
            var headerEncoded = jsonHeader.base64EncodedString()
            headerEncoded = removePadding(text: headerEncoded)
            let jsonPayload = try JSONSerialization.data(withJSONObject: payload, options: .init(rawValue: 0))
            var payloadEncoded = jsonPayload.base64EncodedString()
            payloadEncoded = removePadding(text: payloadEncoded)
            let signedData = headerEncoded + "." + payloadEncoded
            print("SIGNEDDATA : \(signedData)")
            var error: Unmanaged<CFError>?
            result = SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256, signedData.data(using: String.Encoding.utf8)! as CFData, datasignature! as CFData, &error)
        }catch{
            print(error)
            return false
        }
        
        return result
    }
    
    private func removePadding(text : String) -> String{
        var result = text
        while result.last == "=" {
            result.removeLast()
        }
        return result
    }
    
    
    func createHeader (headerDictionary : [String:Any]) -> String{
        var keys : [String] = []
        var header : [String : Any] = [:]
        keys.append("typ")
        keys.append("alg")
        header["typ"] = "JWT"
        header["alg"] = "HS256"
        print(header.description)
        var headerStr = "{"
        for i in 0..<keys.count {
            headerStr += "\"\(keys[i])\":" + "\"\(header[keys[i]] as! String)\""
            if(i < keys.count - 1) { headerStr += ",\r\n "}
        }
        headerStr += "}"
        return headerStr
    }
    
    
}
