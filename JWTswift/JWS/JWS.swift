//
//  JWS.swift
//  eduid-iOS
//
//  Created by Blended Learning Center on 08.12.17.
//  Copyright © 2017 Blended Learning Center. All rights reserved.
//

import Security
import Foundation

public enum JWSAlgorithm {
    case HS256
    case RS256
    case ES256
}

public class JWS{
    //header would be generated automatically as default on the sign() function below.
    public var headerDict : [String : Any]? = nil
    public var payloadDict : [String : Any]? = nil
    var signatureStr : String? = nil
    public var jwsCompactResult : String? = nil
    
    public init() {
        
    }
    
    public init(payloadDict :  [String : Any]) {
        self.payloadDict = payloadDict
    }
    
    
    /**
     Sign a header and payload data together with a specific key to create a signature
     - returns : A complete String of JWS with the following format (header.payload.signature)
     */
    public func sign(key : Key , alg : JWSAlgorithm) -> String? {
        var headerVar = [String: Any]()
        var payloadVar = [String: Any]()
        //kid in key is always in base64url
        headerVar["kid"] = key.getKid()
        headerVar["typ"] = "JWT"
        if alg == JWSAlgorithm.RS256 {
            headerVar["alg"] = "RS256"
        }else{
            print("algorithm : \(alg) is not supported")
            return nil
        }
        self.headerDict = headerVar
        payloadVar = self.payloadDict!
        
        var result : String?
        do{
            let jsonHeader = try JSONSerialization.data(withJSONObject: headerVar, options: .init(rawValue: 0))
            var headerEncoded = jsonHeader.base64EncodedString()
            headerEncoded = headerEncoded.clearPaddding().base64ToBase64Url()
            let jsonPayload = try JSONSerialization.data(withJSONObject: payloadVar, options: .init(rawValue: 0))
            var payloadEncoded = jsonPayload.base64EncodedString()
            payloadEncoded = payloadEncoded.clearPaddding().base64ToBase64Url()
            let dataToSign = headerEncoded + "." + payloadEncoded
            print("DATA TO SIGN : \(dataToSign)")
            
            var error : Unmanaged<CFError>?
            let signature = SecKeyCreateSignature(key.getKeyObject(), SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256, dataToSign.data(using: String.Encoding.utf8)! as CFData, &error) as Data?
            result = (signature?.base64EncodedString())!.clearPaddding().base64ToBase64Url()
            self.signatureStr = result! //+ "=="
            print("SIGNATURE : \(String(describing: result))" , " Length : \(String(describing: result?.count))")
            result = dataToSign + "." + result!
        }catch {
            print(error)
            return nil
        }
        if self.headerDict != nil && self.payloadDict != nil{
            self.jwsCompactResult = result
        }
        return result
    }
    
    //    kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
    //    - RSA signature with PKCS#1 padding, input data must be SHA-256 generated digest.
    //    kSecKeyAlgorithmRSASignatureMessagePKCS1v15SHA256
    //    - RSA signature with PKCS#1 padding, SHA-256 digest is generated from input data of any size.
    
    /**
     Verify function to check if the data has been sent by the desired Sender
     - parameter jwsToVerify : a jws compact serialization, that to be verified
     - parameter key: a key to verify the signature of the JWS package
     -returns:  Status from verifying the data, true if successful, false if not verified or if there any error on process
     */
    public static func verify(jwsToVerify : String, key : Key) -> Bool{
        var result : Bool
        
        let stringsTmp = jwsToVerify.split(separator: ".")
        let header = String(stringsTmp[0])
        let payload = String(stringsTmp[1])
        var signature = String(stringsTmp[2])
        
        let signedData = header + "." + payload
        
        while(signature.count%4 != 0){
            signature += "="
        }
        let datasignature = Data.init(base64Encoded: signature.base64UrlToBase64(), options: .ignoreUnknownCharacters)
        
        var error: Unmanaged<CFError>?
        result = SecKeyVerifySignature(key.getKeyObject(), .rsaSignatureMessagePKCS1v15SHA256, signedData.data(using: String.Encoding.utf8)! as CFData, datasignature! as CFData, &error)
        
        return result
    }
    
    public func verifyWithDict(header :  [String : Any]? , payload :[String: Any]? , signature: String , key : Key ) -> Bool {
        
        var headerVar : [String: Any]
        var payloadVar : [String: Any]
        var signatureTmp = signature
        if header == nil {
            if self.headerDict == nil {
                print("No header data found for this signing")
                return false
            } else {
                headerVar = self.headerDict!
            }
        } else{
            headerVar = header!
        }
        
        if payload == nil{
            if self.payloadDict == nil {
                print("No payload data found for this signing")
                return false
            } else {
                payloadVar = self.payloadDict!
            }
        } else {
            payloadVar = payload!
        }
        
        var result : Bool = false
        while(signatureTmp.count%4 != 0){
            signatureTmp += "="
        }
        let datasignature = Data.init(base64Encoded: signatureTmp.base64UrlToBase64(), options: .ignoreUnknownCharacters)
        print("DATA SIG: " , datasignature!.base64EncodedString())
        do{
            let jsonHeader = try JSONSerialization.data(withJSONObject: headerVar, options: .init(rawValue: 0))
            var headerEncoded = jsonHeader.base64EncodedString()
            headerEncoded = headerEncoded.clearPaddding().base64ToBase64Url()
            let jsonPayload = try JSONSerialization.data(withJSONObject: payloadVar, options: .init(rawValue: 0))
            var payloadEncoded = jsonPayload.base64EncodedString()
            payloadEncoded = payloadEncoded.clearPaddding().base64ToBase64Url()
            let signedData = headerEncoded + "." + payloadEncoded
            print("SIGNEDDATA : \(signedData)")
            var error: Unmanaged<CFError>?
            result = SecKeyVerifySignature(key.getKeyObject(), .rsaSignatureMessagePKCS1v15SHA256, signedData.data(using: String.Encoding.utf8)! as CFData, datasignature! as CFData, &error)
        }catch{
            print(error)
            return false
        }
        return result
    }
    
    public static func parseJWSheader(stringJWS : String) -> [String : Any]? {
        if stringJWS.count == 0 || !stringJWS.contains(".") {
            return nil
        }
        var result = [String : Any]()
        let splits = stringJWS.split(separator: ".")
        
        let payload = String(splits[0]).base64UrlToBase64().addPadding()
        let payloadData = Data(base64Encoded: payload)
        do{
            result = try JSONSerialization.jsonObject(with: payloadData!, options: .allowFragments) as! [String : Any]
        } catch {
            print(error)
        }
        
        return result
        
    }
    
    public static func parseJWSpayload(stringJWS : String) -> [String : Any]? {
        if stringJWS.count == 0 || !stringJWS.contains(".") {
            return nil
        }
        var result = [String : Any]()
        let splits = stringJWS.split(separator: ".")
        
        let payload = String(splits[1]).base64UrlToBase64().addPadding()
        let payloadData = Data(base64Encoded: payload)
        do{
            result = try JSONSerialization.jsonObject(with: payloadData!, options: .allowFragments) as! [String : Any]
        } catch {
            print(error)
        }
        
        return result
    }
    
}
