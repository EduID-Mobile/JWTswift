//
//  CryptoManager.swift
//  eduid-iOS
//
//  Created by Blended Learning Center on 06.12.17.
//  Copyright © 2017 Blended Learning Center. All rights reserved.
//

import Foundation

class CryptoManager {
    
    static func encryptData (key: SecKey ,algorithm : SecKeyAlgorithm, plainData : NSData) -> NSData? {
        let canEncrypt = SecKeyIsAlgorithmSupported(key, SecKeyOperationType.encrypt, algorithm)
        print("plaindata length : \(plainData.length)")
        print("keysize : \(SecKeyGetBlockSize(key))")
        //check if the data empty and if the algorithm is supported for the key, return nil if not
        //the data length itself restricted and must be 130 bytes smaller than key size
        if( plainData.length <= 0 || !canEncrypt ||
            plainData.length > SecKeyGetBlockSize(key) - 130){
            return nil
        }
        var cipherText : NSData? = nil
        var error: Unmanaged<CFError>?
        
        cipherText = SecKeyCreateEncryptedData(key, algorithm, plainData as CFData, &error)
        if let errormsg = error?.takeRetainedValue(){
            print(errormsg)
        }
        
        
        return cipherText
    }
    
    static func decryptData (key: SecKey , algorithm : SecKeyAlgorithm, cipherData : NSData) -> NSData? {
        
        let canDecrypt = SecKeyIsAlgorithmSupported(key, .decrypt, algorithm)
        
        if( cipherData.length <= 0 || !canDecrypt ||
            cipherData.length != SecKeyGetBlockSize(key)){
            return nil
        }
        
        var decrpytedData : NSData? = nil
        var error : Unmanaged<CFError>?
        
        decrpytedData = SecKeyCreateDecryptedData(key, algorithm, cipherData as CFData, &error)
        if let errormsg = error?.takeRetainedValue(){
            print(errormsg)
        }
        return decrpytedData
    }
    
    
    
}
