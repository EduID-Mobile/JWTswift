//
//  CryptoManager.swift
//  eduid-iOS
//
//  Created by Blended Learning Center on 06.12.17.
//  Copyright © 2017 Blended Learning Center. All rights reserved.
//

import Foundation

public class CryptoManager {
    
    public static func encryptData (key: Key ,algorithm : SecKeyAlgorithm, plainData : NSData) -> NSData? {
        let canEncrypt = SecKeyIsAlgorithmSupported(key.getKeyObject(), SecKeyOperationType.encrypt, algorithm)
        print("plaindata length : \(plainData.length)")
        print("keysize : \(SecKeyGetBlockSize(key.getKeyObject()))")
        //check if the data empty and if the algorithm is supported for the key, return nil if not
        //the data length itself restricted and must be 130 bytes smaller than key size
        if( plainData.length <= 0 || !canEncrypt ||
            plainData.length > SecKeyGetBlockSize(key.getKeyObject()) - 130){
            return nil
        }
        var cipherText : NSData? = nil
        var error: Unmanaged<CFError>?
        
        cipherText = SecKeyCreateEncryptedData(key.getKeyObject(), algorithm, plainData as CFData, &error)
        if let errormsg = error?.takeRetainedValue(){
            print(errormsg)
        }
        
        return cipherText
    }
    
    public static func decryptData (key: Key , algorithm : SecKeyAlgorithm, cipherData : NSData) -> NSData? {
        
        let canDecrypt = SecKeyIsAlgorithmSupported(key.getKeyObject(), .decrypt, algorithm)
        
        if( cipherData.length <= 0 || !canDecrypt ||
            cipherData.length != SecKeyGetBlockSize(key.getKeyObject())){
            return nil
        }
        
        var decrpytedData : NSData? = nil
        var error : Unmanaged<CFError>?
        
        decrpytedData = SecKeyCreateDecryptedData(key.getKeyObject(), algorithm, cipherData as CFData, &error)
        if let errormsg = error?.takeRetainedValue(){
            print(errormsg)
        }
        return decrpytedData
    }
    
}
