//
//  RSA-OAEP.swift
//  JWTswift
//
//  Created by Blended Learning Center on 01.10.18.
//  Copyright © 2018 Blended Learning Center. All rights reserved.
//

import Foundation

internal struct RSA_OAEP_256 {
    
    
    static func encrypt(encryptKey : Key, cek : [UInt8]) -> Data? {
        guard SecKeyIsAlgorithmSupported(encryptKey.getKeyObject(), .encrypt, .rsaEncryptionOAEPSHA256) else {
            
            print("Key doesn't support the encryption algorithm")
            return nil
            
        }
        
        print("block size = \(SecKeyGetBlockSize(encryptKey.getKeyObject()))")
        
        // Transform CEK into Data format
        let cekData = Data(bytes: cek)
        print("cekData count = \(cekData.count)")
        guard cekData.count < (SecKeyGetBlockSize(encryptKey.getKeyObject()) - 130) else {
            print("Cek is too big")
            return nil
        }
        
        var error : Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(encryptKey.getKeyObject(), .rsaEncryptionOAEPSHA256, cekData as CFData, &error) as Data? else {
            print(error!.takeRetainedValue())
            return nil
        }
        print("Cipher Text = \([UInt8](cipherText).count)")
        
        return cipherText
    }
    
    
    static func decrypt(decryptKey: Key, cipherText: Data) -> Data? {
        guard SecKeyIsAlgorithmSupported(decryptKey.getKeyObject(), .decrypt, .rsaEncryptionOAEPSHA256) else {
            print("Key doesn't support the decryption algorithm.")
            return nil
        }
        
        print("CipherData count = \(cipherText.count)")
        
        guard cipherText.count == (SecKeyGetBlockSize(decryptKey.getKeyObject())) else {
            print("Cek is too big")
            return nil
        }
        
        var error: Unmanaged<CFError>?
        guard let plainData = SecKeyCreateDecryptedData(decryptKey.getKeyObject(), .rsaEncryptionOAEPSHA256, cipherText as CFData, &error) else {
            print(error!.takeRetainedValue())
            return nil
        }
        
        return plainData as Data
    }
    
}
