//
//  RSA1_5.swift
//  JWTswift
//
//  Created by Blended Learning Center on 24.09.18.
//  Copyright © 2018 Blended Learning Center. All rights reserved.
//

import Foundation

internal struct RSA1_5{
    
    static func encrypt(encryptKey : Key, cek: [UInt8]) -> Data? {
        //.rsaEncryptionPKCS1
        guard SecKeyIsAlgorithmSupported(encryptKey.getKeyObject(), .encrypt, .rsaEncryptionPKCS1) else {
            print("Key doesn't support the encryption algorithm.")
            return nil
        }
        print("block size = " , SecKeyGetBlockSize(encryptKey.getKeyObject()))
        
        
        // Transform CEK into Data format
        let cekData = Data(bytes: cek)
        print("cekData count = " ,cekData.count)
        guard cekData.count < (SecKeyGetBlockSize(encryptKey.getKeyObject())-130) else {
            print("Cek is too big")
            return nil
        }
        
        
        var error: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(encryptKey.getKeyObject(), .rsaEncryptionPKCS1, cekData as CFData, &error) as Data? else {
            print(error!.takeRetainedValue())
            return nil
        }
        print("Cipher Text = " ,[UInt8](cipherText).count)
        
        return cipherText
    }
    
    static func decrypt(decryptKey: Key, cipherText: Data) -> Data? {
        //rsaEncryptionPKCS1
        guard SecKeyIsAlgorithmSupported(decryptKey.getKeyObject(), .decrypt, .rsaEncryptionPKCS1) else {
            print("Key doesn't support the decryption algoritm.")
            return nil
        }
        
        print("CipherData count = \(cipherText.count)")
        guard cipherText.count == (SecKeyGetBlockSize(decryptKey.getKeyObject())) else {
            print("Cek is too big")
            return nil
        }
        
        var error : Unmanaged<CFError>?
        guard let plainData = SecKeyCreateDecryptedData(decryptKey.getKeyObject(), .rsaEncryptionPKCS1, cipherText as CFData, &error) else {
            print(error!.takeRetainedValue())
            return nil
        }
        
        return plainData as Data
        
    }
    
}
