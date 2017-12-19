//
//  KeyChain.swift
//  eduid-iOS
//
//  Created by Blended Learning Center on 05.12.17.
//  Copyright © 2017 Blended Learning Center. All rights reserved.
//

import Foundation

class KeyChain {
    /**
     Saving a specific key into the keychain.
     - parameter tagString: unique identity for the Key to simplify the retrieving progress.
     - parameter key: key data which want to be saved in to the keychain
     - returns:  Status from the saving process
     */
    static func saveKey(tagString: String, key: SecKey) -> OSStatus{
        let tag = tagString.data(using: .utf8)
        let saveQuery = [
            kSecClass as String : kSecClassKey as String,
            kSecAttrApplicationTag as String : tag!,
            kSecValueRef as String : key,
        ] as [String : Any]
        // delete the old key if it does exist
        let stats = deleteKey(tagString: tagString)
        print("DELETE STATUS ON SAVING : " , stats.description)
        return SecItemAdd(saveQuery as CFDictionary, nil)
    }
    
    static func loadKey(tagString : String) -> SecKey? {
        let tag = tagString.data(using: .utf8)
        let getQuery = [
            kSecClass as String : kSecClassKey,
            kSecAttrApplicationTag as String : tag!,
            kSecReturnRef as String : true,
            kSecAttrKeyType as String : kSecAttrKeyTypeRSA
        ] as [String : Any]
        
        var loadedKey : CFTypeRef?
        let status : OSStatus = SecItemCopyMatching(getQuery as CFDictionary, &loadedKey)
        
        if status == noErr {
            return (loadedKey as! SecKey)
        } else {
            print(status.description)
            return nil
        }
    }
    
    static func deleteKey(tagString : String) -> Bool {
        
        let tag = tagString.data(using: .utf8)
        let getQuery : [String : Any] = [
            kSecClass as String : kSecClassKey,
            kSecAttrApplicationTag as String : tag!,
            kSecAttrKeyType as String : kSecAttrKeyTypeRSA
        ]
        
        let status = SecItemDelete(getQuery as CFDictionary)
        
        if status == noErr {
            return true
        } else {
            return false
        }
    }
    
    class func createUniqueID() -> String {
        let uuid : CFUUID = CFUUIDCreate(nil)
        let cfStr : CFString = CFUUIDCreateString(nil, uuid)
        
        let swiftString : String = cfStr as String
        return swiftString
    }
    
}
