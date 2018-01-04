//
//  KeyChain.swift
//  eduid-iOS
//
//  Created by Blended Learning Center on 05.12.17.
//  Copyright © 2017 Blended Learning Center. All rights reserved.
//

import Foundation

public class KeyChain {

    /**
     Saving a specific key into the keychain.
     - parameter tagString: unique identifier for the Key to simplify the retrieving process.
     - parameter key: key data which want to be saved in to the keychain
     - returns:  Status from the saving process, true if successful, false if there any error
     */
    public static func saveKey(tagString: String, key: SecKey) -> Bool{
        let tag = tagString.data(using: .utf8)
        
        //check if key is already on the keychain, return false if yes
        if loadKey(tagString: tagString) == key {
            return false
        }
        
        let saveQuery = [
            kSecClass as String : kSecClassKey as String,
            kSecAttrApplicationTag as String : tag!,
            kSecValueRef as String : key

        ] as [String : AnyObject]
        
        let status = SecItemAdd(saveQuery as CFDictionary, nil)
        if status == noErr {
            return true
        } else {
            print("ATRRIBUTE :\(status == errSecParam)")
            print("error \(status.description)")
            return false
        }
    }
    
    public static func saveKid(tagString : String , kid : String) -> Bool{
//        let tag = tagString.data(using: .utf8)
        let encodedKid = Data(base64Encoded: kid.addPadding())
        
        // Check if item is already on the keychain, return false if yes
        if loadKid(tagString: tagString) == kid {
            return false
        }
        
        let saveQuery : [String : AnyObject ] = [
            kSecClass as String : kSecClassGenericPassword ,
            kSecAttrService as String : tagString as AnyObject,
            kSecValueData as String : encodedKid as AnyObject
        ]
        
        
        let status = SecItemAdd(saveQuery as CFDictionary, nil)
        guard status == noErr else {
            print("FAILED STATUS : \(status)")
            return false
        }
        return true
    }
    
    /**
     Load a specific key from the keychain.
     - parameter tagString: unique identifier for the Key to simplify the retrieving process
     - returns : A SecKey object from the keychain , if there isn't any key found then return nil
     */
    public static func loadKey(tagString : String) -> SecKey? {
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
    
    public static func loadKid(tagString : String) -> String? {
//        let tag = tagString.data(using: .utf8)
        let getQuery : [String : AnyObject] = [
            kSecClass as String : kSecClassGenericPassword,
            kSecAttrService as String : tagString as AnyObject,
            
            kSecMatchLimit as String : kSecMatchLimitOne,
            kSecReturnAttributes as String : kCFBooleanFalse,
            kSecReturnData as String : kCFBooleanTrue
        ]
        var loadedKid : AnyObject?
        
        let status : OSStatus = withUnsafeMutablePointer(to: &loadedKid) {
            SecItemCopyMatching(getQuery as CFDictionary, UnsafeMutablePointer($0))
        }
//            SecItemCopyMatching(getQuery as CFDictionary, &loadedKid)
        
        if status == noErr {
            print(loadedKid.debugDescription)
            let dataKid = loadedKid as! Data
            return dataKid.base64EncodedString().clearPaddding()
        } else{
            print(status.description)
            return nil
        }
        
    }
    
    /**
     Delete a specific key from the keychain.
     - parameter tagString: unique identifier for the Key to simplify the retrieving process.
     - returns:  Status from the deleting process, true if successful, false if there any error
    */
    public static func deleteKey(tagString : String) -> Bool {
        
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
    
    public static func deleteKID(tagString: String) -> Bool {
        let deleteQuery : [String : Any] = [
            kSecClass as String : kSecClassGenericPassword,
            kSecAttrService as String : tagString as Any
        ]
        
        let status = SecItemDelete(deleteQuery as CFDictionary)
        if status == noErr{
            return true
        } else {
            print(status)
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
