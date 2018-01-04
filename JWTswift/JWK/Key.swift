//
//  Key.swift
//  JWTswift
//
//  Created by Blended Learning Center on 03.01.18.
//  Copyright © 2018 Blended Learning Center. All rights reserved.
//

import Foundation

public class Key {
    
    private var kid : String
    private var keyObject : SecKey
    
    public init(keyObject : SecKey , kid : String) {
        self.keyObject = keyObject
        self.kid = kid
    }
    
    public func getKid() -> String {
        return self.kid
    }
    
    public func getKeyObject() -> SecKey {
        return self.keyObject
    }

    
}
