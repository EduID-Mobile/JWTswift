//
//  Key.swift
//  JWTswift
//
//  Created by Blended Learning Center on 03.01.18.
//  Copyright © 2018 Blended Learning Center. All rights reserved.
//

import Foundation

class Key {
    
    private var kid : String
    private var keyObject : SecKey
    
    init(keyObject : SecKey , kid : String) {
        self.keyObject = keyObject
        self.kid = kid
    }
    
    func getKid() -> String {
        return self.kid
    }
    
    func getKeyObject() -> SecKey {
        return self.keyObject
    }

    
}
