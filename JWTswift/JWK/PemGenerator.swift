//
//  PemGenerator.swift
//  eduid-iOS
//
//  Created by Blended Learning Center on 12.12.17.
//  Copyright © 2017 Blended Learning Center. All rights reserved.
//

import Foundation

class PemGenerator {
    
    private var modulusHex : String
    private var exponentHex : String
    private var lengthModulus : Int
    private var lengthExponent : Int
    
    
    init(modulusHex: String, exponentHex: String, lengthModulus : Int, lengthExponent: Int) {
        self.modulusHex = modulusHex
        self.exponentHex = exponentHex
        self.lengthModulus = lengthModulus
        self.lengthExponent = lengthExponent
    }
    
    private func integerMaker(byteLength: inout Int , value : inout String) -> String{
        var header = "02"
        var length : String?
        let first = String.init(describing: value.first!)
        
        
        let intValue = Int(first, radix:16)!
        if(intValue > 7){
            byteLength = byteLength + 1
            value = "00" + value
        }
        
        print("INTVALUE \(first)")
        //        var lengthHeader : String?
        
        if byteLength < 128 {
            length = String(format: "%2X", byteLength)
            length = length?.replacingOccurrences(of: " ", with: "")
            if length?.count == 1 {
                length = "0" + length!
            }
            
        }else{
            var i = 1
            
            while( byteLength > Int(truncating: NSDecimalNumber(decimal: pow(256, i)))-1 ) {
                i = i + 1
            } //this just work to the length 256^15, need to optimize it for the bigger data
            var byteInString = String(format: "%2X", byteLength)
            if byteInString.count % 2 != 0{
                byteInString = "0" + byteInString
            }
            length = "8" + String(format: "%X", i) + byteInString
            
        }
        header += length!
        print("HEADER : \(header)")
        
        return header + value
    }
    
    private func sequenceMaker(byteLength : Int, elements : [String]) -> String {
        var header = "30"
        var length : String?
        
        if byteLength < 128 {
            length = String(format: "%2X" , byteLength)
            length = length?.replacingOccurrences(of: " ", with: "")
            if length?.count == 1{
                length = "0" + length!
            }
        } else {
            var i = 1
            while (byteLength > Int(truncating: NSDecimalNumber(decimal: pow(256, i)))-1 ){
                i = i + 1
            } //this just work to the length 256^15 TODO
            var byteInString = String(format: "%2X", byteLength)
            if byteInString.count%2 != 0{
                byteInString = "0" + byteInString
            }
            length = "8" + String(format: "%X", i) + byteInString
        }
        header += length!
        for element in elements{
            header += element
        }
        return header
    }
    
    func modulusInteger(length: Int) -> String {
        var byteCount = length
        return integerMaker(byteLength: &byteCount, value: &self.modulusHex)
    }
    
    func exponentInteger(length: Int) -> String{
        var byteCount = length
        return integerMaker(byteLength: &byteCount, value: &self.exponentHex)
    }
    
    func generateBitString(byteLength: Int , elements : [String]) ->String {
        var header = "03"
        var length : String?
        let tmpLength = byteLength + 1 // for the unused bit
        if tmpLength < 128 { //1 for unsusedbit
            length = String(format: "%2X" , tmpLength) //+1 for unused bits octet
            length = length?.replacingOccurrences(of: " ", with: "")
            if length?.count == 1{
                length = "0" + length!
            }
        } else {
            var i = 1
            while (tmpLength > Int(truncating: NSDecimalNumber(decimal: pow(256, i)))-1 ){
                i = i + 1
            } //this just work to the length 256^15 TODO
            var byteInString = String(format: "%2X", tmpLength)
            if byteInString.count%2 != 0{
                byteInString = "0" + byteInString
            }
            length = "8" + String(format: "%X", i) + byteInString + "00" //unused bits 00
        }
        header += length!
        for element in elements{
            header += element
        }
        return header
    }
    
    private func generateNull() -> String{
        return "0500"
    }
    
    private func rsaObjectIdentifier() -> String {
        //1.2.840.113549.1.1.1
        _ = "06"
        
        return "06092A864886F70D010101"
    }
    
    public func generatePublicPem() -> String{
        var result : String?
        let modulusInt = modulusInteger(length: self.lengthModulus)
        let exponentInt = exponentInteger(length: self.lengthExponent)
        let sequenceKeyLength = modulusInt.count/2 + exponentInt.count/2
        let sequenceKey = sequenceMaker(byteLength: sequenceKeyLength, elements: [modulusInt, exponentInt])
        print("MODULUS INT : \(modulusInt)")
        print("EXPONENT INT: \(exponentInt)")
        print("SEQUENCE KEY : \(sequenceKey)")
        print("with sequence length : \(sequenceKey.count/2)")
        let bitString = generateBitString(byteLength: sequenceKey.count/2, elements: [sequenceKey])
        print("BIT STRING \(bitString)")
        let rsaID = rsaObjectIdentifier()
        let null = generateNull()
        let seqAlgoIDlength = rsaID.count/2 + null.count/2
        let sequenceAlgorithmID = sequenceMaker(byteLength: seqAlgoIDlength, elements: [rsaID, null])
        
        
        let algoIDlength = sequenceAlgorithmID.count/2
        let bitStringlength = bitString.count/2
        result = sequenceMaker(byteLength: algoIDlength+bitStringlength, elements: [sequenceAlgorithmID, bitString])
        //PKCS#8 as result
        
        print("PEM HEX: \(result!)" )
        result = result?.hexToBase64().base64EncodedString()
//        result = RSApublicHeaderFooter(key: result!)
        print("PEM : \n\(result!)")
        return result!
    }
    
    func RSApublicHeaderFooter(key: String) -> String{
        let counter : Int = key.count / 64
        var result = key
        
        for i in 1...counter {
    
            if i == 1 {
                let index = result.index(result.startIndex, offsetBy: (64*i))
                result.insert(contentsOf: "\r\n", at: index)
                print(index.encodedOffset)
            } else {
                let index = result.index(result.startIndex, offsetBy: ((64*i) + ((i-1)*2)) - (i-1))
                result.insert(contentsOf: "\r\n", at: index)
                print(index.encodedOffset)
            }
        }
        result = "-----BEGIN PUBLIC KEY-----\r\n" + result + "\r\n-----END PUBLIC KEY-----"
        return result
    }
    
}
