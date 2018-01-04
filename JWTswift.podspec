Pod::Spec.new do |s|

  s.name         = "JWTswift"
  s.version      = "1.0.0"
  s.summary      = "A simple swift library to help the developer using JSON Web Token in swift environment(iOS)."
  s.description  = "JWTswift is a completely independent library, which only used the basic C and Swift library for them."
  s.homepage     = "https://github.com/BLC-HTWChur/JWTswift"
  s.license      = { :type => "MIT", :file => "LICENSE" }
  s.author       = { "Julius Saputra" => "julius_saputra@hotmail.com" }
  s.platform     = :ios, "10.0"
  s.source       = { :git => "https://github.com/BLC-HTWChur/JWTswift.git", :tag => "1.0.0"}

  s.source_files  = "JWTswift/**/*"
  s.resources = "JWTswift/TestResources/*.jwks"
  #s.exclude_files = "Classes/Exclude"
  s.pod_target_xcconfig = { 'SWIFT_VERSION' => '4'}


  s.requires_arc = true
  s.xcconfig = { 'HEADER_SEARCH_PATHS' => '$(SDKROOT)/usr/include/libxml2', 'SWIFT_INCLUDE_PATHS' => '$(PODS_ROOT)/JWTswift/CommonCrypto' }
  s.preserve_paths = 'CommonCrypto/CommonCrypto.xcconfig'

end
