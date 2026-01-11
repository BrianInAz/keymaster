// Keymaster - Secure TouchID access to Keychain secrets
// Enhanced version for bjzy.me vault integration
//
import Foundation
import LocalAuthentication

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

func setPassword(key: String, password: String) -> Bool {
  // Add biometric protection to the keychain item
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecValueData as String: password.data(using: .utf8) ?? Data(),
    kSecAttrAccessControl as String: createAccessControl()
  ]

  // Delete existing item first to prevent duplicates
  _ = deletePassword(key: key)
  
  let status = SecItemAdd(query as CFDictionary, nil)
  return status == errSecSuccess
}

func createAccessControl() -> SecAccessControl {
  var error: Unmanaged<CFError>?
  let access = SecAccessControlCreateWithFlags(
    nil,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    .userPresence,
    &error
  )
  return access!
}

func deletePassword(key: String) -> Bool {
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne
  ]
  let status = SecItemDelete(query as CFDictionary)
  return status == errSecSuccess
}

func getPassword(key: String) -> String? {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecReturnData as String: true
  ]
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)

  guard status == errSecSuccess,
    let passwordData = item as? Data,
    let password = String(data: passwordData, encoding: String.Encoding.utf8)
  else { return nil }

  return password
}

func readPassword() -> String {
  let password = readLine(strippingNewline: true) ?? ""
  return password
}

func usage() {
  print("keymaster [get|set|delete] [key] [secret]")
  print("  get vault-password    - Retrieve password with TouchID")
  print("  set vault-password    - Set password (reads from stdin securely)")
  print("  set vault-password pwd - Set password (legacy, less secure)")
  print("  delete vault-password - Remove password from keychain")
}

func main() {
  let inputArgs: [String] = Array(CommandLine.arguments.dropFirst())
  if (inputArgs.count < 2 || inputArgs.count > 3) {
    usage()
    exit(EXIT_FAILURE) 
  }
  
  let action = inputArgs[0]
  let key = inputArgs[1]
  var secret = ""
  
  // Enhanced security: read password from stdin for 'set' operation
  if (action == "set") {
    if inputArgs.count == 3 {
      // Legacy mode: password as argument (less secure)
      fputs("Warning: Password passed as argument is visible in process list\n", stderr)
      secret = inputArgs[2]
    } else {
      // Secure mode: read from stdin
      fputs("Enter password (will not echo):\n", stderr)
      secret = readPassword()
    }
  }

  let context = LAContext()
  context.touchIDAuthenticationAllowableReuseDuration = 0

  var error: NSError?
  guard context.canEvaluatePolicy(policy, error: &error) else {
    print("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics")
    exit(EXIT_FAILURE)
  }

  if (action == "set") {
    context.evaluatePolicy(policy, localizedReason: "set to your password") { success, error in
      guard setPassword(key: key, password: secret) else {
        print("Error setting password")
        exit(EXIT_FAILURE)
      }
      print("Key \(key) has been sucessfully set in the keychain")
      exit(EXIT_SUCCESS)
    }
    dispatchMain()
  }

  if (action == "get") {
    context.evaluatePolicy(policy, localizedReason: "access to your password") { success, error in
      if success && error == nil {
        guard let password = getPassword(key: key) else {
          print("Error getting password")
          exit(EXIT_FAILURE)
        }
        print(password)
        exit(EXIT_SUCCESS)
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }

  if (action == "delete") {
    context.evaluatePolicy(policy, localizedReason: "delete your password") { success, error in
      if success && error == nil {
        guard deletePassword(key: key) else {
          print("Error deleting password")
          exit(EXIT_FAILURE)
        }
        print("Key \(key) has been sucessfully deleted from the keychain")
        exit(EXIT_SUCCESS)
      } else {
        let errorDescription = error?.localizedDescription ?? "Unknown error"
        print("Error \(errorDescription)")
        exit(EXIT_FAILURE)
      }
    }
    dispatchMain()
  }
}

main()
