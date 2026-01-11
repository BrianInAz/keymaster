// Keymaster - Simple TouchID access to Keychain secrets
// Based on original working version
//
import Foundation
import LocalAuthentication

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

func setPassword(key: String, password: String) -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecValueData as String: password.data(using: .utf8) ?? Data()
  ]

  // Delete existing item first to prevent duplicates
  _ = deletePassword(key: key)
  
  let status = SecItemAdd(query as CFDictionary, nil)
  return status == errSecSuccess
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

  return password.trimmingCharacters(in: .whitespacesAndNewlines)
}

func readPassword() -> String {
  let password = readLine(strippingNewline: true) ?? ""
  return password.trimmingCharacters(in: .whitespacesAndNewlines)
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
  
  // Read password from stdin for 'set' operation
  if (action == "set") {
    if inputArgs.count == 3 {
      // Legacy mode: password as argument
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
    context.evaluatePolicy(policy, localizedReason: "Keymaster: store vault password") { success, error in
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
    context.evaluatePolicy(policy, localizedReason: "Keymaster: unlock vault password") { success, error in
      if success && error == nil {
        guard let password = getPassword(key: key) else {
          print("Error getting password")
          exit(EXIT_FAILURE)
        }
        print(password, terminator: "")
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
    context.evaluatePolicy(policy, localizedReason: "Keymaster: delete vault password") { success, error in
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
