import Foundation
import Darwin

// MARK: - Main

print("===== MConfPoC =====")
print("Sandbox Escape Test")
print("")

// Test 1: File exists
let testPath = "/private/var/mobile/Media/iTunes_Control/iTunes/MediaLibrary.sqlitedb"
let exists = FileManager.default.fileExists(atPath: testPath)
print("[TEST] File exists: \(exists)")

// Test 2: Try to read (will fail in sandbox)
do {
    let data = try Data(contentsOf: URL(fileURLWithPath: testPath))
    print("[TEST] Read \(data.count) bytes (unexpected — sandbox escape worked?)")
} catch {
    print("[TEST] Read failed: \(error.localizedDescription)")
}

// Test 3: Save results
let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
let resultsURL = documents.appendingPathComponent("test_results.txt")
let results = "Test completed at \(Date())\nFile exists: \(exists)\n"
try? results.write(to: resultsURL, atomically: true, encoding: .utf8)
print("[TEST] Results saved to: \(resultsURL.path)")

print("===== Complete =====")
