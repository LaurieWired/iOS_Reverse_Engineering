# Repository Overview
This repository is a reference for getting started with iOS Reverse Engineering! It contains all the information you need to start taking apart IPA files including:
- Scripts for helping your iOS Reverse Engineering in Ghidra
- Example iOS IPA files demonstrating different forms of obfuscation
- A guide for getting started with iOS Reverse Engineering

I will continue adding more information to speed up your Reverse Engineering process!

# Example IPA Files
Each IPA file is created to help you with your static analysis. Use the section below to learn how to extract the executable components and learn their inner workings.

- [Swizzling IPA](https://github.com/LaurieWired/iOS_Reverse_Engingeering/blob/main/ObfuscatedAppExamples/ObjectiveSwizzling.ipa) - This file contains an example iOS application written in Objective-C that demostrates swizzling to replace one method's implementation with another.
- [No Tampering IPA](https://github.com/LaurieWired/iOS_Reverse_Engingeering/blob/main/ObfuscatedAppExamples/NoTampering.ipa) - This file contains an example iOS application written in Swift that uses the [IOSSecuritySuite](https://github.com/securing/IOSSecuritySuite) to avoid printing the true value to the screen if it discovers any potential tampering, debugging, or emulator use.
- [Control Flow Flattening IPA](https://github.com/LaurieWired/iOS_Reverse_Engingeering/blob/main/ObfuscatedAppExamples/ControlFlowFlattening.ipa) - This file contains an example iOS application written in Swift that implements the same method without control flow flattening, with flattening, and with a more complex flattening example.

# Ghidra Scripts
This repo contains scripts for helping your iOS Reverse Engineering including:
- [Swift Name Demangler](https://github.com/LaurieWired/iOS_Reverse_Engingeering/blob/main/SwiftNameDemangler.py) - This traverses your Swift binary and demangles methods and labels. It sets each of the new names and leaves a comment with the original and demangled name above the method and label.
- [Swizzling Detector](https://github.com/LaurieWired/iOS_Reverse_Engingeering/blob/main/SwizzlingDetector.py) - This script searches your Objective-C binary to detect references to potential Swizzling calls. It prints the function name and all potential references in the code.

## Running the Scripts
In order to run the scripts in this repo, you can add them as new scripts for Ghidra. Either manually place them in the `ghidra_scripts` folder or add them through the Ghidra GUI. Here are the steps for both options:

### Option 1: Pasting the Script into `ghidra_scripts` Folder

1. **Locate the `ghidra_scripts` Folder**:
   - By default, Ghidra has a directory named `ghidra_scripts` in your user's home directory or within the Ghidra installation directory.
   
2. **Add the Scripts**:
   - Copy or paste the scripts into the `ghidra_scripts` folder.

3. **Refresh the Script Manager in Ghidra**:
   - If Ghidra is already open, refresh the Script Manager (`Window` -> `Script Manager`).
   - Click the "Refresh Script List" icon.

4. **Run the Script**:
   - The scripts should now appear in the Script Manager.
   - Highlight the script and click the green "Run" button. Make sure you have the appropriate binary opened in Ghidra.

### Option 2: Using the Ghidra GUI

1. **Open the Script Manager**:
   - Navigate to `Window` -> `Script Manager` in Ghidra.

2. **Determine Script Directory**:
   - In the Script Manager, there's an icon with three dots. Click it to see the script directories.

3. **Use the "New Script" Option**:
   - In the Script Manager, click on the "New Script" icon.
   - This will open a dialog where you can write or paste your script and save it.

4. **Run the Script**:
   - After saving, the script will appear in the Script Manager.
   - Highlight the script and click the green "Run" button. Make sure you have the appropriate program or binary opened in Ghidra.


## Installing Swift

# Getting Started Reversing iOS IPA Files

## Application Entrypoint
Find the entrypoint in the Info.plist

A plist (property list) file is a structured data representation used by macOS and iOS. It is often for storing user settings and information about bundles and applications and can be in XML or binary format. Reading an XML plist is as simple as throwing the file in a text editor, but reading a binary plist requires decoding to convert to a human-readable format.

### Reading a Binary Property List
Opening a plist file on Mac is as simple as double-clicking the file. By default, Mac will decode the file to a human-readable format. If not working on Mac, however, the following Python code decodes the binary plist and prints it as a JSON string to the console:

```
import plistlib
import json

with open('Info.plist', 'rb') as fp:
    pl = plistlib.load(fp)

print(json.dumps(pl, indent=4))
```

### Finding the Executable in the Info.plist
Once, you have opened the plist text, the main executable will be found under the "CFBundleExecutable" tag.

![ios_plist_exe](https://github.com/LaurieWired/iOS_Reverse_Engingeering/assets/123765654/174576ba-f371-45c3-965e-68cb045c4554)

This string will name a Mach-O binary inside of the application bundle that will be the main entrypoint of the application.

![macho_exe](https://github.com/LaurieWired/iOS_Reverse_Engingeering/assets/123765654/3033cc64-f318-4756-afe6-0aafe8268f02)

Find an acompanying video to help you take apart an IPA file at [YouTube - Finding the Entrypoint of iOS Apps in Ghidra](https://www.youtube.com/watch?v=mLDsIMXafP4)

## Entitlements

Payload/MyApp.app/embedded.mobileprovision

The entitlements can be found under the <key>Entitlements</key> section.

Generally for system capabilities. App capabilities will be in the Info.plist

## Finding Strings
lproj directories contain localized strings

Supports different languages per lproj directory. For example, if you're searching for the strings in English, maneuver to the ```en.lproj``` directory and open the ```Localizable.strings``` file. This file is encoded, but corresponds to key-value pairs.

### Decoding Via plutil
```
plutil -p Payload/MyApp.app/en.lproj/Localizable.strings
```

### Decoding Via Python

```
Insert python
```

## Reverse Engineering iOS Code

### iOS Programming Languages

Most newer iOS binaries will be written in Swift, but many legacy applications will still be written in Objective-C. Swift is designed to be interoperable with Objective-C. This means that Swift code can call Objective-C code and vice-versa. There may also be many references to the Objective-C runtime or libraries inside of Swift binaries, so it is important to be able to understand both. 

To determine if a binary is written in Swift, check the Mach-O sections and see if there is a ```__swift5_``` section in the TEXT segment. This indicates the presence of Swift code. The Program Tree in Ghidra can be used to view the segments and sections of the binary.

![ghidra_swift_section](https://github.com/LaurieWired/iOS_Reverse_Engingeering/assets/123765654/3e1b01ec-537a-4fd5-a38b-cff7fcd3c017)






### Dynamic Method Resolution
Selectors

Objective-C runtime reference: https://developer.apple.com/documentation/objectivec

### Name Mangling
Fixing swift mangled names

```
swift-demangle
```

Class names and method names are mangled into one identifer.
https://ronyfadel.github.io/swiftdemangler/


### Locating Libraries
Dylibs and frameworks

Insert screenshot of ghidra showing referenced libraries

### Common Entrypoints for Swift and Objective C Code

The following contains a table of common methods to look at when starting to Reverse Engineer and iOS application. These are different entrypoints of code that may be executed for different states of the application.

| Class              | Method (Objective-C / Swift)  | Description |
|--------------------|-------------------------------|-------------|
| `UIApplicationDelegate` | `application:didFinishLaunchingWithOptions:` / `application(_:didFinishLaunchingWithOptions:)` | Called when the application has finished launching, but before it has started running. Often used for set-up code that doesn't involve the UI. |
| `UIApplicationDelegate` | `applicationDidBecomeActive:` / `applicationDidBecomeActive(_:)` | Called when the application has become active and can start running code. |
| `SceneDelegate` | `scene:willConnectToSession:options:` / `scene(_:willConnectToSession:options:)` | Called when a new scene is being created. |
| `SceneDelegate` | `sceneDidBecomeActive:` / `sceneDidBecomeActive(_:)` | Called when the scene becomes active (the app is in the foreground and receiving events). |
| `UIViewController` | `viewDidLoad` / `viewDidLoad()` | Called after the controller's view is loaded into memory. Ideal for initial setup. |
| `UIViewController` | `viewWillAppear:` / `viewWillAppear(_:)` | Called before the view is added to the app's view hierarchy. |


