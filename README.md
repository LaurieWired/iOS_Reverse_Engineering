# iOS Reverse Engingeering Reference

# Static Analysis

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

# Dynamic Analysis

Link to Frida scripts
