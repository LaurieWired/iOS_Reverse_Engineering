# iOS Reverse Engingeering Reference

## Info.plist
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


## Common Entrypoints for Swift and Objective C Code

The following contains a table of common methods to look at when starting to Reverse Engineer and iOS application. These are different entrypoints of code that may be executed for different states of the application.

| Class              | Method (Objective-C / Swift)  | Description |
|--------------------|-------------------------------|-------------|
| `UIApplicationDelegate` | `application:didFinishLaunchingWithOptions:` / `application(_:didFinishLaunchingWithOptions:)` | Called when the application has finished launching, but before it has started running. Often used for set-up code that doesn't involve the UI. |
| `UIApplicationDelegate` | `applicationDidBecomeActive:` / `applicationDidBecomeActive(_:)` | Called when the application has become active and can start running code. |
| `SceneDelegate` | `scene:willConnectToSession:options:` / `scene(_:willConnectToSession:options:)` | Called when a new scene is being created. |
| `SceneDelegate` | `sceneDidBecomeActive:` / `sceneDidBecomeActive(_:)` | Called when the scene becomes active (the app is in the foreground and receiving events). |
| `UIViewController` | `viewDidLoad` / `viewDidLoad()` | Called after the controller's view is loaded into memory. Ideal for initial setup. |
| `UIViewController` | `viewWillAppear:` / `viewWillAppear(_:)` | Called before the view is added to the app's view hierarchy. |
