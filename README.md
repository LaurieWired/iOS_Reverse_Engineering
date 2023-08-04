# iOS_Reverse_Engingeering

## Common Entrypoints for Swift and Objective C
The following contains a table of common methods to look at when starting to Reverse Engineer and iOS application. These are different entrypoints of code that may be executed for different states of the application.

| Class              | Method (Objective-C / Swift)  | Description |
|--------------------|-------------------------------|-------------|
| `UIApplicationDelegate` | `application:didFinishLaunchingWithOptions:` / `application(_:didFinishLaunchingWithOptions:)` | Called when the application has finished launching, but before it has started running. Often used for set-up code that doesn't involve the UI. |
| `UIApplicationDelegate` | `applicationDidBecomeActive:` / `applicationDidBecomeActive(_:)` | Called when the application has become active and can start running code. |
| `SceneDelegate` | `scene:willConnectToSession:options:` / `scene(_:willConnectToSession:options:)` | Called when a new scene is being created. |
| `SceneDelegate` | `sceneDidBecomeActive:` / `sceneDidBecomeActive(_:)` | Called when the scene becomes active (the app is in the foreground and receiving events). |
| `UIViewController` | `viewDidLoad` / `viewDidLoad()` | Called after the controller's view is loaded into memory. Ideal for initial setup. |
| `UIViewController` | `viewWillAppear:` / `viewWillAppear(_:)` | Called before the view is added to the app's view hierarchy. |
