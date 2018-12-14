# Keycard Java SDK for Android and Desktop

This SDK simplifies integration with the [Status Keycard](https://github.com/status-im/status-keycard) in Android
and Desktop applications. In this SDK you find both the classes needed for generic communication with SmartCards as well 
as classes specifically addressing the Keycard.

To get started, check the file ```demo-android/src/main/java/im/status/keycard/app/MainActivity.java``` which a simple
demo application showing how the SDK works and what you can do with it.

## Usage

You can import the SDK in your Gradle or Maven project using [Jitpack.io](https://jitpack.io).

### On Android

```groovy
dependencies {
  implementation 'com.github.status-im.status-keycard-java:android:2.0.0'
}
```

### on the desktop

```groovy
dependencies {
  implementation 'com.github.status-im.status-keycard-java:desktop:2.0.0'
}
```