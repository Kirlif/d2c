## Install

### Linux

The following are the installation and configuration steps in the ubuntu 18.04 environment. If some links have already been configured, such as JDK, you can skip it.

-   Clone the repo

```
git clone https://github.com/ratsan/dex2c.git
```

-   Install required dependencies
-   Check the latest version of apktool in bitbucket

```
cd dex2c
pip3 install -r requirements.txt
wget -O tools/apktool.jar https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar
```

-   Install and configure Android development environment (NDK r17+, SDK)

```
export PATH="/path/to/Android/Sdk/ndk/version:$PATH"
```

-   Install JDK

```
sudo apt-get install openjdk-11-jdk
```

### Windows

-   Install Python3
-   Install project dependencies same way as in linux
-   Download apktool latest version, rename it to apktool.jar and put it in dex2c/tools directory

```
cd dex2c
pip3 install -r requirements.txt
```

-   Install NDK (r17+), change ndk_dir in dex2c.cfg to NDK installation directory
-   Install JRE or JDK, add java to PATH in environment variables

## How to Use

### 1. Load Native Library

First, add and load the library code at the appropriate location of the app code, such as the static code block of Application or onCreate, and rebuild your apk file.

```
try {
     // Add library name without 'lib' part from start
     // Default is 'stub'
     System.loadLibrary("library_name");
} catch (UnsatisfiedLinkError e) {
     e.printStackTrace();
}
```

### 2. Filter

#### Use black and white lists

dex2c supports the use of black and white lists to filter functions that need to be compiled or prohibited from being compiled. Modify filter.txt, use regular expressions to configure the functions that need to be processed. By default, compile Activity.onCreate, and test all functions in the demo.

#### Using Annotations

Add Dex2C annotation class in your project.

```
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy. RUNTIME)
public @interface Dex2C {}
```

Then use Dex2C annotation to mark the class or method that needs to be compiled. If you're using Proguard, R8 etc tools then don't forget to add rules to keep the annotations.

### 3. Reinforce APP

Use the following command to strengthen your app

```
python3 dex2c.py input.apk -o output.apk
```

This command will generate two files 'output/protected.apk' and 'output/project-source.zip'. Among them, 'protected.apk' has been reinforced, which can be installed directly. 'project-source.zip' is a jni project, which contains the cpp code generated by dex2c. After decompression, it can be compiled directly with ndk.

## Notice

-   This is author's personal research project, it has not been tested extensively, please use it carefully for online projects!
-   The compiled CPP code uses JNI to interact with the Java virtual machine, which may have a very serious impact on performance, please choose the hardened function carefully!

## Reference resources

-   [DAD](https://github.com/androguard/androguard/tree/master/androguard/decompiler/dad)
