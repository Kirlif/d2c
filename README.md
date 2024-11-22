<div align="center">
  <h1 align="center">𝐃𝐞𝐱𝟐𝐂</h1>  
  <p align="center">
    Method-based AOT compiler that can wrap Dalvik bytecode with JNI native code.
  </p>
</div>

### Requierements
1. Python3
2. lxml python package.
   ```bash
   pip3 install -U --user 'lxml>=4.3.0'
   ```
3. JRE/JDK
3. Android NDK

### Installation
   ```bash
   git clone https://github.com/Kirlif/d2c
   ```
- configure dcc.cfg with your NDK path

### Major updates
- changed <a href="https://apktool.org/">Apktool</a> for <a href="https://github.com/REAndroid/APKEditor">APKEditor</a>
- cleaned androguard from useless parts and removed dependencies
- DEX file support: creates a ZIP archive of the built libraries and dex file
- skip constructors by default
- the application class is the loader ; if not defined or absent from dex, the custom loader is used
- --allow-init option: do not skip constructors
- --lib-name option: edit the library name, default: stub
- --output default value is « output.apk » for an APK else « output.zip » for a DEX
- --input only is required 
- all options can be configured in dcc.cfg ; options passed to the command line have priority
- adjust APP_PLATFORM automatically
