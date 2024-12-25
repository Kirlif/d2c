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
   on Termux:
      ```bash
   pkg install libxml2 libxslt
   CFLAGS="-O0" pip install -U lxml
   ```
3. JRE/JDK
4. Android NDK

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

### Settings

|  Cli  |  Config  |  Default  |
| ----- | -------- |  -------- |
|-i, --input|||
| -o, --output|output|output.(apk\|zip)|
|-p, --obfuscate|obfuscate|false|
|-d, --dynamic-register|dynamic_register|false|
|-s, --skip-synthetic|skip_synthetic|false|
|-a, --allow-init|allow_init|false|
|-k, --force-keep-libs|force_keep_libs|false|
|-b, --no-build|no_build|false|
|-f, --filter|filter|filter.txt|
|-c, --custom-loader|custom_loader|amimo.dcc.DccApplication|
|-r, --force-custom-loader|force_custom_loader|false
|-l, --lib-name|lib_name|stub|
|-e, --source-dir|source_dir||
|-z, --project-archive|project_archive|project-source.zip|
