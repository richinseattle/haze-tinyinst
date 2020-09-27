# haze
 haze binary fuzzer

 This is a fuzzer for Windows based on TinyInst
 Current version is a modification of litecov to perform fuzzing

Checkout 
```
git clone --recurse-submodules https://github.com/richinseattle/haze
```

Build
```
mkdir build
cd build
cmake -G"Visual Studio 16 2019 Win64" ..
cmake --build . --config Release
```

Usage
```
haze.exe --hook_module <module name> --hook_func <offset or symbol name> --cov <module name> -i <input dir> -i <output dir> -- <target path> <target args>
```
