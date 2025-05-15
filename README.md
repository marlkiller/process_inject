# macOS Process Injection Tool


## Usage

```bash
process_inject <target> <dylib> [flags]
```

### Parameters:

- `<target>`: Can be one of:
    - Process ID of the target process (for direct injection)
    - Process name (when using -name flag)
    - Application bundle path (when using -spawn flag)
- `<dylib>`: The full path to the dynamic library (dylib) to inject.
- `[flags]`: Optional flags for different injection modes.

### Flags:

- `-name`: Use the process name instead of process ID to identify the target (for existing processes).
- `-spawn`: Spawn a new process from the specified application bundle and inject the dylib.

### Examples:

1. Inject into an already running process by PID:

```bash
process_inject 1234 "/path/to/library.dylib"
```

2. Inject into an already running process by name:

```bash
process_inject "Safari" "/path/to/library.dylib" -name
```

3. Spawn a new process and inject (spawn mode):

```bash
process_inject "/Applications/Calculator.app/Contents/MacOS/Calculator" "/path/to/library.dylib" -spawn
```


**Note:** Injecting into root processes requires root privileges

> sudo codesign -f -s - --all-architectures --deep --entitlements "process_inject.entitlements" process_inject


## References

Thanks to these projects for their inspiring idea and code!

- <[https://github.com/notahacker8/MacInject](https://github.com/notahacker8/MacInject)>  
