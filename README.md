# not-a-network-utility



My attempt to write a loader in C/C++. It uses

* Compile-time API hashing to hide WinAPI imports,
* Halo's Gate and Indirect syscalls to bypass hooks,
* PPID Spoofing to evade parent-child process co-relation,
* DLL-sideloading restrictions,



and masquerades as a network utility through its versioning and application manifest.



Read more at:

* [Crafting a Loader: My First Experience in Malware Development](https://ashtrace.github.io/posts/my\_first\_loader/)
* [Stripping the Binary Clean: Hiding the malware indicators](https://ashtrace.github.io/posts/stripping\_iocs/)
* [Against Runtime Analysis: Sandboxes, Syscalls and Hooks](https://ashtrace.github.io/posts/sandboxes\_syscalls\_and\_hooks/)

