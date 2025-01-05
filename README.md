# efunc
**efunc** is general-purpose kernel function tracer tool like ftrace funcgraph, which was inspired by [retsnoop](https://https://github.com/anakryiko/retsnoop).

## Feature

* **function call graph** trace function entry and exit, even sub-fuction, final generate call relationship.
* **record args and ret** record all args and ret of each traced function.
* **dump any variable base on args or ret** as `skb->head`, `*skb->dev`, you can get data of any variable which can be reached from args or ret, output as a human-readable format (like `gdb` print format)
* **filter by number or string** trace function only filter expression is allowed

## Installation

### Prebuilt binaries
Download binary from [release page](https://github.com/xixiliguo/efunc/releases).    
### Source
install from source code
```bash
go install github.com/xixiliguo/efunc@latest
```