# signscanner

静态定位 QQ `wrapper.node` 里的**签名函数**喵～。

不做字节特征匹配——除了那串 RTTI 类型名本身。全程沿 C++ 对象模型的稳定锚点链走：

```text
Itanium (Linux/macOS): name -> typeinfo -> vtable -> MSFSign -> sign core
MSVC    (Windows):     type descriptor -> COL -> vtable -> MSFSign -> sign core
```

传入一个文件即可，容器（ELF / PE / Mach-O universal）、架构（x86-64 / aarch64）与
ABI（Itanium / MSVC）全部自动识别；universal Mach-O 会逐个切片定位。

## 用法

```sh
signscanner <wrapper.node>          # 自动识别并打印各锚点与签名函数 RVA
signscanner --json <wrapper.node>   # JSON 输出（脚本消费）
signscanner -q <wrapper.node>       # 只输出签名函数 RVA（每切片一行）
signscanner --typeinfo <NAME> <wrapper.node>  # 覆盖 RTTI 锚点名
signscanner --no-banner <wrapper.node>        # 不打印 banner
```

## 构建

```sh
cargo build --release      # 产物 target/release/signscanner
```
