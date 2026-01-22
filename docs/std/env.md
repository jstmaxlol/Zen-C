# Standard Library: Env (`std/env.zc`)

`Env` is a Zen-C library for accessing the environment of the process environment.

## Usage

```zc
import "std/env.zc"

fn main() {
    Env::set("HELLO", "world");

    var hello = Env::get("HELLO");

    if (hello.is_some()) {
        println "Hello {hello.unwrap()}";
    }
}
```

## Enum

```zc
enum EnvRes {
    ERR,
    OK,
}
```

## Methods

### get

Retrieves the env-var as borrowed string (char *) (no alloc)

```zc
fn get(name: string) -> Option<string>
```

### get_dup

Retrieves the env-var as caller-owned String() (heap alloc)

```zc
fn get_dup(name: string) -> Option<String>
```

### set

Sets an env-var variable

```zc
fn set(name: string, value: string) -> EnvRes
```

### unset

Unsets an existing env-var

```zc
fn unset(name: string) -> EnvRes
```

---

Check the ``examples`` folder for more.
