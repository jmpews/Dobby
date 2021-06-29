# ArxContainer

C++ container-like classes (`vector`, `deque`, `map` etc.) for Arduino which cannot use STL

## Note

- `ArxContainer` is C++ container-__like__ classes for Arduino
  - Containers in this library is defined inside namespace `arx` instad of `std` (e.g. `arx::vector`)
  - All of the functions is not supported currently
- If standard libraries are available, automatically use `std` version instead of `arx` version


## Supported Container Types

- `vector`
- `map` (`pair`)
- `deque`


## Supported Boards

`arx` version of containers are enabled only if you use following architecture.
In other borads, `arx` version is disabled and standard libraries (`std` version) will be imported (because they can use them).

- AVR (Uno, Nano, Mega, etc.)
- MEGAAVR (Uno WiFi, Nano Ecery, etc.)
- SAM (Due)


## Usage

### vector

```C++
// initialize with initializer_list
arx::vector<int> vs {1, 2, 3};

// add contents
for (size_t i = 4; i <= 5; ++i)
    vs.push_back(i);

// index access
for (size_t i = 0; i < vs.size(); ++i)
    Serial.println(vs[i]);

// range-based access
for (const auto& v : vs)
    Serial.println(v);
```

### map

``` C++
// initialize with initializer_list
arx::map<String, int> mp {{"one", 1}, {"two", 2}};

// add contents
mp.insert("three", 3);
mp["four"] = 4;

// range based access
for (const auto& m : mp)
{
    Serial.print("{");
    Serial.print(m.first); Serial.print(",");
    Serial.print(m.second);
    Serial.println("}");
}

// key access
Serial.print("one   = "); Serial.println(mp["one"]);
Serial.print("two   = "); Serial.println(mp["two"]);
Serial.print("three = "); Serial.println(mp["three"]);
Serial.print("four  = "); Serial.println(mp["four"]);
```

### deque

```C++
// initialize with initializer_list
arx::deque<int> dq {1, 2, 3};

// add contents
for (int i = 4; i <= 5; ++i)
    dq.push_back(i);

// index access
for (int i = 0; i < dq.size(); ++i)
    Serial.print(dq[i]);
```


## Detail

`ArxContainer` is C++ container-__like__ classes for Arduino.
This library is based on `arx::RingBuffer` and `arx::xxxx` is limited-size container.
`arx::RingBuffer` can be used as:

```C++
ArxRingBuffer<uint8_t, 4> buffer;

buffer.push(1);
buffer.push(2);
buffer.push(3);

for(size_t i = 0; i < buffer.size(); ++i)
    Serial.println(buffer[i]);

buffer.pop();

for(auto& b : buffer)
    Serial.println(b);
```

`arx::xxxx` are derived from `RingBuffer` and defined as:

``` C++
namespace arx {
    template <typename T, size_t N = ARX_VECTOR_DEFAULT_SIZE>
    struct vector : public RingBuffer<T, N>

    template <class Key, class T, size_t N = ARX_MAP_DEFAULT_SIZE>
    struct map : public RingBuffer<pair<Key, T>, N>

    template <typename T, size_t N = ARX_DEQUE_DEFAULT_SIZE>
    struct deque : public RingBuffer<T, N>
}
```

So range-based loop cannot be applyed to `arx::deque` (iterator is not continuous because it is based on `RingBuffer`).


### Manage Size Limit of Container

Global default size of container can be changed by defining these macros before `#include <ArxContainer.h>`.

``` C++
#define ARX_VECTOR_DEFAULT_SIZE XX // default: 16
#define ARX_MAP_DEFAULT_SIZE XX    // default: 16
#define ARX_DEQUE_DEFAULT_SIZE XX  // default: 16
```

Or you can change each container size by template argument.

``` C++
arx::vector<int, 3> vs;
arx::map<String, int, 4> ms;
arx::deque<int, 5> ds;
```

## Roadmap

This library will be updated if I want to use more container interfaces on supported boards shown above.
PRs are welcome!


## Used Inside of

- [Packetizer](https://github.com/hideakitai/Packetizer)
- [MsgPack](https://github.com/hideakitai/MsgPack)
- [ArduinoOSC](https://github.com/hideakitai/ArduinoOSC)
- [ArtNet](https://github.com/hideakitai/ArtNet)
- [Tween](https://github.com/hideakitai/Tween)
- [TimeProfiler](https://github.com/hideakitai/TimeProfiler)
- [TaskManager](https://github.com/hideakitai/TaskManager)
- [ArxStringUtils](https://github.com/hideakitai/ArxStringUtils)
- [Debouncer](https://github.com/hideakitai/Debouncer)


## License

MIT
