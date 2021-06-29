#include <ArxContainer.h>

ArxRingBuffer<int8_t, 4> buffer;

void setup() {
    Serial.begin(115200);
    delay(2000);

    Serial.println("ringbuffer test start");
    Serial.println();

    buffer.push(1);
    buffer.push(2);
    buffer.push(3);
    buffer.push(4);

    Serial.println("for loop (indexed) should be 1, 2, 3, 4");
    for (size_t i = 0; i < buffer.size(); ++i) {
        Serial.print("index ");
        Serial.print(i);
        Serial.print(": ");
        Serial.println(buffer[i]);
    }

    Serial.println();
    buffer.pop();

    Serial.println("for loop (ranged) should be 2, 3, 4");
    for (const auto& b : buffer)
        Serial.println(b);

    Serial.println();
    buffer.pop();

    Serial.println("for loop (iterator) should be 3, 4");
    for (auto it = buffer.begin(); it != buffer.end(); ++it)
        Serial.println(*it);

    Serial.println();
    Serial.println("===========================================================");
}

void loop() {
    static int count = 5;
    delay(500);

    buffer.push(count++);
    for (const auto& b : buffer) {
        Serial.print(b);
        Serial.print(", ");
    }
    Serial.println();
}
