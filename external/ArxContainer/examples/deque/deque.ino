#include <ArxContainer.h>

// initialize with initializer_list
arx::deque<int> dq {1, 2, 3};

void setup() {
    Serial.begin(115200);
    delay(2000);

    // add contents
    for (size_t i = 4; i <= 5; ++i)
        dq.push_back(i);

    // index access
    for (size_t i = 0; i < dq.size(); ++i) {
        Serial.print(dq[i]);
        Serial.print(" ");
    }
    Serial.println();
}

void loop() {
}
