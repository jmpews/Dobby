#include <ArxContainer.h>

// initialize with initializer_list
arx::vector<int> vs {1, 2, 3};

void setup() {
    Serial.begin(115200);
    delay(2000);

    // add contents
    for (size_t i = 4; i <= 5; ++i)
        vs.push_back(i);

    // index access
    for (size_t i = 0; i < vs.size(); ++i) {
        Serial.print(vs[i]);
        Serial.print(" ");
    }
    Serial.println();

    // range-based access
    for (const auto& v : vs) {
        Serial.print(v);
        Serial.print(" ");
    }
    Serial.println();
}

void loop() {
}
