#include <ArxContainer.h>

size_t vec_len(std::initializer_list<int> l) {
    return l.size();
}

void setup() {
    Serial.begin(115200);
    delay(2000);

    arx::vector<int> vs {1, 2, 3, 4, 5};
    for (const auto& v : vs) {
        Serial.print(v);
        Serial.print(" ");
    }
    Serial.println();

    Serial.print("length of initializer_list is: ");
    Serial.println(vec_len({1, 2, 3}));
}

void loop() {
}
