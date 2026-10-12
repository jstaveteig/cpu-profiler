#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <thread>
#include <cstdio>
#include <pthread.h>
#include "../scope_span.hpp"

using namespace std::chrono_literals;

int main() {
    std::array<std::thread, 32> threads;
    std::array<std::uint64_t, 32> results{};
    std::this_thread::sleep_for(100ms); // Mapping capture

    for (std::size_t i = 0; i < threads.size(); ++i) {
        threads[i] = std::thread([&, i] {
            char name[16];
            std::snprintf(name, sizeof(name), "worker-%02zu", i);
            pthread_setname_np(pthread_self(), name);
            scope::Span worker("worker");
            std::uint64_t value = i + 1;
            for (int round = 0; round < 200; ++round) {
                {
                    scope::Span work("work");
                    for (int n = 0; n < 1'000'000; ++n)
                        value = value * 6364136223846793005ULL + 1;
                }
                {
                    scope::Span sleep("sleep");
                    std::this_thread::sleep_for(5ms);
                }
            }
            results[i] = value;
        });
    }

    for (auto& thread : threads) thread.join();
    std::uint64_t checksum = 0;
    for (auto value : results) checksum += value;
    std::cout << checksum << '\n';
}
