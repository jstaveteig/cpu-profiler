// Scope's known delay: worker waits for an intentionally slow producer.
// Build with: g++ -std=c++20 -O1 -g -fno-omit-frame-pointer -pthread examples/stall_demo.cpp -o stall-demo
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>

using namespace std::chrono_literals;

std::mutex mutex;
std::condition_variable workReady;
bool ready = false;

void takeWork() {
    std::unique_lock<std::mutex> lock(mutex);
    workReady.wait(lock, [] { return ready; }); // The deliberately blocked site.
    std::cout << "Worker received work\n";
}

void produceWork() {
    // Deliberately postpone the handoff to make the wait easy to find.
    std::this_thread::sleep_for(450ms);
    {
        std::lock_guard<std::mutex> lock(mutex);
        ready = true;
    }
    workReady.notify_one();
}

int main() {
    // Allow the recorder to observe this executable's memory mappings first.
    std::this_thread::sleep_for(100ms);
    std::thread worker(takeWork);
    std::thread producer(produceWork);
    worker.join();
    producer.join();
}
