// Worker blocked on a slow producer
// Build with: g++ -std=c++20 -O1 -g -fno-omit-frame-pointer -pthread examples/stall_demo.cpp -o stall-demo
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>
#include <pthread.h>
#include "scope_span.hpp"

using namespace std::chrono_literals;

std::mutex mutex;
std::condition_variable workReady;
bool ready = false;

void takeWork() {
    pthread_setname_np(pthread_self(), "scope-worker");
    scope::Span span("wait_for_work");
    std::unique_lock<std::mutex> lock(mutex);
    workReady.wait(lock, [] { return ready; }); // Blocked worker
    std::cout << "Worker received work\n";
}

void produceWork() {
    pthread_setname_np(pthread_self(), "scope-producer");
    scope::Span span("produce_work");
    // 450 ms handoff delay
    std::this_thread::sleep_for(450ms);
    {
        std::lock_guard<std::mutex> lock(mutex);
        ready = true;
    }
    workReady.notify_one();
}

int main() {
    // Startup delay for mapping capture
    std::this_thread::sleep_for(100ms);
    std::thread worker(takeWork);
    std::thread producer(produceWork);
    worker.join();
    producer.join();
}
