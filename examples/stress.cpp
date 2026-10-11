
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <unistd.h>

using namespace std::chrono_literals;

constexpr int THREAD_COUNT = 32;

std::atomic<bool> stop{false};
std::atomic<uint64_t> checksum{0};

std::mutex sharedMutex;
std::mutex wakeMutex;
std::condition_variable cv;

int generation = 0;
bool finished = false;

void cpuWork(std::chrono::milliseconds duration) {
    auto end = std::chrono::steady_clock::now() + duration;
    uint64_t value = 123456789;

    do {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
    } while (std::chrono::steady_clock::now() < end);

    checksum.fetch_xor(value, std::memory_order_relaxed);
}

void worker(int id) {
    int group = id % 4;

    if (group == 0) {
        // CPU-intensive threads
        while (!stop.load()) {
            cpuWork(3ms);
            std::this_thread::sleep_for(1ms);
        }
    }
    else if (group == 1) {
        // Threads competing for the same mutex
        while (!stop.load()) {
            {
                std::lock_guard<std::mutex> lock(sharedMutex);
                cpuWork(3ms);
            }
            std::this_thread::sleep_for(2ms);
        }
    }
    else if (group == 2) {
        // Threads repeatedly sleeping
        while (!stop.load()) {
            std::this_thread::sleep_for(15ms);
        }
    }
    else {
        // Threads waiting for notifications
        int lastGeneration = 0;

        while (true) {
            std::unique_lock<std::mutex> lock(wakeMutex);

            cv.wait(lock, [&] {
                return generation != lastGeneration || finished;
            });

            if (finished) {
                break;
            }

            lastGeneration = generation;
            lock.unlock();

            cpuWork(2ms);
        }
    }
}

int main() {
    std::cout << "PID: " << getpid() << '\n';
    std::cout << "Starting " << THREAD_COUNT << " threads\n";

    std::vector<std::thread> threads;

    for (int i = 0; i < THREAD_COUNT; ++i) {
        threads.emplace_back(worker, i);
    }

    // Periodically wake condition-variable workers
    for (int i = 0; i < 50; ++i) {
        std::this_thread::sleep_for(50ms);

        {
            std::lock_guard<std::mutex> lock(wakeMutex);
            ++generation;
        }

        cv.notify_all();
    }

    stop.store(true);

    {
        std::lock_guard<std::mutex> lock(wakeMutex);
        finished = true;
    }

    cv.notify_all();

    for (auto& thread : threads) {
        thread.join();
    }

    std::cout << "All threads finished\n";
    std::cout << "Checksum: " << checksum.load() << '\n';

    return 0;
}
