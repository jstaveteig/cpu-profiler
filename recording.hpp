#pragma once

#include "reconstruct.hpp"
#include <string>
#include <vector>

void saveRecording(
    const std::string& path,
    const std::vector<traceEvent>& events
);


std::vector<traceEvent> loadRecording(
    const std::string& path
);