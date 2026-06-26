#include <pybind11/pybind11.h>
#include <string>

namespace py = pybind11;

class StreamFramer {
private:
    std::string buffer;

public:
    StreamFramer() = default;

    void add_data(const py::bytes& data) {
        // Append new bytes to our internal C++ buffer
        std::string s_data = data;
        buffer += s_data;
    }

    py::list get_frames() {
        py::list frames;
        
        while (buffer.size() >= 4) {
            // Read 4 bytes big endian length prefix
            uint32_t msg_len = ((uint32_t)(uint8_t)buffer[0] << 24) | 
                               ((uint32_t)(uint8_t)buffer[1] << 16) | 
                               ((uint32_t)(uint8_t)buffer[2] << 8)  | 
                               ((uint32_t)(uint8_t)buffer[3]);
            
            // Check if we have the complete message
            if (buffer.size() < 4 + msg_len) {
                break; // Wait for more data
            }
            
            // Extract the message
            std::string frame = buffer.substr(4, msg_len);
            frames.append(py::bytes(frame));
            
            // Remove processed frame from buffer
            buffer.erase(0, 4 + msg_len);
        }
        
        return frames;
    }
};

void init_stream_framer(py::module_ &m) {
    py::class_<StreamFramer>(m, "StreamFramer")
        .def(py::init<>())
        .def("add_data", &StreamFramer::add_data)
        .def("get_frames", &StreamFramer::get_frames);
}
