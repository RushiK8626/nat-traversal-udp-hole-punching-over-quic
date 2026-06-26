#include <pybind11/pybind11.h>
#include <chrono>
#include <thread>
#include <string>
#include <atomic>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

namespace py = pybind11;

class Puncher {
private:
    std::atomic<bool> stop_flag{false};

public:
    Puncher() = default;

    void stop() {
        stop_flag = true;
    }

    // Send punches blockingly. Must be run in an executor.
    void send_punches(int sock_fd, const std::string& target_ip, int target_port,
                      const std::string& peer_id, int max_attempts) {
        
        stop_flag = false;

        // Release the Python GIL so asyncio and other threads can continue to run!
        py::gil_scoped_release release;
        
        struct sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(target_port);
        inet_pton(AF_INET, target_ip.c_str(), &target_addr.sin_addr);

        auto create_packet = [&](int seq) {
            auto now = std::chrono::system_clock::now().time_since_epoch();
            double ts = std::chrono::duration<double>(now).count();
            char buf[256];
            snprintf(buf, sizeof(buf), "{\"magic\": \"NATPUNCH\", \"peer_id\": \"%s\", \"seq\": %d, \"ts\": %f}", peer_id.c_str(), seq, ts);
            return std::string(buf);
        };

        // Initial burst
        for (int i = 0; i < 5 && !stop_flag; ++i) {
            std::string pkt = create_packet(i);
            sendto(sock_fd, pkt.c_str(), pkt.size(), 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        // Regular interval punches
        for (int seq = 5; seq < max_attempts && !stop_flag; ++seq) {
            std::string pkt = create_packet(seq);
            sendto(sock_fd, pkt.c_str(), pkt.size(), 0, (struct sockaddr*)&target_addr, sizeof(target_addr));
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
};

void init_stream_framer(py::module_ &m); // forward declaration

PYBIND11_MODULE(nat_core_ext, m) {
    m.doc() = "NAT Traversal C++ extension";

    py::class_<Puncher>(m, "Puncher")
        .def(py::init<>())
        .def("stop", &Puncher::stop, "Stop the sending loop")
        .def("send_punches", &Puncher::send_punches, 
             py::arg("sock_fd"), py::arg("target_ip"), py::arg("target_port"), 
             py::arg("peer_id"), py::arg("max_attempts"),
             "Send hole punch packets. Releases GIL.");

    init_stream_framer(m);
}
