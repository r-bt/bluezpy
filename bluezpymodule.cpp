#include <iostream>
#include <vector>
#include <array>
#include <memory>
#include <cstring>
#include <cstdint>
#include <poll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include "lib/acl_packet.h"
#include "lib/hci_event_packet.h"
#include <iomanip>
#include <unordered_map>
#include <queue>
#include <Python.h>
#include <thread>
#include <mutex>

std::queue<std::pair<std::string, std::vector<unsigned char>>> packetQueue;
std::mutex queueMutex;

struct HCIAdapter
{
    int deviceId;
    int socket;
};

using handle_map = std::unordered_map<uint16_t, bdaddr_t>;
using device_map = std::unordered_map<int, handle_map>;

/**
 * Creates a HCI socket and returns the file descriptor.
 *
 * @param devId The device ID of the HCI device to use.
 * @return The file descriptor of the HCI socket, or -1 if an error occurred.
 */
std::unique_ptr<int> create_hci_socket(int devId)
{
    std::unique_ptr<int> hciSocket(new int(hci_open_dev(devId)));
    if (*hciSocket < 0)
    {
        perror("Failed to open HCI device");
        return nullptr;
    }
    return hciSocket;
}

/**
 * Returns a list of HCI devices
 *
 * @param hciSocket The HCI socket to use
 * @return A vector of HCI devices
 */
std::vector<hci_dev_info> get_hci_dev_list(int hciSocket)
{
    std::vector<hci_dev_info> devInfos;

    struct hci_dev_list_req *devList;
    struct hci_dev_info devInfo;

    devList = (struct hci_dev_list_req *)malloc(HCI_MAX_DEV * sizeof(struct hci_dev_req) + sizeof(uint16_t));
    if (!devList)
    {
        perror("Failed to allocate HCI device request memory");
        return devInfos;
    }

    devList->dev_num = HCI_MAX_DEV;

    if (ioctl(hciSocket, HCIGETDEVLIST, (void *)devList) < 0)
    {
        perror("Failed to get HCI device list");
        free(devList);
        return devInfos;
    }

    int devCount = devList->dev_num;

    for (int i = 0; i < devCount; i++)
    {
        devInfo.dev_id = devList->dev_req[i].dev_id;
        if (ioctl(hciSocket, HCIGETDEVINFO, (void *)&devInfo) < 0)
        {
            perror("Failed to get HCI device info");
            continue;
        }

        devInfos.push_back(devInfo);
    }

    // Deallocates block of memory previously allocated by malloc
    free(devList);

    return devInfos;
}

/**
 * Creates sockets for all available HCI devices
 *
 * @return A vector of HCIAdapter objects
 */
std::vector<HCIAdapter> get_hci_adapters()
{
    std::vector<HCIAdapter> adapters;

    int initalDeviceId = hci_get_route(NULL);

    std::unique_ptr<int> hciSocket = create_hci_socket(initalDeviceId);
    if (hciSocket < 0)
    {
        perror("Failed to open HCI device");
        return adapters;
    }

    adapters.push_back({initalDeviceId, *hciSocket});

    std::vector<hci_dev_info> devInfos = get_hci_dev_list(*hciSocket);

    for (const auto &devInfo : devInfos)
    {
        int devId = devInfo.dev_id;

        std::string message = "Device id: " + std::to_string(devId) + "\n";

        if (devId == initalDeviceId)
        {
            continue;
        }

        std::unique_ptr<int> newSocket = create_hci_socket(devId);
        if (newSocket < 0)
        {
            perror("Failed to open HCI device");
            continue;
        }

        adapters.push_back({devId, *newSocket});
    }

    return adapters;
}

void handle_acl_packet(ACLPacket::ACL_PACKET const &packet, handle_map &handleToAddress)
{
    // Check if the packet is an ATT Handle Value Notification (0x1B is the opcode for ATT Handle Value Notification)
    if (packet.payload[4] != 0x1B)
    {
        return;
    };

    uint16_t handle = packet.handle;

    // Make sure the handle maps to a Bluetooth address
    if (handleToAddress.find(handle) == handleToAddress.end())
    {
        return;
    }

    char addressStr[18];
    ba2str(&handleToAddress[handle], addressStr);

    // Get the packet data

    std::vector<unsigned char> extractedValue;

    int startOffset = 7; // Assuming this is the inclusive start offset
    int numElements = packet.dataLength - startOffset;

    const unsigned char *payloadPtr = packet.payload + startOffset;

    extractedValue.reserve(numElements);
    extractedValue.insert(extractedValue.end(), payloadPtr, payloadPtr + numElements);

    // Add it to the queue

    std::lock_guard<std::mutex> lock(queueMutex);

    packetQueue.push(std::make_pair(std::string(addressStr), extractedValue));
}

void handle_hci_event_packet(HCIEventPacket::HCIEventPacket const &packet, handle_map &handleToAddress)
{
    if (packet.eventCode != EVT_LE_META_EVENT)
    {
        return;
    }

    evt_le_meta_event *evt = (evt_le_meta_event *)packet.parameters;

    switch (evt->subevent)
    {
    case EVT_LE_CONN_COMPLETE:
    {
        evt_le_connection_complete *cc = (evt_le_connection_complete *)evt->data;

        handleToAddress[cc->handle] = cc->peer_bdaddr;
    }
    }
}

void handle_packet(const unsigned char *packet, handle_map &handleToAddress)
{
    switch (packet[0])
    {
    case HCI_ACLDATA_PKT:
    {
        ACLPacket::ACL_PACKET acl_packet = ACLPacket::parse(packet + 1);
        handle_acl_packet(acl_packet, handleToAddress);
        break;
    }
    case HCI_EVENT_PKT:
    {
        HCIEventPacket::HCIEventPacket hci_event_packet = HCIEventPacket::parse(packet + 1);
        handle_hci_event_packet(hci_event_packet, handleToAddress);
        break;
    }
    }
}

void init()
{
    // Py_BEGIN_ALLOW_THREADS;

    std::vector<HCIAdapter> adapters = get_hci_adapters();

    // We'll store a vector of pollfds
    std::vector<pollfd> fds(adapters.size());

    for (const HCIAdapter &adapter : adapters)
    {
        // Set HCI filter to only receive HCI ACL Data packets
        struct hci_filter filter;
        hci_filter_clear(&filter);
        hci_filter_set_ptype(HCI_ACLDATA_PKT, &filter);
        hci_filter_set_ptype(HCI_EVENT_PKT, &filter);
        hci_filter_set_event(EVT_LE_META_EVENT, &filter);

        if (setsockopt(adapter.socket, SOL_HCI, HCI_FILTER, &filter, sizeof(filter)) < 0)
        {
            perror("Failed to set HCI filter");
            close(adapter.socket);
            continue;
        }

        // Add the socket to the pollfd vector
        fds[adapter.deviceId].fd = adapter.socket;
        fds[adapter.deviceId].events = POLLIN;
    }

    // We need to map deviceIds to a map of handles to addresses
    device_map deviceToHandleToAddress;

    // Poll for incoming packets
    while (true)
    {
        if (poll(fds.data(), fds.size(), -1) < 0)
        {
            perror("Poll failed");
            break;
        }

        for (const HCIAdapter &adapter : adapters)
        {
            if (fds[adapter.deviceId].revents & POLLIN)
            {
                std::array<unsigned char, HCI_MAX_EVENT_SIZE> buffer;
                std::memset(buffer.data(), 0, buffer.size());

                int bytesRead = read(adapter.socket, buffer.data(), buffer.size());
                if (bytesRead > 0)
                {
                    handle_packet(buffer.data(), deviceToHandleToAddress[adapter.deviceId]);
                }
            }
        }
    }

    // Py_END_ALLOW_THREADS;
}

static std::thread bluezListeningThread;

static PyObject *listen(PyObject *self, PyObject *args)
{
    if (!bluezListeningThread.joinable())
    {
        bluezListeningThread = std::thread(init);
        bluezListeningThread.detach();
    }

    Py_RETURN_NONE;
}

PyObject *get_packet(PyObject *self, PyObject *args)
{
    std::lock_guard<std::mutex> lock(queueMutex);

    if (packetQueue.empty())
        Py_RETURN_NONE;

    auto item = packetQueue.front();
    packetQueue.pop();

    // Create a Python string object for the address
    PyObject *addressObj = PyUnicode_FromString(item.first.c_str());

    // Create a Python bytearray object for the packets
    PyObject *packetsByteArray = PyByteArray_FromStringAndSize(reinterpret_cast<const char *>(item.second.data()), item.second.size());

    // Create a tuple object with the address and packets
    PyObject *returnValue = PyTuple_New(2);
    PyTuple_SetItem(returnValue, 0, addressObj);
    PyTuple_SetItem(returnValue, 1, packetsByteArray);

    return returnValue;
}

static PyMethodDef BluezPyMethods[] = {
    {"listen", listen, METH_VARARGS, "Listen for Bluetooth packets"},
    {"get_packet", get_packet, METH_NOARGS, "Get the first packet from the queue."},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef bluezpy = {
    PyModuleDef_HEAD_INIT,
    "bluezpy",
    "Bluez Python module",
    -1,
    BluezPyMethods};

PyMODINIT_FUNC PyInit_bluezpy(void)
{
    return PyModule_Create(&bluezpy);
}