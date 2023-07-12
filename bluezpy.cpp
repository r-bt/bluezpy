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

struct HCIAdapter
{
    int deviceId;
    int socket;
};

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

void handle_acl_packet(ACLPacket::ACL_PACKET packet)
{
}

void handle_hci_event_packet(HCIEventPacket::HCIEventPacket packet)
{
    if (packet.eventCode != EVT_LE_META_EVENT)
    {
        return;
    }

    uint8_t eventCode = packet.eventCode;
    std::cout << "Event Code: 0x" << std::hex << static_cast<int>(eventCode) << std::endl;
    std::cout << "Parameters: ";
    for (int i = 0; i < packet.parameterTotalLength; ++i)
    {
        std::cout << std::setw(2) << std::setfill('0') << static_cast<int>(packet.parameters[i]) << " ";
    }
    std::cout << std::endl;
}

void print_packet(const unsigned char *packet, int debug_length)
{
    switch (packet[0])
    {
    case HCI_ACLDATA_PKT:
    {
        ACLPacket::ACL_PACKET acl_packet = ACLPacket::parse(packet + 1);
        handle_acl_packet(acl_packet);
        break;
    }
    case HCI_EVENT_PKT:
    {
        HCIEventPacket::HCIEventPacket hci_event_packet = HCIEventPacket::parse(packet + 1);
        handle_hci_event_packet(hci_event_packet);
        break;
    }
    }

    // std::cout << "Packet[0] value: " << std::hex << static_cast<int>(packet[0]) << std::endl;

    // std::cout << "Payload: ";
    // for (int i = 0; i < debug_length; ++i)
    // {
    //     std::cout << std::hex << static_cast<int>(packet[i]) << " ";
    // }
    // std::cout << std::endl;
    // We remove the first byte since it contains the packet type
    // ACLPacket::ACL_PACKET acl_packet = ACLPacket::parse(packet + 1);

    // uint16_t handle = acl_packet.handle;
    // std::cout << "Handle: " << handle << std::endl;

    // uint16_t length = acl_packet.dataLength;
    // std::cout << "Length: " << std::dec << acl_packet.dataLength << std::endl;

    // std::cout << "PB: " << ACLPacket::pb_to_str(acl_packet.pb) << std::endl;

    // const unsigned char *payload = acl_packet.payload;
    // std::cout << "Payload: ";
    // for (int i = 0; i < length; ++i)
    // {
    //     std::cout << std::hex << static_cast<int>(payload[i]) << " ";
    // }
    // std::cout << std::endl;

    // if (packet[0] == HCI_EVENT_PKT)
    // {
    //     // Extract the Bluetooth address from the HCI event header
    //     bdaddr_t address;
    //     bacpy(&address, reinterpret_cast<const bdaddr_t *>(&packet[3]));

    //     // Print the Bluetooth address
    //     char addressStr[18];
    //     ba2str(&address, addressStr);
    //     std::cout << "Bluetooth Address: " << addressStr << std::endl;
    // }
    // else if (packet[0] == HCI_ACLDATA_PKT)
    // {
    //     // Check if the packet is an ATT Handle Value Notification (0x1B is the opcode for ATT Handle Value Notification)
    //     if (packet[9] == 0x1B)
    //     {
    //         // Extract the Attribute Handle
    //         uint16_t attributeHandle = packet[10] | (packet[11] << 8);

    //         // Extract an arbitrary length value starting from a specific offset (e.g., offset 12)
    //         std::vector<unsigned char> extractedValue;
    //         int offset = 12;
    //         while (offset < length)
    //         {
    //             extractedValue.push_back(packet[offset]);
    //             offset++;
    //         }

    //         // Print the Attribute Handle and Attribute Value
    //         std::cout << "Attribute Handle: " << attributeHandle << std::endl;
    //         std::cout << "Attribute Value: ";
    //         for (auto byte : extractedValue)
    //         {
    //             printf("%02X ", byte);
    //         }
    //         std::cout << std::endl;
    //     }
    // }
}

int main()
{
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
        hci_filter_set_event(EVT_LE_CONN_COMPLETE, &filter);
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
                    print_packet(buffer.data(), bytesRead);
                }
            }
        }
    }
}