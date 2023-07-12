#ifndef HCI_EVENT_PACKET_H
#define HCI_EVENT_PACKET_H

#include <cstdint>
#include <string>
#include <tuple>
#include <unordered_map>
#include <cassert>

/**
 * HCI event packet format is:
 * 1 octet event code
 * 1 octet parameter total length
 * 0 or octet bytes of parameters
 *
 * References can be found here:
 * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 5.3
 * [vol 4] Part E (Section 5.4.4) - HCI Event Packet
 */

namespace HCIEventPacket
{

    struct HCIEventPacket
    {
        uint8_t eventCode;
        uint8_t parameterTotalLength;

        const unsigned char *parameters;
    };

    struct HCI_EVENT_HEADER_BITS
    {
        uint8_t eventCode : 8;
        uint8_t parameterTotalLength : 8;
    };

    union HCI_EVENT_HEADER
    {
        HCI_EVENT_HEADER_BITS b;
        uint16_t asbyte;
    };

    HCIEventPacket parse(const unsigned char *data)
    {
        HCIEventPacket result;
        HCI_EVENT_HEADER hdr;
        std::memcpy(&hdr.asbyte, data, sizeof(hdr.asbyte));
        result.eventCode = static_cast<uint8_t>(hdr.b.eventCode);
        result.parameterTotalLength = static_cast<uint8_t>(hdr.b.parameterTotalLength);
        result.parameters = data + sizeof(hdr.asbyte);
        return result;
    }

}
#endif // HCI_EVENT_PACKET_H