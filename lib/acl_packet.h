#ifndef ACL_PACKET_PARSER_H
#define ACL_PACKET_PARSER_H

#include <cstdint>
#include <string>
#include <tuple>
#include <unordered_map>
#include <cassert>

/**
 * ACL handle is 12 bits, followed by 2 bits packet boundary flags and 2 bits broadcast flags.
 *
 * References can be found here:
 * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 5.3
 * [vol 4] Part E (Section 5.4.2) - HCI ACL Data Packets
 */

namespace ACLPacket
{

    struct ACL_PACKET
    {
        uint16_t handle;
        uint8_t pb;
        uint8_t bc;
        uint16_t dataLength;
        const unsigned char *payload;
    };

    struct ACL_HEADER_BITS
    {
        uint32_t handle : 12;
        uint32_t pb : 2;
        uint32_t bc : 2;
        uint32_t length : 16;
    };

    union ACL_HEADER
    {
        ACL_HEADER_BITS b;
        uint32_t asbyte;
    };

    const uint8_t PB_START_NON_AUTO_L2CAP_PDU = 0;
    const uint8_t PB_CONT_FRAG_MSG = 1;
    const uint8_t PB_START_AUTO_L2CAP_PDU = 2;
    const uint8_t PB_COMPLETE_L2CAP_PDU = 3;

    const std::unordered_map<uint8_t, std::string> PB_FLAGS = {
        {PB_START_NON_AUTO_L2CAP_PDU, "ACL_PB START_NON_AUTO_L2CAP_PDU"},
        {PB_CONT_FRAG_MSG, "ACL_PB CONT_FRAG_MSG"},
        {PB_START_AUTO_L2CAP_PDU, "ACL_PB START_AUTO_L2CAP_PDU"},
        {PB_COMPLETE_L2CAP_PDU, "ACL_PB COMPLETE_L2CAP_PDU"}};

    ACL_PACKET parse(const unsigned char *data)
    {
        ACL_PACKET result;
        ACL_HEADER hdr;
        std::memcpy(&hdr.asbyte, data, sizeof(hdr.asbyte));
        result.handle = static_cast<uint16_t>(hdr.b.handle);
        result.pb = static_cast<uint8_t>(hdr.b.pb);
        result.bc = static_cast<uint8_t>(hdr.b.bc);
        result.dataLength = static_cast<uint16_t>(hdr.b.length);
        result.payload = data + sizeof(hdr.asbyte);
        return result;
    }

    std::string pb_to_str(uint8_t pb)
    {
        assert(pb >= 0 && pb <= 3);
        return PB_FLAGS.at(pb);
    }

} // namespace ACLPacket

#endif // ACL_PACKET_PARSER_H
