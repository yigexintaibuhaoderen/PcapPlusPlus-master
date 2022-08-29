#ifndef PACKETPP_GTP_REASSEMBLY
#define PACKETPP_GTP_REASSEMBLY

#include "IpAddress.h"
#include "Packet.h"
#include <map>

/**
 * @namespace pcpp
 * @brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
class GtpPacketData
{
  public:
	GtpPacketData(const uint8_t *udpData, size_t udpDataLength, std::string tupleName)
		: m_Data(udpData), m_DataLen(udpDataLength), m_TupleName(tupleName)
	{
	}

	const uint8_t *getData() const
	{
		return m_Data;
	}

	size_t getDataLength() const
	{
		return m_DataLen;
	}

	std::string getTupleName()
	{
		return m_TupleName;
	}

  private:
	const uint8_t *m_Data;
	size_t m_DataLen;
	std::string m_TupleName;
};

class GTPReassembly
{
  public:
	/**
	 * @typedef OnGtpMessageReady
	 * A callback invoked when new data arrives
	 */
	typedef void (*OnGtpMessageReady)(pcpp::GtpPacketData *udpData, void *userCookie);

	/**
	 * An enum representing the status returned from processing a fragment
	 */
	enum ReassemblyStatus
	{
		NonIpPacket,
		NonGtpPacket,
		GtpMessageHandled,
	};

	GTPReassembly(OnGtpMessageReady onGtpMessageReadyCallback, void *callbackUserCookie = NULL)
		: m_OnGtpMessageReadyCallback(onGtpMessageReadyCallback), m_CallbackUserCookie(callbackUserCookie)
	{
	}


	ReassemblyStatus reassemblePacket(Packet &gtpData);

	ReassemblyStatus reassemblePacket(RawPacket *gtpRawData);

	std::string getTupleName(IPAddress src, IPAddress dst);

  private:
	struct GTPReassemblyData
	{
		IPAddress srcIP;
		IPAddress dstIP;
		std::string tupleName;
		uint16_t number;

		GTPReassemblyData()
		{
		}
		GTPReassemblyData(IPAddress src, IPAddress dst, std::string tName, uint16_t n)
			: srcIP(src), dstIP(dst), tupleName(tName), number(n)
		{
		}
	};

	typedef std::map<std::string, GTPReassemblyData> FragmentList;

	FragmentList m_FragmentList;
	OnGtpMessageReady m_OnGtpMessageReadyCallback;
	void *m_CallbackUserCookie;
};

}// namespace pcpp

#endif /* PACKETPP_GTP_REASSEMBLY */