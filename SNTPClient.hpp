/*
   Simple Network Time Protocol (SNTP v4) client for Arduino

   This header-only library provides a complete and self-contained implementation 
   of SNTP v4 client implementation in compliance with the RFC-4330 specification
   for synchronizing time via UDP network sockets in Arduino environments.

   It automatically handles the conversion from the raw NTP timestamp format to a 
   standard Unix epoch timestamp:
      - Processes the incoming raw NTP timestamp (seconds since Jan 1, 1900)
      - Provides a standard Unix epoch timestamp (seconds since Jan 1, 1970)

   Copyright (c) 2026 Jorge Rivera. https://github.com/latchdevel/SNTPClient
   License GNU Lesser General Public License v3.0.
*/

#include <Arduino.h>
#include <Udp.h>
#include <Dns.h>

// Byte Order Conversion (Endianness)
// NTP timestamps are transmitted in Big-Endian (Network Byte Order). 
// This macro converts a 32-bit Big-Endian integer to the Host's native endianness.

#undef be32toh // Prevent conflicts with pre-existing definitions

// Fallback for older compilers that do not support __has_builtin
#ifndef __has_builtin         
   #define __has_builtin(x) 0 // Provide a safe default for legacy compilers
#endif

// be32toh (Big Endian 32-bit to Host)
#if __has_builtin(__builtin_bswap32)
   // Fast path for GCC/Clang compilers (e.g., AVR, ARM, ESP32) using optimized intrinsics
   #define be32toh(x) __builtin_bswap32(x)
#elif defined(ARDUINO_ARCH_ESP32) || defined(ARDUINO_ARCH_ESP8266) || defined(_LWIP_SOCKET_H)
   // Fallback for architectures where ntohl() 'Network to Host Long' is available via LWIP/POSIX
   #define be32toh(x) ntohl(x)
#else
   // Universal pure-C fallback for platforms lacking builtins or network libraries
   #define be32toh(x) ( \
      (((uint32_t)(x) & 0x000000FFUL) << 24) | \
      (((uint32_t)(x) & 0x0000FF00UL) <<  8) | \
      (((uint32_t)(x) & 0x00FF0000UL) >>  8) | \
      (((uint32_t)(x) & 0xFF000000UL) >> 24)   \
   )
#endif

// Fallback: Avoid conflict with newlib, AVR-libc, or other POSIX environments
#if !defined(__time_t_defined) && !defined(_TIME_T_DEFINED) && !defined(_TIME_T)
   typedef unsigned long time_t;
#endif

/**
 * @namespace NTP
 * @brief Scope encapsulating all structures, enumerations, and core logic 
 *        for the Simple Network Time Protocol (SNTP) client implementation.
 * @details Prevents naming collisions within the global scope, grouping components 
 *          responsible for network I/O, packet parsing, and timestamp processing.
*/
namespace NTP {
   /*
      Leap Indicator (LI): This is a two-bit code warning of an impending
      leap second to be inserted/deleted in the last minute of the current
      day.  This field is significant only in server messages, where the
      values are defined as follows:
   */
   enum LeapIndicator : uint8_t {
      NoWarning        = 0, // No warning. The local clock is operating normally and synchronized.
      InsertSecond     = 1, // Positive leap second. The last minute of the current day has 61 seconds.
      DeleteSecond     = 2, // Negative leap second. The last minute of the current day has 59 seconds.
      AlarmCondition   = 3  // Clock unsynchronized. The server time is unreliable and must be rejected.
   };

   /*
      Mode: This is a three-bit number indicating the protocol mode.
      In unicast and manycast modes, the client sets mode field to 3 (CLIENT) in the request,
      The server sets mode to 4 (SERVER) in the reply. In broadcast mode, the server sets 
      mode to 5 (BROADCAST). The other modes are not used by SNTP servers and clients.
      The values are defined as follows:
   */
   enum Mode : uint8_t {
      Reserved           = 0,
      SymmetricActive    = 1,
      SymmetricPassive   = 2,
      Client             = 3,
      Server             = 4,
      Broadcast          = 5,
      ControlMessage     = 6, // Reserved for NTP control message.
      PrivateUse         = 7  // Reserved for private use.
   };

   /*
      Version Number (VN): This is a three-bit integer indicating the
      NTP/SNTP version number, currently 4.  If necessary to distinguish
      between IPv4, IPv6, and OSI, the encapsulating context must be
      inspected.
   */
   enum Version : uint8_t {
      Unknown = 0,
      V1      = 1,
      V2      = 2,
      V3      = 3,
      V4      = 4
   };

   /*
      Stratum  Meaning
      ----------------------------------------------
      0        kiss-o'-death message
      1        primary reference (e.g., synchronized by radio clock)
      2-15     secondary reference (synchronized by NTP or SNTP)
      16-255   reserved
   */
   enum Stratum : uint8_t {
      KissOfDeath           =   0,
      PrimaryReference      =   1,
      SecondaryReferenceMin =   2,
      SecondaryReferenceMax =  15,
      ReservedMin           =  16,
      ReservedMax           = 255
   };

   /*
      Diagnostic error codes indicating specific failure points during execution.
   */
   enum ErrorCodes : uint8_t {
      NoError,                 // Operation completed successfully with no errors detected
      UDPBeginError,           // Failed to initialize or bind the local UDP socket socket
      UDPBeginPacketError,     // Failed to establish a remote connection session via UDP
      UDPAvailableBytesError,  // Network buffer timeout or unexpected incoming data payload stream
      DNSResolveError,         // Domain name resolution failed within the allocated timeout period
      NTPServerIpError,        // Provided NTP server IP address is invalid or evaluates to INADDR_NONE
      NTPPacketSizeError,      // Received payload size does not match the standard 48-byte NTP structure
      NTPModeError,            // Packet rejected: Mode field is not set to standard Server response
      NTPLeapIndicatorError,   // Packet rejected: Leap indicator warns of an unsynchronized clock status
      NTPKissOfDeathError,     // Packet rejected: Stratum contains a destructive Kiss-of-Death code
      NTPStratumError,         // Packet rejected: Stratum exceeds the valid secondary reference limit
      NTPTimestampError,       // Packet rejected: Transmit timestamp seconds evaluate to zero (invalid source)
      NTPEpochError            // Conversion failed: Retrieved NTP time is prior to the 1970 Unix Epoch baseline
   };

   /**
    * @class SNTPClient
    * @brief A lightweight, non-blocking Simple Network Time Protocol (SNTP) client.
    * @details This class provides robust NTP packet parsing, endianness-safe timestamp conversion,
    *          and comprehensive error tracking for embedded systems without blocking core execution loops.
   */
   class SNTPClient final {
      public:
         /**
          * @brief Constructs an SNTPClient instance using only a UDP socket reference.
          * @details Use this constructor if the target server will be specified dynamically 
          *          during runtime operations or resolved through manual overrides.
          * @param udp Reference to an initialized UDP object (e.g., EthernetUDP, WiFiUDP).
         */
         SNTPClient(UDP &udp) : udp(udp) {} ;

         /**
          * @brief Constructs an SNTPClient instance bound to a specific static IP address.
          * @param udp         Reference to an initialized UDP object.
          * @param ntpServerIp The static IP Address of the target remote NTP server.
         */
         SNTPClient(UDP &udp, IPAddress ntpServerIp) : udp(udp), ntpServerIp(ntpServerIp) {} ;

         /**
          * @brief Constructs an SNTPClient instance bound to a domain name string.
          * @details The domain name will be resolved via DNS using the configured timeout 
          *          parameters when execution begins.
          * @param udp           Reference to an initialized UDP object.
          * @param ntpServerName Null-terminated character string containing the remote host domain.
         */
         SNTPClient(UDP &udp, const char* ntpServerName) : udp(udp), ntpServerName(ntpServerName) {};

         /**
          * @brief Public read-only reference to the internal error state.
          * @details Allows external inspection of failure codes without permitting modification.
         */
         const uint8_t& error = errorCode; 

         /**
          * @brief Requests and retrieves the current time from the configured SNTP server.
          * @details Sends an SNTP request packet via UDP, applies a strict hardware timeout,
          *          parses the server response, validates the packet flags, and converts 
          *          the 32-bit NTP timestamp to a standard Unix epoch timestamp.
          * @param timeout_ms  Maximum time in milliseconds to wait for the server's UDP response (default: 500ms).
          * @param dstPort     The target UDP port on the remote NTP server (default: 123).
          * @param srcPort     The local UDP port to bind for this request. If 0, a random dynamic port will be used (default: 0).
          * @return time_t     The current Unix timestamp (seconds since Jan 1, 1970) if successful; 
          *                    returns 0 if the request times out, DNS resolution fails, or packet validation is rejected.
          * @note If the function returns 0, a specific error condition is logged. The caller should check the public read-only 
          *       reference `error` to diagnose the failure reason.
         */
         time_t get(uint16_t timeout_ms = 500, uint16_t dstPort = 123, uint16_t srcPort = 0 ){
            
            time_t result{};
            int beginPacketStatus{};
            NTP_Packet_t ntpPacket{};
            
            ntpPacket.leap    = NTP::LeapIndicator::NoWarning;    // Set Leap Indicator to normal operation
            ntpPacket.version = NTP::Version::V4;                 // Set NTP Version to 4
            ntpPacket.mode    = NTP::Mode::Client;                // Set Mode to Client

            // Reset to `NoError` at the start of operations and updated on failure
            errorCode = NoError;
            
            // Initialize UDP socket
            if (udp.begin(srcPort)) {
               // Checking for NTP server name
               if (ntpServerName) {
                  #if defined(USE_ETHERNET_DNS)
                     // Custom Ethernet DNS resolve (<2 seconds timeout)
                     DNSClient dns;

                     dns.begin(Ethernet.dnsServerIP());

                     if (dns.getHostByName(ntpServerName, ntpServerIp, timeout_ms) == 1) {
                        // UDP begin IP packet
                        beginPacketStatus = udp.beginPacket(ntpServerIp, dstPort);
                     } else {
                        errorCode = DNSResolveError;
                     }
                  #else
                     // UDP begin packet native DNS resolve (>15 seconds timeout)
                     beginPacketStatus = udp.beginPacket(ntpServerName, dstPort);
                  #endif
               } else {
                  if (ntpServerIp != INADDR_NONE) {
                     beginPacketStatus = udp.beginPacket(ntpServerIp, dstPort);
                  } else {
                     errorCode = NTPServerIpError;
                  }
               }

               // Checking for UDP beginPacket
               if (beginPacketStatus){
                  udp.write(ntpPacket.raw, NTP_Packet_size);
                  udp.endPacket();

                  unsigned long timeout = millis() + timeout_ms;

                  while ((udp.parsePacket() == 0) and (millis() < timeout)) {
                     delay(1);
                  }

                  if (udp.available() == NTP_Packet_size) {
                     if (udp.read(ntpPacket.raw, NTP_Packet_size) == NTP_Packet_size){
                        if (ntpPacket.mode == NTP::Mode::Server){
                           if (ntpPacket.leap == NTP::LeapIndicator::NoWarning){
                              if (ntpPacket.stratum != NTP::Stratum::KissOfDeath) {
                                 if (ntpPacket.stratum <= NTP::Stratum::SecondaryReferenceMax) {
                                    if (ntpPacket.transmit_ts.seconds != 0) {
                                       // Transmit timestamp 'fraction' is ignored since sub-second precision is not required
                                       // Convert transmit timestamp 'seconds' from Network Byte Order to Host Byte Order
                                       uint32_t ntp_time = be32toh(ntpPacket.transmit_ts.seconds);
                                       if (ntp_time > NTP_TO_UNIX_EPOCH_OFFSET) {
                                          result = ntp2epoch(ntp_time);
                                       } else {
                                          errorCode = NTPEpochError;
                                       }
                                    } else {
                                       errorCode = NTPTimestampError;
                                    }
                                 } else {
                                    errorCode = NTPStratumError;
                                 }
                              } else {
                                 errorCode = NTPKissOfDeathError;
                              }
                           } else {
                              errorCode = NTPLeapIndicatorError;
                           }
                        } else {
                           errorCode = NTPModeError;
                        }
                     } else {
                        errorCode = NTPPacketSizeError;
                     }
                  } else {
                     errorCode = UDPAvailableBytesError;
                  }
               } else {
                  if (errorCode == NoError)
                     errorCode = UDPBeginPacketError;
               }
            } else {
               errorCode = UDPBeginError;
            }

            udp.stop();
            return result;
         } // End of get() method

      private:
         /**
          * @brief Reference to the active network UDP interface implementation.
          * @note Must be explicitly initialized via the constructor initialization list; 
          *       cannot be default-assigned or left uninitialized.
         */
         UDP &udp;

         /**
          * @brief Pointer to a null-terminated string holding the remote NTP server domain name.
          * @details Defaults to `nullptr` if a static IP address or manual assignment is used instead.
         */
         const char* ntpServerName{nullptr};

         /**
          * @brief Stored IP address of the target NTP server.
          * @details Defaults to `INADDR_NONE` to explicitly flag an unconfigured or 
          *          invalid IP address prior to resolution.
         */         
         IPAddress ntpServerIp{INADDR_NONE};
         
         /** 
          * @brief Internal state register tracking the most recent execution outcome.
          * @details Reset to `NoError` at the start of operations and updated on failure.
         */
         uint8_t errorCode{NoError}; 

         /** 
          * @brief Number of seconds from Jan 1, 1900 (NTP Epoch) to Jan 1, 1970 (Unix Epoch).
          * @details Constant value used to convert NTP timestamps to Unix timestamps by offsetting the difference in epochs.
         */
         static constexpr uint32_t NTP_TO_UNIX_EPOCH_OFFSET = 2208988800UL;

         /**
          * @brief Represents a standard 64-bit NTP fixed-point timestamp.
          * @details Consists of a 32-bit seconds part and a 32-bit fractional part.
         */
         struct NTP_Timestamp_t {
            uint32_t seconds;  // Main 32-bit counter representing seconds since Jan 1, 1900.
            uint32_t fraction; // 32-bit fractional part representing sub-second values
         } __attribute__((__packed__));

         /**
          * @brief Data structure mapping the standard 48-byte NTP packet payload.
          * @details Wrapped in a union to allow dual-mode access: either as a raw 
          *          byte array for I/O operations or as structured fields.
         */
         union NTP_Packet_t {
            uint8_t raw[48]; // Raw binary buffer representing the complete network packet
            struct  {
               /**
                * @brief Anonymous union encapsulating the first protocol byte.
                * @details Exposes fields directly while allowing full byte manipulation.
               */
               union {
                  uint8_t controlByte;  // Access to the complete control byte at once
                  struct {
                     // Bitfield ordering depends on the host architecture's endianness
                     // The layout below matches typical little-endian bit packing order
                     uint8_t mode      : 3;  // Bits 0-2 Mode: Specifies the protocol mode (e.g., Client, Server)
                     uint8_t version   : 3;  // Bits 3-5 Version: NTP version number (typically 4)
                     uint8_t leap      : 2;  // Bits 6-7 Leap Indicator : Warns of impending leap second
                  };
               };
               
               uint8_t stratum;              // 8 bits: Stratum level of the clock (distance from reference source)
               uint8_t poll;                 // 8 bits: Poll interval between successive messages (log2 seconds)
               int8_t  precision;            // 8 bits: Signed precision of the host system clock (log2 seconds)

               // Delay and Dispersion Fields
               uint32_t root_delay;          // 32 bits: Total round-trip delay to the reference clock source
               uint32_t root_dispersion;     // 32 bits: Total maximum error inherent in the reference clock estimate
               uint32_t ref_id;              // 32 bits: Reference source identifier (e.g., ASCII string or IPv4 address)

               // 64-bit NTP Timestamps
               NTP_Timestamp_t reference_ts; // 64 bits: Reference Timestamp: Time when the system clock was last set or corrected
               NTP_Timestamp_t originate_ts; // 64 bits: Originate Timestamp: Time at which the request departed the client
               NTP_Timestamp_t receive_ts;   // 64 bits: Receive Timestamp: Time at which the request arrived at the server
               NTP_Timestamp_t transmit_ts;  // 64 bits: Transmit Timestamp: Time at which the reply departed the server
            } __attribute__((packed));  // Prevents compiler padding to maintain strict alignment with network layout
         };

         /** 
          * @brief Size of the NTP packet structure in bytes.
          * @details Calculated automatically at compile time using the size of the NTP_Packet_t type.
         */
         static constexpr uint8_t NTP_Packet_size = sizeof(NTP_Packet_t);

         /** 
          * @brief Converts an NTP timestamp (seconds since 1900) to a Unix epoch timestamp (seconds since 1970).
          * @details Subtracts the epoch offset difference (NTP_TO_UNIX_EPOCH_OFFSET) to align the time base.
          * @param ntpSeconds Raw timestamp in NTP format (seconds since Jan 1, 1900).
          * @return The corresponding Unix timestamp as a time_t value.
         */
         static time_t ntp2epoch(uint32_t ntpSeconds) {
            return static_cast<time_t>(ntpSeconds - NTP_TO_UNIX_EPOCH_OFFSET);
         }
   }; // End of class SNTPClient

} // End of namespace NTP
