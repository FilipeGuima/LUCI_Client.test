/*

 * LUCI PACKET FORMATION CODE

 * Copyright (c) 2016-2019 Libre Wireless Technologies

 * All rights reserved

 

 * Redistribution and use in source and binary forms, with or without

 * modification, are permitted provided that the following conditions

 * are met:

 * 1. Redistributions of source code must retain the above copyright

 *    notice, this list of conditions and the following disclaimer.

 * 2. Redistributions in binary form must reproduce the above copyright

 *    notice, this list of conditions and the following disclaimer in the

 *    documentation and/or other materials provided with the distribution.

 *

 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND

 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE

 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE

 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE

 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL

 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS

 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)

 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT

 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY

 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF

 * SUCH DAMAGE.

 

 *RECOMENDATION : THIS IS ONLY REFERENCE APPLICATION SHOWING CASING  THE LUCI CLIENT IMPLEMENTATION ,

  *WE STRONGLY RECOMMEND TO REFER LUCI DOCUMENTATION OBATINED FROM LIBRE WIRELESS TECHNOLOGIES

*/

#ifndef __LUCI_PACKET_H__
#define __LUCI_PACKET_H__

#define LUCI_SAFE_FREE(ptr) \
    if(ptr) \
    { \
      free(ptr); \
      ptr = NULL; \
    }


class LUCIPacket {
  public:
  
    LUCIPacket()
        : mIsPacked(false)
        , mRemoteID(0)
        , mCommandType(0)
        , mSocketInfo(0)
        , mCRC(0)
        , mCommand(100)
        , mCommandStatus(0)
        , mDataLen(0)
        , mPacket(NULL)
        , mPacketLen(0) 
        , mAccessUnitData(NULL)
        ,m_IP(NULL)
{
    
}

  public:
    virtual ~LUCIPacket();
    void setRemoteID(uint16_t val);
    void setCommandType(uint8_t val);
    void setCommand(uint16_t val);
    void setCommandStatus(uint8_t val);
    void setSocketInfo(uint8_t val);

    uint16_t getRemoteID() const ;
    uint8_t getSocketInfo() const ;
    uint8_t getCommandType() const ;
    uint16_t getCommand() const ;
    uint8_t getCommandStatus() const ;
    void setAccessUnitData( uint8_t* data, size_t len);
    void getAccessUnitData( uint8_t ** data, size_t *len);

    uint8_t* getPacket() const;
    int getPacketLen() const;
    bool CalcCRC(uint8_t*& buf);
    virtual bool pack();
    void setIP(char* IP);
    char* getIP();
   
  protected:
    static const int kLUCIHeaderLen = 10;
   
    void writeLUCIHeader(uint8_t*& buf,
                        
                         int totalPacketLen);
    void writeU8(uint8_t*& buf, uint8_t val);
    void writeU16(uint8_t*& buf, uint16_t val);
    void writeU32(uint8_t*& buf, uint32_t val);
    void writeU64(uint8_t*& buf, uint64_t val);

    bool      mIsPacked;
    size_t    mAccessUnitLen;

    uint16_t  mRemoteID;
    uint8_t   mCommandType;  // 1 is get and 2 is set and
    uint8_t   mSocketInfo;
    uint16_t  mCRC;
    uint16_t  mCommand;
    uint8_t   mCommandStatus;
    uint16_t  mDataLen;
    uint8_t*  mPacket;
    int       mPacketLen;

    uint8_t* mAccessUnitData;
    
    char *m_IP;

};

#endif 
