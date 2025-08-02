self.nfc.powerOff()
self.nfc.deconfigure()
READER_LIBNFC = 0x08
#########################################################################
#########################################################################
list cards we need'
@@@@@@@@#######################################


    def selectISO14443A(self):
        """Detect and initialise an ISO14443A card, returns an ISO14443A() object."""
        if rfidiotglobals.Debug:
            self.log.debug("Polling for ISO14443A cards")
        self.powerOff()
        self.powerOn()
        nm = NFC_MODULATION()
        nm.nmt = NMT_ISO14443A
        nm.nbr = NBR_106
        if self.libnfc.nfc_initiator_list_passive_targets(
            self.device, nm, ctypes.byref(self.tag), MAX_TARGET_COUNT
        ):
            return ISO14443A(self.tag[0].nti.nai)
        return None


#################################################################
SELECT TAG
#################################################################

if self.readertype == self.READER_LIBNFC:
            try:
                if self.DEBUG:
                    print("selecting card using LIBNFC")
                if cardtype == "A":
                    result = self.nfc.selectISO14443A()
                    if result:
                        self.atr = result.atr
                        self.uid = result.uid
                        if self.DEBUG:
                            print("UID: " + self.uid)
                        return True
                    # else:
                    if self.DEBUG:
                        print("Error selecting card")
                    return False
                if cardtype == "B": # elif
                    result = self.nfc.selectISO14443B()
                    if result:
                        self.pupi = result.pupi
                        self.atr = result.atr
                        self.uid = result.uid
                        self.appdata = result.appdata
                        self.protocol = result.protocol
                        self.cid = result.cid
                        if self.DEBUG:
                            print("PUPI: " + self.pupi)
                            print("ATR: " + self.atr)
                            print("UID: " + self.uid)
                            print("APPDATA: " + self.appdata)
                            print("PROTOCOL: " + self.protocol)
                            print("CID: " + self.cid)
                        return True
                    # else:
                    if self.DEBUG:
                        print("Error selecting card")
                    return False
                if cardtype == "ICLASS": # elif
                    result = self.nfc.selectICLASS()
                    if result:
                        self.uid = result.uid
                        if self.DEBUG:
                            print("ID: " + self.uid)
                        return True
                    # else:
                    if self.DEBUG:
                        print("Error selecting card")
                    return False
                elif cardtype == "JEWEL":
                    result = self.nfc.selectJEWEL()
                    if result:
                        self.btsensres = result.btSensRes
                        self.btid = result.btId
                        self.uid = result.uid
                        if self.DEBUG:
                            print("SENSRES: " + self.btsensres)
                            print("ID: " + self.btid)
                        return True
                    # else:
                    if self.DEBUG:
                        print("Error selecting card")
                    return False
                # else:
                if self.DEBUG:
                    print("Error: Unknown card type specified: %s" % cardtype)
                return False
            except ValueError:
                self.errorcode = "Error selecting card using LIBNFC" + e

############################################################################################
###########################################################################################



    def sendAPDU(self, apdu, timeout=None):
    #    apdu = [x for x in apdu]
    #    apdu = [str(x) for x in apdu]
        apdu = "".join(list(apdu))
        print(apdu)
        txData = []
        for i in range(0, len(apdu), 2):
            txData.append(int(apdu[i : i + 2], 16))

        txAPDU = ctypes.c_ubyte * len(txData)
        tx = txAPDU(*txData)

        rxAPDU = ctypes.c_ubyte * MAX_FRAME_LEN
        rx = rxAPDU()

        if rfidiotglobals.Debug:
            self.log.debug(
                "Sending %d byte APDU: %s"
                % (len(tx), "".join([f"{x:02x}" for x in tx]))
            )
        rxlen = self.libnfc.nfc_initiator_transceive_bytes(
            self.device,
            ctypes.byref(tx),
            ctypes.c_size_t(len(tx)),
            ctypes.byref(rx),
            ctypes.c_size_t(len(rx)),
            int(timeout * 1000) if timeout is not None else -1,
        )
        if rfidiotglobals.Debug:
            self.log.debug("APDU rxlen = " + str(rxlen))
        if rxlen < 0:
            self.libnfc.nfc_perror(self.device, "nfc_initiator_transceive_bytes")
            if rfidiotglobals.Debug:
                self.log.error("Error sending/receiving APDU")
            return False, rxlen
        # else:
        rxAPDU = "".join([f"{x:02x}" for x in rx[:rxlen]])
        print(rxAPDU)
        if rfidiotglobals.Debug:
            self.log.debug(f"Received {rxlen} byte APDU: {rxAPDU}")
        return True, rxAPDU.upper()


def target_is_present(self):
    ret = self.libnfc.nfc_initiator_tTraceback (most recent call last):Traceback (most recent call last):arget_is_present(self.device, self.tag[0])
    return ret == 0, ret


if __name__ == "__main__":Traceback (most recent call last):Traceback (most recent call last):
    n = NFC()
    n.powerOn()
    c = n.readISO14443A()
    print("UID: " + c.uid)Traceback (most recent call last):
    print("ATR: " + c.atr)
    print("ATQA: " + c.atqa)
    print("SAK: " + c.sak)

    cont = True
    while cont:
        apdu = input("enter the apdu to send now:")
        if apdu == "exit":
            cont = False
        else:
            r = n.sendAPDU(apdu)
            print(r)

    print("Ending now ...")
    n.deconfigure()


###########################################################################
#############################################################################


            # libnfc device
            elif self.readertype == self.READER_LIBNFC:
                print("self.READER_LIBNFC", self.READER_LIBNFC)  ## PMS
                self.nfc = pynfc.NFC(self.NFCReader)
                self.readername = self.nfc.LIBNFC_READER
            # Andoid reader
            elif self.readertype == self.READER_ANDROID:
                self.android = pyandroid.Android()
                self.readername = "Android"
            elif self.readertype == self.READER_NONE:
                self.readername = "none"
            else:


        if self.readertype == self.READER_LIBNFC:
            self.nfc.powerOff()
            self.nfc.powerOn()
        if self.readertype == self.READER_ANDROID:
            self.android.reset()


        if self.readertype == self.READER_LIBNFC:
            print("not implemented!")
            self.errorcode = "----"
            # raise RuntimeError ?
            # raise NotImplementedError("READ_BLOCK")
            return False
            apdu += self.PCSC_APDU["READ_BLOCK"]
            apdu = []
            apdu += "%02X" % pynfc.MC_READ  # mifare read
            hexblock = "%04x" % block
            apdu.append(hexblock)
            ret, self.errorcode = self.nfc.sendAPDU(apdu, self.timeout)
            if not ret:
                return False
            self.errorcode = self.ISO_OK
            return True

    ISOAPDU = {
        "ERASE BINARY": "0E",
        "VERIFY": "20",
        # Global Platform
        "INITIALIZE_UPDATE": "50",
        # GP end
        "MANAGE_CHANNEL": "70",
        "EXTERNAL_AUTHENTICATE": "82",
        "GET_CHALLENGE": "84",
        "INTERNAL_AUTHENTICATE": "88",
        "SELECT_FILE": "A4",
        # vonjeek start
        "VONJEEK_SELECT_FILE": "A5",
        "VONJEEK_UPDATE_BINARY": "A6",
        "VONJEEK_SET_MRZ": "A7",
        "VONJEEK_SET_BAC": "A8",
        "VONJEEK_SET_DATASET": "AA",
        # vonjeek end
        # special for JCOP
        "MIFARE_ACCESS": "AA",
        "ATR_HIST": "AB",
        "SET_RANDOM_UID": "AC",
        # JCOP end
        "READ_BINARY": "B0",
        "READ_RECORD(S)": "B2",
        "GET_RESPONSE": "C0",
        "ENVELOPE": "C2",
        "GET_DATA": "CA",
        "WRITE_BINARY": "D0",
        "WRITE_RECORD": "D2",
        "UPDATE_BINARY": "D6",
        "PUT_DATA": "DA",
        "UPDATE_DATA": "DC",
        "CREATE_FILE": "E0",
        "APPEND_RECORD": "E2",
        # Global Platform
        "GET_STATUS": "F2",
        # GP end
        "READ_BALANCE": "4C",
        "INIT_LOAD": "40",
        "LOAD_CMD": "42",
        "WRITE_MEMORY": "7A",
        "READ_MEMORY": "78",
    }
    # some control parameters
    ISO_7816_SELECT_BY_NAME = "04"
    ISO_7816_SELECT_BY_EF = "02"
    ISO_7816_OPTION_FIRST_OR_ONLY = "00"
    ISO_7816_OPTION_NEXT_OCCURRENCE = "02"



        cla = "84"
        ins = "EXTERNAL_AUTHENTICATE"
        p1 = "00"  # security level 0 - plaintext
        # p1= '01' # security level 1 - C-MAC
        p2 = "00"
        data = self.ToHex(host_cryptogram)
        lc = "10"  # needs to include MAC that will be added after mac generation
        mac = self.ToHex(self.DESMAC(self.ToBinary(cla + "82" + p1 + p2 + lc + data), mac_key, ""))
        data += mac
        return self.send_apdu("", "", "", "", cla, ins, p1, p2, lc, data, "")


def select_ppse():
    # try to select PSE
#   self
#   option
#   pcb
#   cid
#   nad
    cla = "00"
    ins = "A4"
    p1 = "04"
    p2 = "00"
#   lc = [len(ppse)]
    lc = "0E"
    data = "325041592E5359532E4444463031"
    le = "00"
#   apdu = SELECT + [len(DF_PPSE)] + DF_PPSE
    response, sw1, sw2 = send_apdu("", "", "", "", cla, ins, p1, p2, lc, data, le)

    if check_return(sw1,sw2):
        # there is a PSE
        print("PSE found!")
        decode_pse(response)
        status, response, sw1, sw2 = select_aid(aidlist[1][1:]) 
        status, length, pdol = get_tag(response,0x9F38)
        pdollist = list() 
        x = 0
        hexprint(pdol)     
        print(len(pdol)) 
        while x < (len(pdol)): 
            tagstart = x 
            x += 1
        if (pdol[x] & TLV_TAG_NUMBER_MASK) == TLV_TAG_NUMBER_MASK:
            x += 1
        while pdol[x] & TLV_TAG_MASK:
            x += 1
            x += 1
            taglen = x 
            tag = pdol[tagstart:taglen]  
            #tags = map(hex, tag)
            tags = ["{0:02X}".format(item) for item in tag]
            tags = ''.join(tags)
            tags = int(tags,16) 
            pdollist.append(tags) 
            x += 1
            get_processing_options(pdollist)
            get_UNSize() 
    else:
        print("no PSE: %02x %02x' % (sw1,sw2)")


##############################################################



    def send_apdu(self, option, pcb, cid, nad, cla, ins, p1, p2, lc, data, le) -> bool:
        "send iso-7816-4 apdu"
        if not option:
            option = "1f"
            # option= '00'
        if not pcb:
            pcb = "02"
        if not cla:
            cla = "00"
        if not p1:
            p1 = "00"
        if not p2:
            p2 = "00"
        try:
            ins = self.ISOAPDU[ins]
        except:
            pass
        if self.readertype == self.READER_PCSC:
            return self.pcsc_send_apdu(cla + ins + p1 + p2 + lc + data + le)
        if self.readertype == self.READER_LIBNFC:
            if self.DEBUG:
                print("In send_apdu - for libnfc:", cla + ins + p1 + p2 + lc + data + le)
            ret, result = self.nfc.sendAPDU(cla + ins + p1 + p2 + lc + data + le, self.timeout)
            if not ret:
                self.errorcode = "PN00"
                return False
            self.data = result[0:-4]
            self.errorcode = result[len(result) - 4 : len(result)]
            if self.errorcode != self.ISO_OK:
                return False
            return True
        if self.readertype == self.READER_ANDROID:
            result = self.android.sendAPDU(cla + ins + p1 + p2 + lc + data + le)
            self.data = result[0:-4]
            self.errorcode = result[len(result) - 4 : len(result)]
            if self.errorcode == self.ISO_OK:
                return True
            return False
            dlength = 5
        command = pcb + cla + ins + p1 + p2 + lc + data + le
        dlength += len(data) / 2
        dlength += len(lc) / 2
        dlength += len(le) / 2
        if self.DEBUG:
            print("sending: " + "t" + "%02x" % dlength + option + command)
        self.ser.write("t" + "%02x" % dlength + option + command)
        # need check for 'le' length as well
        ret = self.ser.readline()[:-2]
        if self.DEBUG:
            print("received:", ret)
        self.errorcode = ret[len(ret) - 4 : len(ret)]
        # copy data if more than just an error code (JCOP sometimes returns an error with data)
        if len(ret) > 8:
            self.data = ret[4 : len(ret) - 4]
        else:
            self.data = ""
        if self.errorcode == self.ISO_OK:
            return True
        return False

      if self.readertype == self.READER_LIBNFC:
            print("not implemented!")
            self.errorcode = "----"
            # raise RuntimeError ?
            # raise NotImplementedError("READ_BLOCK")
            return False
            apdu += self.PCSC_APDU["READ_BLOCK"]
            apdu = []
            apdu += "%02X" % pynfc.MC_READ  # mifare read
            hexblock = "%04x" % block
            apdu.append(hexblock)
            ret, self.errorcode = self.nfc.sendAPDU(apdu, self.timeout)
            if not ret:
                return False
            self.errorcode = self.ISO_OK
            return True


##########################################################

    def acs_send_apdu(self, apdu) -> bool:
        "ACS send APDU to contacless card"
        myapdu = self.HexArraysToArray(apdu)
        # determine if this is for direct transmission to the card
        if myapdu[0] == "d4":
            # build pseudo command for ACS contactless interface
            lc = "%02x" % len(myapdu)
            apduout = self.HexArrayToList(self.PCSC_APDU["ACS_DIRECT_TRANSMIT"] + [lc] + myapdu)
        else:
            if myapdu[0] in ["ff", "80"]:
                apduout = self.HexArrayToList(myapdu)
            else:
                # build pseudo command for ACS 14443-A
                lc = "%02x" % (len(myapdu) + len(self.PCSC_APDU["ACS_14443_A"]))
                apduout = self.HexArrayToList(self.PCSC_APDU["ACS_DIRECT_TRANSMIT"] + [lc] + self.PCSC_APDU["ACS_14443_A"] + myapdu)
        result, sw1, sw2 = self.acs_transmit_apdu(apduout)
        self.errorcode = "%02X%02X" % (sw1, sw2)
        if self.errorcode == self.ISO_OK:
             
    data = self.ToHex(host_cryptogram)

#########################################################3

get sam serial -
get sam id - 
reset - 
get firmware id - 
poll mifare - # of tags avail
firmware rev - 
power on - 
power off


def libnfc_mifare_login(self, block, key, keytype) -> bool:
    return false or True

 def libnfc_mifare_read_block(self, block) -> bool:

####################################################################################################
####################################################################################################
ISO-7816 FUNCTIONS
####################################################################################################
####################################################################################################

    # ISO 7816 commands
    def iso_7816_external_authenticate(self, response, key) -> bool:
        "7816 external authenticate"
        ins = "EXTERNAL_AUTHENTICATE"
        lc = le = "%02x" % (len(response) / 2)
        if self.send_apdu("", "", "", "", "", ins, "", "", lc, response, le):
            if self.MACVerify(self.data, key):
                return True
        return False

    def iso_7816_fail(self, code) -> None:
        "print 7816 failure code and exit"
        if code == self.ACG_FAIL:
            print("Application not implemented!")
            sys.exit(True)
        print("Failed - reason code " + code + " (" + self.ISO7816ErrorCodes[code] + ")")
        print()
        sys.exit(True)

    def iso_7816_get_challenge(self, length) -> bool:
        "get random challenge - challenge will be in .data"
        ins = "GET_CHALLENGE"
        le = "%02x" % length
        if self.DEBUG:
            print("DEBUG: requesting %d byte challenge" % length)
        return self.send_apdu("", "", "", "", "", ins, "", "", "", "", le)

    def iso_7816_read_binary(self, d_bytes, offset) -> bool:
        "7816 read binary - data read will be in .data"
        ins = "READ_BINARY"
        hexoffset = "%04x" % offset
        p1 = hexoffset[0:2]
        p2 = hexoffset[2:4]
        le = "%02x" % d_bytes
        return self.send_apdu("", "", "", "", "", ins, p1, p2, "", "", le)

    def iso_7816_select_file(self, file, control, options) -> bool:
        "7816 select file"
        ins = "SELECT_FILE"
        lc = "%02x" % (int) (len(file) / 2)
        p1 = control
        p2 = options
        data = file
        return self.send_apdu("", "", "", "", "", ins, p1, p2, lc, data, "")

####################################################################################################
####################################################################################################

SEND_APDU

####################################################################################################
####################################################################################################

    def send_apdu(self, option, pcb, cid, nad, cla, ins, p1, p2, lc, data, le) -> bool:
        "send iso-7816-4 apdu"
        if not option:
            option = "1f"
            # option= '00'
        if not pcb:
            pcb = "02"
        if not cla:
            cla = "00"
        if not p1:
            p1 = "00"
        if not p2:
            p2 = "00"
        try:
            ins = self.ISOAPDU[ins]
        except:
            pass
        if self.readertype == self.READER_PCSC:
            return self.pcsc_send_apdu(cla + ins + p1 + p2 + lc + data + le)
        if self.readertype == self.READER_LIBNFC:
            if self.DEBUG:
                print("In send_apdu - for libnfc:", cla + ins + p1 + p2 + lc + data + le)
            ret, result = self.nfc.sendAPDU(cla + ins + p1 + p2 + lc + data + le, self.timeout)
            if not ret:
                self.errorcode = "PN00"
                return False
            self.data = result[0:-4]
            self.errorcode = result[len(result) - 4 : len(result)]
            if self.errorcode != self.ISO_OK:
                return False
            return True
        if self.readertype == self.READER_ANDROID:
            result = self.android.sendAPDU(cla + ins + p1 + p2 + lc + data + le)
            self.data = result[0:-4]
            self.errorcode = result[len(result) - 4 : len(result)]
            if self.errorcode == self.ISO_OK:
                return True
            return False
            dlength = 5
        command = pcb + cla + ins + p1 + p2 + lc + data + le
        dlength += len(data) / 2
        dlength += len(lc) / 2
        dlength += len(le) / 2
        if self.DEBUG:
            print("sending: " + "t" + "%02x" % dlength + option + command)
        self.ser.write("t" + "%02x" % dlength + option + command)
        # need check for 'le' length as well
        ret = self.ser.readline()[:-2]
        if self.DEBUG:
            print("received:", ret)
        self.errorcode = ret[len(ret) - 4 : len(ret)]
        # copy data if more than just an error code (JCOP sometimes returns an error with data)
        if len(ret) > 8:
            self.data = ret[4 : len(ret) - 4]
        else:
            self.data = ""
        if self.errorcode == self.ISO_OK:
            return True
        return False


####################################################################################################
####################################################################################################
HEX FUNC
####################################################################################################
####################################################################################################


  apdu.append(hexblock[0:2])  # p1
            apdu.append(hexblock[2:4])  # p2
            apdu.append("%02x" % (len(data) / 2))  # le
            apdu.append(data)




    @staticmethod
    def ToHex(data) -> str:
        "convert binary data to hex printable"
        # '\x01\x03\x07\x0F\x1F\x3F\x7F\xFF' -> '0103070f1f3f7fff'"
        if isinstance(data, str):
            data = bytes(data, encoding='latin-1')
        return data.hex()
        # string = ""
        # for x in range(len(data)):
        #     string += "%02x" % ord(data[x])
        # return string

    @staticmethod
    def HexPrint(data) -> None:
        print(rfidiot.ToHex(data))


    @staticmethod
    def ToHex(data) -> str:
        "convert binary data to hex printable"
        # '\x01\x03\x07\x0F\x1F\x3F\x7F\xFF' -> '0103070f1f3f7fff'"
        if isinstance(data, str):
            data = bytes(data, encoding='latin-1')
        return data.hex()
        # string = ""
        # for x in range(len(data)):
        #     string += "%02x" % ord(data[x])
        # return string

    @staticmethod
    def HexPrint(data) -> None:
        print(rfidiot.ToHex(data))

    @staticmethod
    def _ReadablePrint(text) -> str:
        return ''.join([i if i in string.printable else "." for i in text])

    # https://stackoverflow.com/questions/8689795/how-can-i-remove-non-ascii-characters-but-leave-periods-and-spaces ??
    @staticmethod
    def ReadablePrint(data) -> str:
        if isinstance(data, bytes):
            data = data.decode('latin-1')  # Special case
        return ''.join([i if i >= " " and i <= "~"  else "." for i in data])

    @staticmethod
    def ListToHex(data) -> str:
        return ''.join(f"{x:02X}" for x in data)
        # string = ""
        # for d in data:
        #     string += "%02X" % d
        # return string

    @staticmethod
    def HexArrayToString(array) -> str:
        # translate array of strings to single string
        # ['DE', 'AD', 'BE', 'EF'] => 'DEADBEEF' 
        return ''.join(array)
        # out = ""
        # for n in array:
        #     out += n
        # return out

    @staticmethod
    def HexArraysToArray(array) -> list:
        # translate an array of strings to an array of 2 character strings
        # "DEADBEEF" => ['DE', 'AD', 'BE', 'EF']
        temp = rfidiot.HexArrayToString(array)
        return [temp[i:i+2] for i in range(0, len(temp), 2)]

    @staticmethod
    def HexArrayToList(array) -> list:
        # translate array of 2 char HEX to int list
        #  ["DE", "AD", "BE", "EF"] => [222, 173, 190, 239]
        # first make sure we're dealing with a single array
        source = rfidiot.HexArraysToArray(array)
        return [int(n, 16) for n in source]
        # out = []
        # for n in source:
        #     out.append(int(n, 16))
        # return out

    @staticmethod
    def HexToList(string) -> list:
        # translate string of 2 char HEX to int list
        # 'DEADBEEF' => [222, 173, 190, 239]
        return list(bytearray.fromhex(string))
        # n = 0
        # out = []
        # while n < len(string):
        #     out.append(int(string[n : n + 2], 16))
        #     n += 2
        # return out

    @staticmethod
    def ToBinary(string) -> str:
        "convert hex string to binary characters"
        #   '0103070f1f3f7fff' -> b'\x01\x03\x07\x0F\x1F\x3F\x7F\xFF'
        return bytearray.fromhex(string)
        # x = 0
        # while x < len(string):
        #     output += chr(int(string[x : x + 2], 16))
        #     x += 2
        # return output

    # temp save
    def _BinaryPrint(self, data) -> None:
        "print binary representation"
        print(self.ToBinaryString(data))

    @staticmethod
    def BinaryPrint(data) -> None:
        "print binary representation"
        print(rfidiot.ToBinaryString(data))

    @staticmethod
    def ToBinaryString(data) -> str:
        "convert binary data to printable binary ('01101011')"
        # '\x01\x03\x07' => '000000010000001100000111'
        if isinstance(data, str):
            data = bytes(data, encoding='latin-1')
        return ''.join(f'{b:08b}' for b in data)
        #output = ""
        #for b in bytearray(data,  encoding='latin-1'):
        #    # output += bin(b)[2:].zfill(8) # .removepreffix('0b')
        #    output += '{:08b}'.format(b)
        #return output
        # output = ""
        # string = self.ToHex(data)
        # for x in range(0, len(string), 2):
        #     for y in range(7, -1, -1):
        #         output += "%s" % (int(string[x : x + 2], 16) >> y & 1)
        # return output


################################################################################
################################################################################

