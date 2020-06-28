import socket
import time
from Reporting_Unit import ReportingUnit, REPORT_FILE

MS_IN_SEC = 1000
DLC_LEN = 4
ID_LEN = 11
BITS_RIGHT_TO_DATA = 25
MIN_MS_PERIOD = 50
MAX_MS_PERIOD = 100
BYTE_LEN = 8
MAX_DATA_BYTES = 8
MSG_LEN_BYTES = 16
MAX_PACKET_LEN = 108
DLC_MASK = (2 ** DLC_LEN) - 1
ID_MASK = (2 ** ID_LEN) - 1
DATA_MASK = (2 ** BYTE_LEN) - 1
NUM_OF_BITS_LEFT_TO_DLC = 15
NUM_OF_BITS_LEFT_TO_ID = 1
THIRD_IDENTIFIER = 0x300
SECOND_IDENTIFIER = 0x200
FIRST_IDENTIFIER = 0x100

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432  # Port to listen on (non-privileged ports are > 1023)


def find_first_set_bit(num):
    """
    find the most significant bit of num
    :param num: num to check
    :return: most significant bit index, as the rightmost is 1
    """
    index = 0
    while num != 0:
        index += 1
        num >>= 1
    return index


class DetectionUnit:
    """
    receives CAN traffic from the generator unit, and classifies it as valid or invalid
    """

    def __init__(self):
        """
        Constructor - Initiate server and reporting unit
        """
        self.last_packet_arriving_time = {FIRST_IDENTIFIER: 0, SECOND_IDENTIFIER: 0, THIRD_IDENTIFIER: 0}
        self.last_packet_dlc = {FIRST_IDENTIFIER: 0, SECOND_IDENTIFIER: 0, THIRD_IDENTIFIER: 0}
        self.last_packet_data = {FIRST_IDENTIFIER: True, SECOND_IDENTIFIER: True, THIRD_IDENTIFIER: True}
        self.is_first_id = {FIRST_IDENTIFIER: True, SECOND_IDENTIFIER: True, THIRD_IDENTIFIER: True}
        self.last_packet_time_stamp = None
        self.reporter = ReportingUnit()
        self.receive_traffic()

    def receive_traffic(self):
        """
        initiate server, receive packets and report
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            conn, addr = s.accept()
            print('Generation unit began transmitting - ' + str(time.time()))

            with conn:
                while True:
                    data = conn.recv(MSG_LEN_BYTES)
                    if not data:
                        break
                    time_stamp = time.time()
                    if self.last_packet_time_stamp:
                        assert MIN_MS_PERIOD * 0.98 / MS_IN_SEC < (
                                time_stamp - self.last_packet_time_stamp) < MAX_MS_PERIOD * 1.02 / MS_IN_SEC
                    packet = int.from_bytes(data, byteorder='big')
                    try:
                        classification = self.classify_traffic(packet, time_stamp)
                    except AssertionError:
                        print('Fault Packet Format')
                    self.reporter.report(time_stamp, packet, classification)

        self.reporter.close_file()
        print('Generation unit stopped transmitting - ' + str(time.time()))
        print('Created Report - ' + REPORT_FILE)

    def classify_traffic(self, packet, time_stamp):
        """
        classify the packets according to the 3 different parameters determined
        :param packet: CAN data frame as int
        :param time_stamp: packet arrival time
        :return: Classification dictionary regarding the 3 different tests - rat,length & data
        """
        leftmost_bit_index = find_first_set_bit(packet)
        assert leftmost_bit_index in [MAX_PACKET_LEN - BYTE_LEN * i for i in range(MAX_DATA_BYTES + 1)]

        bits_right_to_dlc = leftmost_bit_index - NUM_OF_BITS_LEFT_TO_DLC - DLC_LEN
        packet_dlc = (packet & (DLC_MASK << bits_right_to_dlc)) >> bits_right_to_dlc
        assert packet_dlc <= MAX_DATA_BYTES

        bits_right_to_id = leftmost_bit_index - (NUM_OF_BITS_LEFT_TO_ID + ID_LEN)
        packet_id = (packet & (ID_MASK << bits_right_to_id)) >> bits_right_to_id
        assert packet_id in [FIRST_IDENTIFIER, SECOND_IDENTIFIER, THIRD_IDENTIFIER]

        packet_data = []
        packet >>= BITS_RIGHT_TO_DATA
        for _ in range(packet_dlc):
            packet_data.append(packet & DATA_MASK)
            packet >>= BYTE_LEN

        classification = {'Rate': self.rate_check(packet_id, time_stamp), 'Length': self.length_check(packet_id,
                                                                                                      packet_dlc),
                          'Data': self.data_check(
                              packet_id, packet_data)}

        if self.is_first_id[packet_id]:
            self.is_first_id[packet_id] = False
        return classification

    def rate_check(self, packet_id, time_stamp):
        """
        Perform rate check test
        :param packet_id: frame identifier as int
        :param time_stamp: packet arrival time
        :return: Valid or not according to Rate test
        """
        time_diff = time_stamp - self.last_packet_arriving_time[packet_id]
        if self.is_first_id[packet_id] or time_diff > MAX_MS_PERIOD / MS_IN_SEC:
            self.last_packet_arriving_time[packet_id] = time_stamp
            return True
        self.last_packet_arriving_time[packet_id] = time_stamp
        return False

    def length_check(self, packet_id, packet_dlc):
        """
        Perform length check test
        :param packet_id: frame identifier as int
        :param packet_dlc: frame DLC
        :return: Valid or not according to Length test
        """
        prev_len = self.last_packet_dlc[packet_id]
        if self.is_first_id[packet_id] or packet_dlc != prev_len:
            self.last_packet_dlc[packet_id] = packet_dlc
            return True
        return False

    def data_check(self, packet_id, data):
        """
        Perform Data check test
        :param packet_id: frame identifier as int
        :param data: frame data bytes
        :return: Valid or not according to Data test
        """
        data_valid = True
        if self.is_first_id[packet_id]:
            self.last_packet_data[packet_id] = data
            return True
        for byte in data:
            if byte in self.last_packet_data[packet_id]:
                data_valid = False
                break
        self.last_packet_data[packet_id] = data
        return data_valid


if __name__ == '__main__':
    DetectionUnit()
