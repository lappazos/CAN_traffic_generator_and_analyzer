import socket
import random
from time import sleep
import Detection_Unit


class GeneratorUnit:
    """
    generate random traffic of CAN messages
    """

    def __init__(self):
        """
        Constructor - Initiate traffic
        """
        try:
            self.send_packets()
        except KeyboardInterrupt:
            print('Transmission ended - Keyboard interrupt')

    def send_packets(self):
        """
        Initiate connection to server, and send CAN frames repeatably, with random time gap between them
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((Detection_Unit.HOST, Detection_Unit.PORT))
            while True:
                num_of_ms = random.randint(Detection_Unit.MIN_MS_PERIOD, Detection_Unit.MAX_MS_PERIOD)
                sleep(num_of_ms / Detection_Unit.MS_IN_SEC)
                data = (self.create_data_frame()).to_bytes(Detection_Unit.MSG_LEN_BYTES, byteorder='big')
                s.sendall(data)

    @staticmethod
    def create_data_frame():
        """
        randomize CAN data frames according to the rules determined
        :return: CAN data frame as int
        """
        # SOF
        frame = 1
        # first bit of identifier
        frame <<= 1
        # second bit of identifier
        frame <<= 1
        second_bit = random.getrandbits(1)
        frame += second_bit
        # third bit of identifier
        frame <<= 1
        if second_bit:
            frame += random.getrandbits(1)
        else:
            frame += 1
        # rest of identifier
        frame <<= Detection_Unit.ID_LEN - 3
        # RTR + IDE + r
        frame <<= 3
        frame += 0b111
        # data field
        num_of_data_bytes = random.randint(0, Detection_Unit.MAX_DATA_BYTES)
        # DLC
        frame <<= Detection_Unit.DLC_LEN
        frame += num_of_data_bytes
        for _ in range(num_of_data_bytes):
            frame <<= Detection_Unit.BYTE_LEN
            rand_byte = random.randint(0, (2 ** Detection_Unit.BYTE_LEN) - 1)
            frame += rand_byte
        # checksum + DEL + ACK + DEL + EOF
        frame <<= Detection_Unit.BITS_RIGHT_TO_DATA
        frame += (2 ^ Detection_Unit.BITS_RIGHT_TO_DATA) - 1
        return frame


if __name__ == '__main__':
    GeneratorUnit()
