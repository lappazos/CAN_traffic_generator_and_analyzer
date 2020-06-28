REPORT_FILE = "CAN Traffic Report.txt"
NEW_LINE = '\n'


class ReportingUnit:
    """
    Receives input from the detection unit and writes the following fields (comma-separated) to a log file for
    each entry (entry = CAN frame)
    """

    def __init__(self):
        """
        Constructor - open log file
        """
        try:
            self.file = open(REPORT_FILE, 'w')
        except OSError:
            print('Problem opening log file')
            exit(1)

    def write_to_file(self, line):
        """
        write a single line to the log file
        :param line: line to write
        """
        self.file.write(line)
        self.file.write(NEW_LINE)

    def close_file(self):
        """
        close the og file
        """
        self.file.close()

    def report(self, timestamp, frame, valid_dict):
        """
        report a specific data frame to the log file
        :param timestamp: frame arrival time to detection unit
        :param frame: the data frame itself as int
        :param valid_dict: is valid according to each of the 3 tests
        """
        is_valid = True
        invalid_reason = None
        for check in valid_dict:
            if not valid_dict[check]:
                is_valid = False
                invalid_reason = check
        if is_valid:
            line = "{:f},0x{:x},Valid".format(timestamp, frame)
            self.write_to_file(line)
        else:
            self.write_to_file("{:f},0x{:x},Invalid,{:s}".format(timestamp, frame, invalid_reason))
