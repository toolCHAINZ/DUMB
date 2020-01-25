from binaryninja import Architecture, BinaryReader, BinaryView
from binaryninja.enums import SectionSemantics, SegmentFlag


class DumbView(BinaryView):
    """
    This is our custom Binary View.
    """
    name = 'DUMB File'

    @classmethod
    def is_valid_for_data(cls, data):
        """
        This function tells Binja whether to use this view for a given file
        """
        if data[0:4] == b'DUMB':
            return True
        return False

    def __init__(self, data):
        """
        Once our view is selected, this method is called to actually create it.
        :param data: the file data
        """
        BinaryView.__init__(self, file_metadata=data.file, parent_view=data)
        self.platform = Architecture['DUMB'].standalone_platform

        self.parse_format(data)

    def parse_format(self, data):
        """
        This is a helper function to parse our BS format
        :param data:
        :return:
        """
        reader = BinaryReader(data)
        reader.seek(4)
        loading_addr = reader.read32()
        flags = SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
        self.add_auto_segment(loading_addr, len(data) - 8, 8, len(data) - 8, flags)
        self.add_auto_section("text", loading_addr, len(data) - 8,
                              SectionSemantics.ReadOnlyCodeSectionSemantics)

        self.add_entry_point(loading_addr)
