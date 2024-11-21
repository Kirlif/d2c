from struct import unpack, pack


# Print arg into a correct format
def _Print(name, arg):
    buff = name + " "

    if type(arg).__name__ == 'int':
        buff += "0x%x" % arg
    elif type(arg).__name__ == 'long':
        buff += "0x%x" % arg
    elif type(arg).__name__ == 'str':
        buff += "%s" % arg
    elif isinstance(arg, SV):
        buff += "0x%x" % arg.get_value()
    print(buff)

class SV(object):

    def __init__(self, size, buff):
        self.__size = size
        self.__value = unpack(self.__size, buff)[0]

    def _get(self):
        return pack(self.__size, self.__value)

    def __str__(self):
        return "0x%x" % self.__value

    def __int__(self):
        return self.__value

    def get_value_buff(self):
        return self._get()

    def get_value(self):
        return self.__value

    def set_value(self, attr):
        self.__value = attr

def object_to_bytes(obj):
    """
    Convert a object to a bytearray or call get_raw() of the object
    if no useful type was found.
    """
    if isinstance(obj, str):
        return bytearray(obj, "UTF-8")
    elif isinstance(obj, bool):
        return bytearray()
    elif isinstance(obj, int):
        return pack("<L", obj)
    elif obj is None:
        return bytearray()
    elif isinstance(obj, bytearray):
        return obj
    else:
        return obj.get_raw()

class BuffHandle(object):
    """
    BuffHandle is a wrapper around bytes.
    It gives the ability to jump in the byte stream, just like with BytesIO.
    """

    def __init__(self, buff):
        self.__buff = bytearray(buff)
        self.__idx = 0

    def __getitem__(self, item):
        """
        Get the byte at the position `item`

        :param int item: offset in the buffer
        :returns: byte at the position
        :rtype: int
        """
        return self.__buff[item]

    def __len__(self):
        return self.size()

    def size(self):
        """
        Get the total size of the buffer

        :rtype: int
        """
        return len(self.__buff)

    def length_buff(self):
        """
        Alias for :meth:`size`
        """
        return self.size()

    def set_idx(self, idx):
        """
        Set the current offset in the buffer

        :param int idx: offset to set
        """
        self.__idx = idx

    def get_idx(self):
        """
        Get the current offset in the buffer

        :rtype: int
        """
        return self.__idx

    def add_idx(self, idx):
        """
        Advance the current offset by `idx`

        :param int idx: number of bytes to advance
        """
        self.__idx += idx

    def tell(self):
        """
        Alias for :meth:`get_idx`.

        :rtype: int
        """
        return self.__idx

    def readNullString(self, size):
        """
        Read a String with length `size` at the current offset

        :param int size: length of the string
        :rtype: bytearray
        """
        data = self.read(size)
        return data

    def read_b(self, size):
        """
        Read bytes with length `size` without incrementing the current offset

        :param int size: length to read in bytes
        :rtype: bytearray
        """
        return self.__buff[self.__idx:self.__idx + size]

    def peek(self, size):
        """
        Alias for :meth:`read_b`
        """
        return self.read_b(size)

    def read_at(self, offset, size):
        """
        Read bytes from the given offset with length `size` without incrementing
        the current offset

        :param int offset: offset to start reading
        :param int size: length of bytes to read
        :rtype: bytearray
        """
        return self.__buff[offset:offset + size]

    def readat(self, off):
        """
        Read all bytes from the start of `off` until the end of the buffer

        :param int off: starting offset
        :rtype: bytearray
        """
        if isinstance(off, SV):
            off = off.value

        return self.__buff[off:]

    def read(self, size):
        """
        Read from the current offset a total number of `size` bytes
        and increment the offset by `size`

        :param int size: length of bytes to read
        :rtype: bytearray
        """
        if isinstance(size, SV):
            size = size.value

        buff = self.__buff[self.__idx:self.__idx + size]
        self.__idx += size

        return buff

    def end(self):
        """
        Test if the current offset is at the end or over the buffer boundary

        :rtype: bool
        """
        return self.__idx >= len(self.__buff)

    def get_buff(self):
        """
        Return the whole buffer

        :rtype: bytearray
        """
        return self.__buff

    def set_buff(self, buff):
        """
        Overwrite the current buffer with the content of `buff`

        :param bytearray buff: the new buffer
        """
        self.__buff = buff



class Buff(object):
    def __init__(self, offset, buff):
        self.offset = offset
        self.buff = buff

        self.size = len(buff)


# Here for legacy reasons. Might get removed some day...
_Bytecode = BuffHandle


class Node(object):
    def __init__(self, n, s):
        self.id = n
        self.title = s
        self.children = []

