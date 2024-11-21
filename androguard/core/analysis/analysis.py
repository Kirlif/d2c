import re
import warnings
from androguard.core.bytecodes import dvm
import logging

log = logging.getLogger("androguard.analysis")

BasicOPCODES = []
for i in dvm.BRANCH_DVM_OPCODES:
    BasicOPCODES.append(re.compile(i))


class DVMBasicBlock:
    """
        A simple basic block of a dalvik method
    """

    def __init__(self, start, vm, method, context):
        self.__vm = vm
        self.method = method
        self.context = context

        self.last_length = 0
        self.nb_instructions = 0

        self.fathers = []
        self.childs = []

        self.start = start
        self.end = self.start

        self.special_ins = {}

        self.name = "%s-BB@0x%x" % (self.method.get_name(), self.start)
        self.exception_analysis = None

        self.__cached_instructions = None

    def get_instructions(self):
        """
        Get all instructions from a basic block.

        :rtype: Return all instructions in the current basic block
        """
        tmp_ins = []
        idx = 0
        for i in self.method.get_instructions():
            if self.start <= idx < self.end:
                yield i
            idx += i.get_length()

    def get_nb_instructions(self):
        return self.nb_instructions

    def get_name(self):
        return "%s-BB@0x%x" % (self.method.get_name(), self.start)

    def get_start(self):
        return self.start

    def get_end(self):
        return self.end

    def get_last(self):
        return self.get_instructions()[-1]

    def get_next(self):
        """
            Get next basic blocks

            :rtype: a list of the next basic blocks
        """
        return self.childs

    def get_prev(self):
        """
            Get previous basic blocks

            :rtype: a list of the previous basic blocks
        """
        return self.fathers

    def set_fathers(self, f):
        self.fathers.append(f)

    def get_last_length(self):
        return self.last_length

    def set_childs(self, values):
        # print self, self.start, self.end, values
        if not values:
            next_block = self.context.get_basic_block(self.end + 1)
            if next_block is not None:
                self.childs.append((self.end - self.get_last_length(), self.end,
                                    next_block))
        else:
            for i in values:
                if i != -1:
                    next_block = self.context.get_basic_block(i)
                    if next_block is not None:
                        self.childs.append((self.end - self.get_last_length(),
                                            i, next_block))

        for c in self.childs:
            if c[2] is not None:
                c[2].set_fathers((c[1], c[0], self))

    def push(self, i):
        self.nb_instructions += 1
        idx = self.end
        self.last_length = i.get_length()
        self.end += self.last_length

        op_value = i.get_op_value()

        if op_value == 0x26 or (0x2b <= op_value <= 0x2c):
            code = self.method.get_code().get_bc()
            self.special_ins[idx] = code.get_ins_off(idx + i.get_ref_off() * 2)

    def get_special_ins(self, idx):
        """
            Return the associated instruction to a specific instruction (for example a packed/sparse switch)

            :param idx: the index of the instruction

            :rtype: None or an Instruction
        """
        if idx in self.special_ins:
            return self.special_ins[idx]
        else:
            return None

    def get_exception_analysis(self):
        return self.exception_analysis

    def set_exception_analysis(self, exception_analysis):
        self.exception_analysis = exception_analysis

class BasicBlocks:
    """
        This class represents all basic blocks of a method
    """

    def __init__(self, _vm):
        self.__vm = _vm
        self.bb = []

    def push(self, bb):
        self.bb.append(bb)

    def pop(self, idx):
        return self.bb.pop(idx)

    def get_basic_block(self, idx):
        for i in self.bb:
            if i.get_start() <= idx < i.get_end():
                return i
        return None

    def get(self):
        """
            :rtype: return each basic block (:class:`DVMBasicBlock` object)
        """
        for i in self.bb:
            yield i

    def gets(self):
        """
            :rtype: a list of basic blocks (:class:`DVMBasicBlock` objects)
        """
        return self.bb

    def get_basic_block_pos(self, idx):
        return self.bb[idx]


class ExceptionAnalysis:
    def __init__(self, exception, bb):
        self.start = exception[0]
        self.end = exception[1]

        self.exceptions = exception[2:]

        for i in self.exceptions:
            i.append(bb.get_basic_block(i[1]))

    def show_buff(self):
        buff = "%x:%x\n" % (self.start, self.end)

        for i in self.exceptions:
            if i[2] is None:
                buff += "\t(%s -> %x %s)\n" % (i[0], i[1], i[2])
            else:
                buff += "\t(%s -> %x %s)\n" % (i[0], i[1], i[2].get_name())

        return buff[:-1]

    def get(self):
        d = {"start": self.start, "end": self.end, "list": []}

        for i in self.exceptions:
            d["list"].append({"name": i[0], "idx": i[1], "bb": i[2].get_name()})

        return d


class Exceptions:
    def __init__(self, _vm):
        self.__vm = _vm
        self.exceptions = []

    def add(self, exceptions, basic_blocks):
        for i in exceptions:
            self.exceptions.append(ExceptionAnalysis(i, basic_blocks))

    def get_exception(self, addr_start, addr_end):
        for i in self.exceptions:
            if i.start >= addr_start and i.end <= addr_end:
                return i

            elif addr_end <= i.end and addr_start >= i.start:
                return i

        return None

    def gets(self):
        return self.exceptions

    def get(self):
        for i in self.exceptions:
            yield i


class MethodAnalysis:
    def __init__(self, vm, method):
        """
        This class analyses in details a method of a class/dex file
        It is a wrapper around a :class:`EncodedMethod` and enhances it
        by using multiple :class:`BasicBlock`.

        :type vm: a :class:`DalvikVMFormat` object
        :type method: a :class:`EncodedMethod` object
        """
        self.__vm = vm
        self.method = method

        self.basic_blocks = BasicBlocks(self.__vm)
        self.exceptions = Exceptions(self.__vm)

        self.code = self.method.get_code()
        if self.code:
            self._create_basic_block()

    def _create_basic_block(self):
        current_basic = DVMBasicBlock(0, self.__vm, self.method, self.basic_blocks)
        self.basic_blocks.push(current_basic)

        bc = self.code.get_bc()
        l = []
        h = {}
        idx = 0

        log.debug("Parsing instructions")
        for i in bc.get_instructions():
            for j in BasicOPCODES:
                if j.match(i.get_name()) is not None:
                    v = dvm.determineNext(i, idx, self.method)
                    h[idx] = v
                    l.extend(v)
                    break

            idx += i.get_length()

        log.debug("Parsing exceptions")
        excepts = dvm.determineException(self.__vm, self.method)
        for i in excepts:
            l.extend([i[0]])
            for handler in i[2:]:
                l.append(handler[1])

        log.debug("Creating basic blocks in %s" % self.method)
        idx = 0
        for i in bc.get_instructions():
            # index is a destination
            if idx in l:
                if current_basic.get_nb_instructions() != 0:
                    current_basic = DVMBasicBlock(current_basic.get_end(), self.__vm, self.method, self.basic_blocks)
                    self.basic_blocks.push(current_basic)

            current_basic.push(i)

            # index is a branch instruction
            if idx in h:
                current_basic = DVMBasicBlock(current_basic.get_end(), self.__vm, self.method, self.basic_blocks)
                self.basic_blocks.push(current_basic)

            idx += i.get_length()

        if current_basic.get_nb_instructions() == 0:
            self.basic_blocks.pop(-1)

        log.debug("Settings basic blocks childs")

        for i in self.basic_blocks.get():
            try:
                i.set_childs(h[i.end - i.get_last_length()])
            except KeyError:
                i.set_childs([])

        log.debug("Creating exceptions")

        # Create exceptions
        self.exceptions.add(excepts, self.basic_blocks)

        for i in self.basic_blocks.get():
            # setup exception by basic block
            i.set_exception_analysis(self.exceptions.get_exception(i.start, i.end - 1))

    def get_basic_blocks(self):
        """
            :rtype: a :class:`BasicBlocks` object
        """
        return self.basic_blocks

    def get_length(self):
        """
            :rtype: an integer which is the length of the code
        """
        return self.code.get_length() if self.code else 0

    def get_method(self):
        return self.method

    def get_vm(self):
        return self.__vm

class MethodClassAnalysis:
    def __init__(self, method):
        """
        MethodClassAnalysis contains the XREFs for a given method.

        Both referneces to other methods (XREF_TO) as well as methods calling
        this method (XREF_FROM) are saved.

        :param androguard.core.bytecodes.dvm.EncodedMethod method: the DVM Method object
        """
        self.method = method


    @property
    def name(self):
        """Returns the name of this method"""
        return self.method.get_name()

    @property
    def descriptor(self):
        """Returns the type descriptor for this method"""
        return self.method.get_descriptor()

    @property
    def access(self):
        """Returns the access flags to the method as a string"""
        return self.method.get_access_flags_string()


class FieldClassAnalysis:
    def __init__(self, field):
        """
        FieldClassAnalysis contains the XREFs for a class field.

        Instead of using XREF_FROM/XREF_TO, this object has methods for READ and
        WRITE access to the field.

        That means, that it will show you, where the field is read or written.

        :param androguard.core.bytecodes.dvm.EncodedField field: `dvm.EncodedField`
        """
        self.field = field

    @property
    def name(self):
        return self.field.get_name()

class ClassAnalysis:
    def __init__(self, classobj):
        """
        It is also used to wrap :class:`~androguard.core.bytecode.dvm.ClassDefItem`, which
        contain the actual class content like bytecode.

        :param classobj: class:`~androguard.core.bytecode.dvm.ClassDefItem`
        """

        self.orig_class = classobj
        self._methods = {}
        self._fields = {}

    @property
    def implements(self):
        """
        Get a list of interfaces which are implemented by this class

        :return: a list of Interface names
        """
        return self.orig_class.get_interfaces()

    @property
    def extends(self):
        """
        Return the parent class

        :return: a string of the parent class name
        """
        return self.orig_class.get_superclassname()

    @property
    def name(self):
        """
        Return the class name

        :return:
        """
        return self.orig_class.get_name()

    def get_vm_class(self):
        return self.orig_class


class Analysis:
    def __init__(self, vm=None):
        """
        Analysis Object

        The Analysis contains a lot of information about (multiple) DalvikVMFormat objects
        Features are for example XREFs between Classes, Methods, Fields and Strings.

        Multiple DalvikVMFormat Objects can be added using the function `add`

        :param vm: inital DalvikVMFormat object (default None)
        """

        # Contains DalvikVMFormat objects
        self.vms = []
        # A dict of {classname: ClassAnalysis}, populated on add(vm)
        self.classes = {}
        # A dict of {EncodedMethod: MethodAnalysis}, populated on add(vm)
        self.methods = {}

        if vm:
            self.add(vm)

    def add(self, vm):
        """
        Add a DalvikVMFormat to this Analysis

        :param vm: :class:`dvm.DalvikVMFormat` to add to this Analysis
        """
        self.vms.append(vm)
        for current_class in vm.get_classes():
            self.classes[current_class.get_name()] = ClassAnalysis(current_class)

        for method in vm.get_methods():
            self.methods[method] = MethodAnalysis(vm, method)

    def get_method(self, method):
        """
        Get the :class:`MethodAnalysis` object for a given :class:`EncodedMethod`.
        This Analysis object is used to enhance EncodedMethods.

        :param method: :class:`EncodedMethod` to search for
        :return: :class:`MethodAnalysis` object for the given method, or None if method was not found
        """
        if method in self.methods:
            return self.methods[method]
        else:
            return None
