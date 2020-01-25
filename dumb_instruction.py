from struct import unpack

from binaryninja import InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType

from .dumb_register import GPR


class DUMBInstruction:
    """
    Our base type for decoding instructions. Implements the decoding functions,
    and the necessary get_instruction_text, get_instruction_info, and
    get_instruction_low_level_il, which are all called from their respective
    functions in our architecture.
    """
    opcode: int = None
    mnemonic: str = ""
    justify: int = 10
    length: int = 0

    @classmethod
    def decode(cls, data, addr):
        """
        Our default decoder. Written so that THIS particular one will never return an object
        but classes with defined opcodes and mnemonics can inherit this and use it.
        """
        if len(data) < cls.length:
            return None
        if cls.opcode is None:
            return None
        if data[0] & 0xf0 != cls.opcode & 0xf0:
            return None
        return cls(data, addr)

    def __init__(self, data, addr):
        """
        We never actually use this one, so it is empty
        :param data:
        :param addr:
        """
        pass

    def get_reg1(self, data):
        """
        Given a string of data, decodes the first register encoded in the first byte
        :param data:
        :return:
        """
        reg_index = (data[0] & 0xc) >> 2
        return GPR[reg_index]

    def get_reg2(self, data):
        """
        Given a string of data, decodes the second register encoded in the first byte
        :param data:
        :return:
        """
        reg_index = (data[0] & 0x3)
        return GPR[reg_index]

    def get_instruction_info(self, data, addr):
        """
        Default get_instruction_info, which sets up the InstructionInfo object and does not
        add a branch.
        :param data:
        :param addr:
        :return:
        """
        info = InstructionInfo()
        info.length = self.length
        return info

    def get_instruction_text(self, data, addr):
        """
        Default (empty) tokenization
        :param data:
        :param addr:
        :return:
        """
        return ['', self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        """
        Default Low Level IL
        :param data:
        :param addr:
        :param il:
        :return:
        """
        return self.length


class OneByteInstruction(DUMBInstruction):
    """
    This class represents one-byte instructions. We define the tokenization for 1-byte instructions
    with no registers here.
    """
    length = 1

    def get_instruction_text(self, data, addr):
        """
        Tokenization for one-byte instructions with no registers
        :param data:
        :param addr:
        :return:
        """
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        return [tokens, self.length]


class FiveByteInstruction(DUMBInstruction):
    """
    This class represents the 5-byte instructions.
    """
    length = 5

    def get_imm(self, data):
        """
        We are adding get_imm to decode the 4-byte immediate from the 5-byte instruction. We are doing
        it here because only 5-byte instructions have this form, so we don't want this function
        available to 1-byte instructions
        :param data:
        :return:
        """
        num = unpack('I', data[1:5])
        return num[0]

    def __init__(self, data, addr):
        arg = self.get_imm(data)
        self.args = [hex(arg)]

    def get_instruction_text(self, data, addr):
        """
        Default tokenization of 5-byte instructions
        :param data:
        :param addr:
        :return:
        """
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        address = InstructionTextTokenType.PossibleAddressToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(address, self.args[0], value=self.get_imm(data)))
        return [tokens, self.length]


class RegReg(OneByteInstruction):
    """
    This class represents 1-byte instructions that use 2 registers. We parse out the arguments
    and define the tokenization here.
    """

    def __init__(self, data, addr):
        dest = self.get_reg1(data)
        src = self.get_reg2(data)
        self.args = [dest, src]

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, self.args[0]))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(register, self.args[1]))
        return [tokens, self.length]


class SingleReg(OneByteInstruction):
    """
    This class represents 1-byte instructions that use 1 register. We parse out the arguments
    and define the tokenization here.
    """

    def __init__(self, data, addr):
        reg = self.get_reg2(data)
        self.args = [reg]

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.InstructionToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, self.args[0]))
        return [tokens, self.length]
