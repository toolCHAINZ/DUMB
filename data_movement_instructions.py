from binaryninja import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType

from .dumb_instruction import FiveByteInstruction, RegReg


class MOV(RegReg):
    opcode = 0x0
    mnemonic = "mov"

    def get_instruction_low_level_il(self, data, addr, il):
        src = il.reg(4, self.args[1])
        op = il.set_reg(4, self.args[0], src)
        il.append(op)
        return self.length


class MOVI(FiveByteInstruction):
    opcode = 0x80
    mnemonic = "mov"

    def get_instruction_text(self, data, addr):
        tokens = []
        text = InstructionTextTokenType.TextToken
        integer = InstructionTextTokenType.IntegerToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        reg = InstructionTextTokenType.RegisterToken

        imm = self.get_imm(data)
        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(text, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(reg, self.get_reg2(data)))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(integer, hex(imm), value=imm))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        src = il.const(4, self.get_imm(data))
        op = il.set_reg(4, self.get_reg2(data), src)
        il.append(op)
        return self.length
