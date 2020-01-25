from binaryninja import Architecture, InstructionInfo, InstructionTextToken
from binaryninja.enums import BranchType, InstructionTextTokenType

from .dumb_instruction import FiveByteInstruction, OneByteInstruction


class JLT(FiveByteInstruction):
    opcode = 0x70
    mnemonic = "jlt"

    def get_instruction_text(self, data, addr):
        tokens = []
        text = InstructionTextTokenType.TextToken
        address = InstructionTextTokenType.PossibleAddressToken
        filler = InstructionTextTokenType.TextToken
        reg = InstructionTextTokenType.RegisterToken
        sep = InstructionTextTokenType.OperandSeparatorToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(text, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(reg, self.get_reg1(data)))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(InstructionTextToken(reg, self.get_reg2(data)))
        tokens.append(InstructionTextToken(sep, ','))
        tokens.append(
            InstructionTextToken(address, hex(self.get_imm(data)), value=self.get_imm(data)))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        if self.get_reg1(data) == self.get_reg2(data):
            # unconditional
            info = InstructionInfo()
            info.add_branch(BranchType.UnconditionalBranch, self.get_imm(data))
            info.length = self.length
            return info
        else:
            # conditional
            info = InstructionInfo()
            info.add_branch(BranchType.TrueBranch, self.get_imm(data))
            info.add_branch(BranchType.FalseBranch, addr + 5)
            info.length = self.length
            return info

    def get_instruction_low_level_il(self, data, addr, il):
        target = self.get_imm(data)
        target_label = il.get_label_for_address(Architecture['DUMB'], target)
        if target_label is None:
            il.add_label_for_address(Architecture['DUMB'], target)
            target_label = il.get_label_for_address(Architecture['DUMB'], target)

        if self.get_reg1(data) != self.get_reg2(data):
            fallthrough = addr + 5

            fallthrough_label = il.get_label_for_address(Architecture['DUMB'], fallthrough)
            if fallthrough_label is None:
                il.add_label_for_address(Architecture['DUMB'], fallthrough)
                fallthrough_label = il.get_label_for_address(Architecture['DUMB'], fallthrough)

            reg1 = il.reg(4, self.get_reg1(data))
            reg2 = il.reg(4, self.get_reg2(data))
            cmp = il.compare_unsigned_less_than(4, reg1, reg2)
            op = il.if_expr(cmp, target_label, fallthrough_label)
            il.append(op)
            return self.length
        else:
            op = il.goto(target_label)
            il.append(op)
            return self.length


class CALL(FiveByteInstruction):
    opcode = 0xa0
    mnemonic = "call"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.CallDestination, self.get_imm(data))
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.call(il.const(4, self.get_imm(data))))
        return self.length


class RET(OneByteInstruction):
    opcode = 0x90
    mnemonic = "ret"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.FunctionReturn)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.ret(il.pop(4)))
        return self.length
